//! A raw ETW session: `StartTrace`, `OpenTrace`, `ProcessTrace` and `ControlTrace` with the
//! `EVENT_RECORD` handed to the callback undecoded.
//!
//! `ferrisetw2` is used for manifest providers, where TDH decoding is worth having. The classic
//! kernel process events are read here instead, because the crate sizes their WBEM SID field as
//! a bare SID and ignores the `TOKEN_USER` header the kernel writes in front of it, so every
//! field after the SID (image name, command line) comes out misaligned. The MOF layout of those
//! events is stable and short, see [`super::classic_process`]. The packet session will use this
//! too: one `TdhGetProperty` round-trip per frame is not something to pay at line rate.

use super::CaptureError;
use crate::model::{filetime_to_timestamp, Timestamp};
use std::ffi::c_void;
use std::mem::{offset_of, size_of};
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};
use windows::core::{GUID, PCWSTR, PWSTR};
use windows::Win32::Foundation::{ERROR_ALREADY_EXISTS, ERROR_CANCELLED, ERROR_SUCCESS, WIN32_ERROR};
use windows::Win32::System::Diagnostics::Etw::{
    CloseTrace, ControlTraceW, EnableTraceEx2, OpenTraceW, ProcessTrace, StartTraceW,
    CONTROLTRACE_HANDLE, EVENT_CONTROL_CODE_ENABLE_PROVIDER, EVENT_HEADER_FLAG_32_BIT_HEADER,
    EVENT_RECORD, EVENT_TRACE_CONTROL_QUERY,
    EVENT_TRACE_CONTROL_STOP, EVENT_TRACE_FLAG, EVENT_TRACE_LOGFILEW, EVENT_TRACE_PROPERTIES,
    EVENT_TRACE_REAL_TIME_MODE, EVENT_TRACE_SYSTEM_LOGGER_MODE, PROCESSTRACE_HANDLE,
    PROCESS_TRACE_MODE_EVENT_RECORD, PROCESS_TRACE_MODE_REAL_TIME, WNODE_FLAG_TRACED_GUID,
};

/// One event as ETW delivered it. `user` is the payload after the header; its layout is the
/// provider's business.
pub struct RawRecord<'a> {
    pub provider: GUID,
    pub id: u16,
    pub version: u8,
    pub opcode: u8,
    pub keyword: u64,
    /// PID from the event header. For kernel process events this is the *creating* thread's
    /// process, not the new process.
    pub header_pid: u32,
    pub header_tid: u32,
    pub timestamp: Timestamp,
    /// 4 or 8, from the header flags. Governs pointer-sized fields in classic payloads.
    pub pointer_size: usize,
    pub user: &'a [u8],
}

pub type RawCallback = Box<dyn Fn(&RawRecord<'_>) + Send + Sync + 'static>;

/// A manifest provider to enable on the session, by GUID string.
pub struct ProviderSpec {
    pub guid: &'static str,
    pub level: u8,
    pub match_any: u64,
    pub match_all: u64,
}

/// Session parameters. Sizes in KB, as ETW counts them.
pub struct RawSessionConfig {
    pub name: String,
    /// `EVENT_TRACE_SYSTEM_LOGGER_MODE`: the session may enable classic kernel flags.
    pub system_logger: bool,
    /// Classic kernel flags (`EVENT_TRACE_FLAG_*`). Only honoured with `system_logger`.
    pub enable_flags: u32,
    pub buffer_kb: u32,
    pub min_buffers: u32,
    pub max_buffers: u32,
    pub flush_secs: u32,
    /// Manifest providers enabled right after the session starts.
    pub providers: Vec<ProviderSpec>,
}

/// `EVENT_TRACE_PROPERTIES` with the session name inline, as `StartTrace` expects.
#[repr(C)]
struct PropsBuf {
    props: EVENT_TRACE_PROPERTIES,
    name: [u16; 256],
}

impl PropsBuf {
    fn new(name: &[u16]) -> Box<Self> {
        // Safety: both members are plain data for which all-zero is a valid value.
        let mut b: Box<Self> = Box::new(unsafe { std::mem::zeroed() });
        b.props.Wnode.BufferSize = size_of::<Self>() as u32;
        b.props.Wnode.Flags = WNODE_FLAG_TRACED_GUID;
        b.props.LoggerNameOffset = offset_of!(Self, name) as u32;
        let n = name.len().min(255);
        b.name[..n].copy_from_slice(&name[..n]);
        b
    }
}

struct Ctx {
    callback: RawCallback,
    handled: AtomicU64,
    callback_panics: AtomicU64,
}

pub struct RawSession {
    name: Vec<u16>,
    control: CONTROLTRACE_HANDLE,
    trace: PROCESSTRACE_HANDLE,
    props: Box<PropsBuf>,
    ctx: Arc<Ctx>,
    /// Second strong reference, handed to ETW as the logfile context and released after the
    /// consumer thread has returned.
    ctx_raw: *const Ctx,
    thread: Option<JoinHandle<()>>,
    lost_cache: Mutex<(Instant, u64)>,
    stopped: bool,
}

// The raw pointer is an `Arc` we own; nothing here is thread-affine.
unsafe impl Send for RawSession {}
unsafe impl Sync for RawSession {}

fn win32(what: &str, code: WIN32_ERROR) -> CaptureError {
    CaptureError::win32(what, windows::core::Error::from(code))
}

fn wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0)).collect()
}

/// Stop a session by name. `Ok(true)` when one was running.
pub fn stop_by_name(name: &str) -> Result<bool, CaptureError> {
    let name_w = wide(name);
    let mut props = PropsBuf::new(&name_w);
    // Safety: `props` is a properly sized, owned buffer; the name is NUL terminated.
    let status = unsafe {
        ControlTraceW(
            CONTROLTRACE_HANDLE::default(),
            PCWSTR(name_w.as_ptr()),
            &mut props.props,
            EVENT_TRACE_CONTROL_STOP,
        )
    };
    match status {
        ERROR_SUCCESS => Ok(true),
        // ERROR_WMI_INSTANCE_NOT_FOUND: nothing to stop.
        WIN32_ERROR(4201) => Ok(false),
        other => Err(win32(&format!("stopping session {name}"), other)),
    }
}

impl RawSession {
    /// Start the session and a consumer thread. Needs an elevated token.
    pub fn start(cfg: RawSessionConfig, callback: RawCallback) -> Result<Self, CaptureError> {
        let name_w = wide(&cfg.name);
        let mut props = PropsBuf::new(&name_w);
        props.props.Wnode.ClientContext = 1; // QPC; ProcessTrace converts to FILETIME for us.
        props.props.Wnode.Guid = GUID::new().unwrap_or_default();
        props.props.BufferSize = cfg.buffer_kb;
        props.props.MinimumBuffers = cfg.min_buffers;
        props.props.MaximumBuffers = cfg.max_buffers;
        props.props.FlushTimer = cfg.flush_secs.max(1);
        props.props.LogFileMode = EVENT_TRACE_REAL_TIME_MODE
            | if cfg.system_logger {
                EVENT_TRACE_SYSTEM_LOGGER_MODE
            } else {
                0
            };
        props.props.EnableFlags = EVENT_TRACE_FLAG(cfg.enable_flags);

        let mut control = CONTROLTRACE_HANDLE::default();
        let mut attempt = 0;
        loop {
            // Safety: the buffer is owned and sized; StartTrace writes the name and handle back.
            let status = unsafe {
                StartTraceW(&mut control, PCWSTR(name_w.as_ptr()), &mut props.props)
            };
            match status {
                ERROR_SUCCESS => break,
                ERROR_ALREADY_EXISTS if attempt == 0 => {
                    attempt += 1;
                    stop_by_name(&cfg.name)?;
                }
                other => return Err(win32(&format!("starting session {}", cfg.name), other)),
            }
        }

        for p in &cfg.providers {
            let Ok(guid) = GUID::try_from(p.guid) else {
                let _ = stop_by_name(&cfg.name);
                return Err(CaptureError::Other(format!("bad provider GUID {}", p.guid)));
            };
            // Safety: the control handle is live; the GUID is only read during the call.
            let status = unsafe {
                EnableTraceEx2(
                    control,
                    &guid,
                    EVENT_CONTROL_CODE_ENABLE_PROVIDER.0,
                    p.level,
                    p.match_any,
                    p.match_all,
                    0,
                    None,
                )
            };
            if status != ERROR_SUCCESS {
                let _ = stop_by_name(&cfg.name);
                return Err(win32(
                    &format!("enabling provider {} on session {}", p.guid, cfg.name),
                    status,
                ));
            }
        }

        let ctx = Arc::new(Ctx {
            callback,
            handled: AtomicU64::new(0),
            callback_panics: AtomicU64::new(0),
        });
        let ctx_raw = Arc::into_raw(ctx.clone());

        let mut logger_name = name_w.clone();
        let mut logfile = EVENT_TRACE_LOGFILEW {
            LoggerName: PWSTR(logger_name.as_mut_ptr()),
            Context: ctx_raw as *mut c_void,
            ..Default::default()
        };
        logfile.Anonymous1.ProcessTraceMode =
            PROCESS_TRACE_MODE_REAL_TIME | PROCESS_TRACE_MODE_EVENT_RECORD;
        logfile.Anonymous2.EventRecordCallback = Some(record_thunk);
        // Safety: `logfile` is fully initialised; OpenTrace copies what it needs out of it.
        let trace = unsafe { OpenTraceW(&mut logfile) };
        if trace.Value == u64::MAX {
            let err = windows::core::Error::from_thread();
            let mut s = Self {
                name: name_w,
                control,
                trace: PROCESSTRACE_HANDLE::default(),
                props,
                ctx,
                ctx_raw,
                thread: None,
                lost_cache: Mutex::new((Instant::now(), 0)),
                stopped: false,
            };
            s.stop_session();
            s.stopped = true;
            // Safety: matching the `into_raw` above; no thunk can run, the trace never opened.
            unsafe { drop(Arc::from_raw(ctx_raw)) };
            return Err(CaptureError::win32(
                &format!("opening session {} for reading", cfg.name),
                err,
            ));
        }

        let thread_name = format!("etw-{}", cfg.name);
        let handle = trace;
        let thread = std::thread::Builder::new()
            .name(thread_name.clone())
            .spawn(move || {
                // Safety: the handle came from OpenTrace and stays open until CloseTrace, which
                // is only called from `stop` after this thread is asked to finish.
                let status = unsafe { ProcessTrace(&[handle], None, None) };
                if status != ERROR_SUCCESS && status != ERROR_CANCELLED {
                    log::warn!("{thread_name}: ProcessTrace returned {}", status.0);
                }
            })
            .map_err(|e| CaptureError::Other(format!("spawning consumer thread: {e}")))?;

        Ok(Self {
            name: name_w,
            control,
            trace,
            props,
            ctx,
            ctx_raw,
            thread: Some(thread),
            lost_cache: Mutex::new((Instant::now() - Duration::from_secs(5), 0)),
            stopped: false,
        })
    }

    /// Events delivered to the callback.
    pub fn events_handled(&self) -> u64 {
        self.ctx.handled.load(Ordering::Relaxed)
    }

    pub fn callback_panics(&self) -> u64 {
        self.ctx.callback_panics.load(Ordering::Relaxed)
    }

    /// Events ETW dropped before we read them (session buffers full). Queried from the session at
    /// most once a second; callers may poll freely.
    pub fn events_lost(&self) -> u64 {
        let mut cache = match self.lost_cache.lock() {
            Ok(c) => c,
            Err(p) => p.into_inner(),
        };
        if cache.0.elapsed() < Duration::from_secs(1) {
            return cache.1;
        }
        let mut q = PropsBuf::new(&self.name);
        // Safety: query only writes statistics into our buffer.
        let status = unsafe {
            ControlTraceW(
                self.control,
                PCWSTR::null(),
                &mut q.props,
                EVENT_TRACE_CONTROL_QUERY,
            )
        };
        if status == ERROR_SUCCESS {
            cache.1 = q.props.EventsLost as u64 + q.props.RealTimeBuffersLost as u64;
        }
        cache.0 = Instant::now();
        cache.1
    }

    fn stop_session(&mut self) {
        // Safety: the control handle is ours; STOP writes final statistics into `props`.
        let status = unsafe {
            ControlTraceW(
                self.control,
                PCWSTR::null(),
                &mut self.props.props,
                EVENT_TRACE_CONTROL_STOP,
            )
        };
        if status != ERROR_SUCCESS {
            log::warn!("stopping ETW session: error {}", status.0);
        }
    }

    /// Close the consumer, stop the session, join the thread.
    pub fn stop(mut self) {
        self.stop_inner();
    }

    fn stop_inner(&mut self) {
        if self.stopped {
            return;
        }
        self.stopped = true;
        if self.trace.Value != 0 {
            // Safety: the handle is open; CloseTrace makes ProcessTrace return.
            let status = unsafe { CloseTrace(self.trace) };
            // ERROR_CTX_CLOSE_PENDING (7007) is the documented "will close when ProcessTrace
            // returns" answer.
            if status != ERROR_SUCCESS && status.0 != 7007 {
                log::warn!("CloseTrace: error {}", status.0);
            }
        }
        self.stop_session();
        if let Some(t) = self.thread.take() {
            let _ = t.join();
        }
        // Safety: the consumer thread has returned, so no thunk will dereference the context.
        unsafe { drop(Arc::from_raw(self.ctx_raw)) };
    }
}

impl Drop for RawSession {
    fn drop(&mut self) {
        self.stop_inner();
    }
}

unsafe extern "system" fn record_thunk(rec: *mut EVENT_RECORD) {
    if rec.is_null() {
        return;
    }
    // Safety: ETW hands us a valid record for the duration of the call; UserContext is the
    // `Ctx` pointer we registered and it outlives the consumer thread.
    let r = unsafe { &*rec };
    if r.UserContext.is_null() {
        return;
    }
    let ctx = unsafe { &*(r.UserContext as *const Ctx) };
    let user: &[u8] = if r.UserData.is_null() || r.UserDataLength == 0 {
        &[]
    } else {
        unsafe { std::slice::from_raw_parts(r.UserData as *const u8, r.UserDataLength as usize) }
    };
    let h = &r.EventHeader;
    let d = &h.EventDescriptor;
    let record = RawRecord {
        provider: h.ProviderId,
        id: d.Id,
        version: d.Version,
        opcode: d.Opcode,
        keyword: d.Keyword,
        header_pid: h.ProcessId,
        header_tid: h.ThreadId,
        timestamp: filetime_to_timestamp(h.TimeStamp as u64),
        pointer_size: if u32::from(h.Flags) & EVENT_HEADER_FLAG_32_BIT_HEADER != 0 {
            4
        } else {
            8
        },
        user,
    };
    ctx.handled.fetch_add(1, Ordering::Relaxed);
    // A panic must never unwind into ETW. With panic=abort this is moot; in debug builds it
    // keeps one bad event from taking the session down.
    if catch_unwind(AssertUnwindSafe(|| (ctx.callback)(&record))).is_err()
        && ctx.callback_panics.fetch_add(1, Ordering::Relaxed) == 0
    {
        log::error!("ETW callback panicked; further panics are counted silently");
    }
}
