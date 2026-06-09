//! Decoder for the classic (MOF) kernel process event, `Process_TypeGroup1`, as emitted by a
//! system-logger session with `EVENT_TRACE_FLAG_PROCESS`. Opcodes: 1 Start, 2 End, 3 DCStart
//! (rundown of live processes), 4 DCEnd.
//!
//! Layout, pointer-sized fields follow the event header's 32/64-bit flag:
//!
//! | field              | type                      | since |
//! |--------------------|---------------------------|-------|
//! | UniqueProcessKey   | pointer                   | v1    |
//! | ProcessId          | u32                       | v1    |
//! | ParentId           | u32                       | v1    |
//! | SessionId          | u32                       | v2    |
//! | ExitStatus         | i32                       | v2    |
//! | DirectoryTableBase | pointer                   | v3    |
//! | Flags              | u32                       | v4    |
//! | UserSID            | WBEM SID, see below       | v1    |
//! | ImageFileName      | ANSI, NUL terminated      | v1    |
//! | CommandLine        | UTF-16, NUL terminated    | v2    |
//! | PackageFullName    | UTF-16, NUL terminated    | v4    |
//! | ApplicationId      | UTF-16, NUL terminated    | v4    |
//!
//! A WBEM SID starts with one pointer-sized value. If it is zero, that is the whole field.
//! Otherwise the field is a `TOKEN_USER` (two pointers: `Sid` and `Attributes` padded) followed
//! by the SID itself: revision, sub-authority count, 6-byte authority, 4 bytes per sub-authority.
//! Fields after `CommandLine` are ignored, so newer versions decode as long as nothing is
//! inserted before it.
//!
//! Pure function, no Windows calls: the unit tests feed it hand-built payloads.

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClassicProcess {
    pub pid: u32,
    pub parent_pid: u32,
    pub session_id: Option<u32>,
    pub exit_status: Option<i32>,
    /// Base name as the kernel reports it, e.g. `cmd.exe`. Not a path.
    pub image: String,
    /// `None` when the event has no command line or it is empty.
    pub cmdline: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DecodeError {
    Truncated(&'static str),
    BadPointerSize,
}

impl std::fmt::Display for DecodeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            DecodeError::Truncated(what) => write!(f, "payload truncated at {what}"),
            DecodeError::BadPointerSize => write!(f, "pointer size is neither 4 nor 8"),
        }
    }
}

struct Cursor<'a> {
    data: &'a [u8],
    pos: usize,
}

impl<'a> Cursor<'a> {
    fn take(&mut self, n: usize, what: &'static str) -> Result<&'a [u8], DecodeError> {
        let end = self.pos.checked_add(n).ok_or(DecodeError::Truncated(what))?;
        let s = self
            .data
            .get(self.pos..end)
            .ok_or(DecodeError::Truncated(what))?;
        self.pos = end;
        Ok(s)
    }
    fn u32(&mut self, what: &'static str) -> Result<u32, DecodeError> {
        let b = self.take(4, what)?;
        Ok(u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
    }
    fn ptr(&mut self, size: usize, what: &'static str) -> Result<u64, DecodeError> {
        let b = self.take(size, what)?;
        let mut v = [0u8; 8];
        v[..size].copy_from_slice(b);
        Ok(u64::from_le_bytes(v))
    }
    fn ansi(&mut self, what: &'static str) -> Result<String, DecodeError> {
        let rest = &self.data[self.pos..];
        let nul = rest
            .iter()
            .position(|&b| b == 0)
            .ok_or(DecodeError::Truncated(what))?;
        let s = rest[..nul].iter().map(|&b| b as char).collect();
        self.pos += nul + 1;
        Ok(s)
    }
    /// `Ok(None)` when the payload ends before the string starts: older versions simply stop.
    fn utf16(&mut self, what: &'static str) -> Result<Option<String>, DecodeError> {
        let rest = &self.data[self.pos..];
        if rest.is_empty() {
            return Ok(None);
        }
        let units: Vec<u16> = rest
            .as_chunks::<2>()
            .0
            .iter()
            .map(|c| u16::from_le_bytes(*c))
            .collect();
        let nul = units
            .iter()
            .position(|&u| u == 0)
            .ok_or(DecodeError::Truncated(what))?;
        self.pos += (nul + 1) * 2;
        Ok(Some(String::from_utf16_lossy(&units[..nul])))
    }
}

/// Decode a `Process_TypeGroup1` payload. `version` is the event descriptor's version,
/// `pointer_size` 4 or 8 from the header flags.
pub fn decode(
    version: u8,
    pointer_size: usize,
    data: &[u8],
) -> Result<ClassicProcess, DecodeError> {
    if pointer_size != 4 && pointer_size != 8 {
        return Err(DecodeError::BadPointerSize);
    }
    let mut c = Cursor { data, pos: 0 };
    c.ptr(pointer_size, "UniqueProcessKey")?;
    let pid = c.u32("ProcessId")?;
    let parent_pid = c.u32("ParentId")?;
    let (session_id, exit_status) = if version >= 2 {
        (
            Some(c.u32("SessionId")?),
            Some(c.u32("ExitStatus")? as i32),
        )
    } else {
        (None, None)
    };
    if version >= 3 {
        c.ptr(pointer_size, "DirectoryTableBase")?;
    }
    if version >= 4 {
        c.u32("Flags")?;
    }
    // WBEM SID.
    let first = c.ptr(pointer_size, "UserSID")?;
    if first != 0 {
        // TOKEN_USER: Sid pointer (already consumed) and Attributes padded to pointer size.
        c.ptr(pointer_size, "UserSID.Attributes")?;
        let head = c.take(2, "UserSID.header")?;
        let sub_count = head[1] as usize;
        c.take(6 + 4 * sub_count, "UserSID.body")?;
    }
    let image = c.ansi("ImageFileName")?;
    let cmdline = if version >= 2 {
        c.utf16("CommandLine")?.filter(|s| !s.trim().is_empty())
    } else {
        None
    };
    Ok(ClassicProcess {
        pid,
        parent_pid,
        session_id,
        exit_status,
        image,
        cmdline,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    struct Builder {
        ptr: usize,
        buf: Vec<u8>,
    }

    impl Builder {
        fn new(ptr: usize) -> Self {
            Builder {
                ptr,
                buf: Vec::new(),
            }
        }
        fn p(mut self, v: u64) -> Self {
            self.buf.extend_from_slice(&v.to_le_bytes()[..self.ptr]);
            self
        }
        fn u(mut self, v: u32) -> Self {
            self.buf.extend_from_slice(&v.to_le_bytes());
            self
        }
        fn sid_none(self) -> Self {
            self.p(0)
        }
        /// TOKEN_USER + S-1-5-21-a-b-c-1001 (5 sub-authorities).
        fn sid_user(mut self) -> Self {
            self = self.p(0x0000_7fff_dead_beef).p(0); // Sid pointer, Attributes
            self.buf.extend_from_slice(&[1, 5, 0, 0, 0, 0, 0, 5]);
            for sub in [21u32, 11, 22, 33, 1001] {
                self.buf.extend_from_slice(&sub.to_le_bytes());
            }
            self
        }
        fn ansi(mut self, s: &str) -> Self {
            self.buf.extend_from_slice(s.as_bytes());
            self.buf.push(0);
            self
        }
        fn w(mut self, s: &str) -> Self {
            for u in s.encode_utf16() {
                self.buf.extend_from_slice(&u.to_le_bytes());
            }
            self.buf.extend_from_slice(&[0, 0]);
            self
        }
    }

    fn v4_x64(sid_user: bool, cmd: &str) -> Vec<u8> {
        let b = Builder::new(8)
            .p(0xffff_8000_1234_5678) // UniqueProcessKey
            .u(4242) // ProcessId
            .u(1000) // ParentId
            .u(1) // SessionId
            .u(0x103) // ExitStatus STATUS_PENDING
            .p(0x1a_b000) // DirectoryTableBase
            .u(0); // Flags
        let b = if sid_user { b.sid_user() } else { b.sid_none() };
        b.ansi("cmd.exe")
            .w(cmd)
            .w("") // PackageFullName
            .w("") // ApplicationId
            .buf
    }

    #[test]
    fn v4_x64_with_token_user_sid() {
        let data = v4_x64(true, "C:\\Windows\\System32\\cmd.exe /c echo hi");
        let p = decode(4, 8, &data).unwrap();
        assert_eq!(p.pid, 4242);
        assert_eq!(p.parent_pid, 1000);
        assert_eq!(p.session_id, Some(1));
        assert_eq!(p.exit_status, Some(0x103));
        assert_eq!(p.image, "cmd.exe");
        assert_eq!(
            p.cmdline.as_deref(),
            Some("C:\\Windows\\System32\\cmd.exe /c echo hi")
        );
    }

    #[test]
    fn v4_x64_with_null_sid_and_empty_cmdline() {
        let data = v4_x64(false, "");
        let p = decode(4, 8, &data).unwrap();
        assert_eq!(p.pid, 4242);
        assert_eq!(p.image, "cmd.exe");
        assert_eq!(p.cmdline, None);
    }

    #[test]
    fn v3_has_no_flags_field() {
        let data = Builder::new(8)
            .p(1)
            .u(7)
            .u(3)
            .u(0)
            .u(0)
            .p(0)
            .sid_user()
            .ansi("svchost.exe")
            .w("svchost.exe -k netsvcs")
            .buf;
        let p = decode(3, 8, &data).unwrap();
        assert_eq!(p.pid, 7);
        assert_eq!(p.parent_pid, 3);
        assert_eq!(p.image, "svchost.exe");
        assert_eq!(p.cmdline.as_deref(), Some("svchost.exe -k netsvcs"));
    }

    #[test]
    fn v4_x86_pointers_are_four_bytes() {
        let data = Builder::new(4)
            .p(1)
            .u(9)
            .u(8)
            .u(2)
            .u(0)
            .p(0)
            .u(0)
            .sid_user()
            .ansi("a.exe")
            .w("a.exe --x")
            .w("")
            .w("")
            .buf;
        let p = decode(4, 4, &data).unwrap();
        assert_eq!((p.pid, p.parent_pid, p.session_id), (9, 8, Some(2)));
        assert_eq!(p.cmdline.as_deref(), Some("a.exe --x"));
    }

    #[test]
    fn truncated_payload_is_an_error_not_a_panic() {
        let data = v4_x64(true, "x");
        // The last 8 bytes are the command line "x" (4) and two empty trailing strings (2 + 2).
        // Cutting the trailing strings is fine, cutting into the command line is not.
        for cut in [0, 10, 30, 60, data.len() - 7, data.len() - 6] {
            assert!(decode(4, 8, &data[..cut]).is_err(), "cut at {cut}");
        }
        assert!(decode(4, 8, &data[..data.len() - 4]).is_ok());
        assert_eq!(decode(4, 3, &data), Err(DecodeError::BadPointerSize));
    }

    #[test]
    fn end_event_carries_exit_status() {
        let data = Builder::new(8)
            .p(1)
            .u(5)
            .u(4)
            .u(1)
            .u(0xC000_013A) // STATUS_CONTROL_C_EXIT
            .p(0)
            .u(0)
            .sid_none()
            .ansi("ping.exe")
            .w("ping -n 2 127.0.0.1")
            .buf;
        let p = decode(4, 8, &data).unwrap();
        assert_eq!(p.exit_status, Some(0xC000_013Au32 as i32));
    }
}
