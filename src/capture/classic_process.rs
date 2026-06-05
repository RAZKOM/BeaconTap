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

