//! Launch & watch. Creates the target suspended so it can be registered before its first
//! instruction runs, and by default without BeaconTap's elevation: a process started from an
//! elevated BeaconTap should behave exactly as if the user had double-clicked it.

/// How a target launched from an elevated BeaconTap is kept out of that elevation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Deelevation {
    /// Keep BeaconTap's own token. The target runs elevated when BeaconTap does.
    None,
    /// `PROC_THREAD_ATTRIBUTE_PARENT_PROCESS` with the desktop shell: the child inherits the
    /// shell's token, but keeps BeaconTap's environment block.
    ShellParent,
    /// [`Deelevation::ShellParent`] plus an environment block built from the shell's token.
    ShellParentCleanEnv,
    /// `CreateProcessWithTokenW` with a duplicate of the shell's primary token and an
    /// environment block built from it. The child's parent is BeaconTap.
    ShellToken,
}

impl Deelevation {
    pub fn label(self) -> &'static str {
        match self {
            Deelevation::None => "none",
            Deelevation::ShellParent => "shell parent",
            Deelevation::ShellParentCleanEnv => "shell parent, clean environment",
            Deelevation::ShellToken => "shell token",
        }
    }
}

