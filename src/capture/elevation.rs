//! Elevation check and relaunch. Kernel ETW providers need an elevated token.

use super::winutil::{current_process_elevated, to_wide};
use super::CaptureError;
use windows::core::PCWSTR;
use windows::Win32::UI::Shell::ShellExecuteW;
use windows::Win32::UI::WindowsAndMessaging::SW_SHOWNORMAL;

pub fn is_elevated() -> bool {
    current_process_elevated()
}

/// Plain-words explanation shown in the UI when not elevated.
pub const WHY_ADMIN: &str = "BeaconTap reads process and network events from the Windows kernel \
through ETW. Windows only hands those out to administrators. The process list works without \
it; capturing does not.";

/// Start a new elevated copy of this exe with `args`, through the UAC prompt. On success the
/// caller should exit; on failure (including the user declining) the error says why.
pub fn relaunch_elevated(args: &[String]) -> Result<(), CaptureError> {
    let exe = std::env::current_exe()
        .map_err(|e| CaptureError::Other(format!("cannot find own exe path: {e}")))?;
    let exe_w = to_wide(&exe.to_string_lossy());
    let params = args
        .iter()
        .map(|a| quote_arg(a))
        .collect::<Vec<_>>()
        .join(" ");
    let params_w = to_wide(&params);
    let verb = to_wide("runas");
    // Safety: all strings are NUL terminated and outlive the call.
    let h = unsafe {
        ShellExecuteW(
            None,
            PCWSTR(verb.as_ptr()),
            PCWSTR(exe_w.as_ptr()),
            PCWSTR(params_w.as_ptr()),
            None,
            SW_SHOWNORMAL,
        )
    };
    let code = h.0 as isize;
    if code > 32 {
        Ok(())
    } else if code == 5 || code == 31 {
        // SE_ERR_ACCESSDENIED, or the UAC prompt was dismissed.
        Err(CaptureError::Other(
            "the elevation prompt was declined, so BeaconTap is still running without admin \
             rights"
                .into(),
        ))
    } else {
        Err(CaptureError::Other(format!(
            "ShellExecute runas failed with code {code}"
        )))
    }
}

/// Quote one argument the way CommandLineToArgvW expects.
pub fn quote_arg(a: &str) -> String {
    if !a.is_empty() && !a.chars().any(|c| c == ' ' || c == '\t' || c == '"') {
        return a.to_string();
    }
    let mut out = String::from("\"");
    let mut backslashes = 0;
    for c in a.chars() {
        match c {
            '\\' => backslashes += 1,
            '"' => {
                out.push_str(&"\\".repeat(backslashes * 2 + 1));
                out.push('"');
                backslashes = 0;
            }
            _ => {
                out.push_str(&"\\".repeat(backslashes));
                out.push(c);
                backslashes = 0;
            }
        }
    }
    out.push_str(&"\\".repeat(backslashes * 2));
    out.push('"');
    out
}

#[cfg(test)]
mod tests {
    use super::quote_arg;

    #[test]
    fn quoting() {
        assert_eq!(quote_arg("plain"), "plain");
        assert_eq!(quote_arg("has space"), "\"has space\"");
        assert_eq!(quote_arg("say \"hi\""), "\"say \\\"hi\\\"\"");
        assert_eq!(
            quote_arg("C:\\dir\\"),
            "C:\\dir\\",
            "no quoting needed without spaces"
        );
        assert_eq!(quote_arg("C:\\my dir\\"), "\"C:\\my dir\\\\\"");
        assert_eq!(quote_arg(""), "\"\"");
    }
}
