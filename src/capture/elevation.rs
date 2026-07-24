//! Elevation check and relaunch. Kernel ETW providers need an elevated token.

use super::winutil::current_process_elevated;

pub fn is_elevated() -> bool {
    current_process_elevated()
}

/// Plain-words explanation shown in the UI when not elevated.
pub const WHY_ADMIN: &str = "BeaconTap reads process and network events from the Windows kernel \
through ETW. Windows only hands those out to administrators. The process list works without \
it; capturing does not.";

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
