//! Names of the network interfaces, by the index the packet layer reports, so a pcapng can
//! say "Wi-Fi" instead of "if12". The NDIS capture provider's `MiniportIfIndex` is the same
//! index IP Helper calls `InterfaceIndex` (what `Get-NetAdapter` shows as ifIndex).

use std::collections::HashMap;
use windows::Win32::NetworkManagement::IpHelper::{FreeMibTable, GetIfTable2, MIB_IF_TABLE2};

fn wide(s: &[u16]) -> String {
    let end = s.iter().position(|&c| c == 0).unwrap_or(s.len());
    String::from_utf16_lossy(&s[..end])
}

/// `index -> "Alias (Description)"` for every interface Windows knows. Empty on failure;
/// the pcapng then falls back to `if<index>`.
pub fn interface_names() -> HashMap<u32, String> {
    let mut out = HashMap::new();
    let mut table: *mut MIB_IF_TABLE2 = std::ptr::null_mut();
    // SAFETY: GetIfTable2 allocates the table and hands ownership back; FreeMibTable releases
    // it. The rows are read only while the table is alive.
    unsafe {
        if GetIfTable2(&mut table).is_err() || table.is_null() {
            return out;
        }
        let n = (*table).NumEntries as usize;
        let rows = std::slice::from_raw_parts((*table).Table.as_ptr(), n);
        for r in rows {
            let alias = wide(&r.Alias);
            let desc = wide(&r.Description);
            let name = if alias.is_empty() {
                desc
            } else if desc.is_empty() || desc == alias {
                alias
            } else {
                format!("{alias} ({desc})")
            };
            if !name.is_empty() {
                out.insert(r.InterfaceIndex, name);
            }
        }
        FreeMibTable(table as *const _);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lists_this_machines_interfaces() {
        let names = interface_names();
        // Every Windows machine has at least the loopback pseudo-interface.
        assert!(!names.is_empty());
        assert!(names.values().all(|n| !n.is_empty() && !n.contains('\0')));
    }
}
