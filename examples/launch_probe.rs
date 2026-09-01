//! Diagnostic: launch a program through BeaconTap's launcher, exactly as the app does, and
//! report the child's token, its process tree and its sockets after a while. No ETW involved,
//! so it separates "the launcher breaks the target" from "the capture breaks the target".
//!
//!   launch_probe <exe> <args> <url> [seconds] [mode]
//!
//! mode: parent (default), env, token, elevated. See `Deelevation` in capture/launch.rs.
use beacontap::capture::launch::{launch, Deelevation, LaunchOptions};
use std::process::Command;

fn main() {
    let a: Vec<String> = std::env::args().skip(1).collect();
    let exe = a
        .first()
        .cloned()
        .expect("usage: launch_probe <exe> <args> <url> [seconds] [parent|env|token|elevated]");
    let args = a.get(1).cloned().unwrap_or_default();
    let url = a.get(2).cloned().unwrap_or_default();
    let secs: u64 = a.get(3).and_then(|s| s.parse().ok()).unwrap_or(20);
    let deelevate = match a.get(4).map(String::as_str) {
        None | Some("parent") => Deelevation::ShellParent,
        Some("env") => Deelevation::ShellParentCleanEnv,
        Some("token") => Deelevation::ShellToken,
        Some("elevated") => Deelevation::None,
        Some(other) => panic!("unknown mode {other}"),
    };
    let opts = LaunchOptions {
        exe: exe.clone().into(),
        args: if url.is_empty() { args } else { format!("{args} {url}") }
            .trim()
            .to_string(),
        cwd: std::path::Path::new(&exe).parent().map(|p| p.to_path_buf()),
        hold: false,
        deelevate,
    };
    println!(
        "mode {}  caller elevated {}",
        deelevate.label(),
        beacontap::capture::elevation::is_elevated()
    );
    let mut l = match launch(&opts) {
        Ok(l) => l,
        Err(e) => {
            println!("launch failed: {e}");
            std::process::exit(1);
        }
    };
    println!(
        "child pid {}  token elevated {:?}  deelevated {}  note {:?}\ncmdline {}",
        l.pid, l.elevated, l.deelevated, l.note, l.cmdline
    );
    l.resume().expect("resume");
    println!("waiting {secs} s ...");
    std::thread::sleep(std::time::Duration::from_secs(secs));
    let script = format!(
        "$root={pid}; $pids=@($root); $all=Get-CimInstance Win32_Process; $q=@($root); \
         while($q){{ $p=$q[0]; $q=@($q | Select-Object -Skip 1); \
         foreach($c in $all | Where-Object {{$_.ParentProcessId -eq $p}}){{ $pids+=$c.ProcessId; $q+=$c.ProcessId }} }}; \
         $names=@(); foreach($x in $pids){{ $w=$all | Where-Object ProcessId -eq $x; if($w){{ $names+=$w.Name }} }}; \
         'tree: '+$pids.Count+' processes: '+(($names | Group-Object | ForEach-Object {{ $_.Name+' x'+$_.Count }}) -join ', '); \
         foreach($x in $pids){{ try {{ $pr=Get-Process -Id $x -ErrorAction Stop; \
         if($pr.MainWindowTitle){{ 'window: '+$pr.MainWindowTitle }} }} catch {{}} }}; \
         $t=@(Get-NetTCPConnection | Where-Object {{ $pids -contains $_.OwningProcess }}); \
         'tcp sockets: '+$t.Count+'  established: '+@($t | Where-Object State -eq 'Established').Count+\
         '  syn-sent: '+@($t | Where-Object State -eq 'SynSent').Count; \
         $u=@(Get-NetUDPEndpoint | Where-Object {{ $pids -contains $_.OwningProcess }}); 'udp sockets: '+$u.Count",
        pid = l.pid
    );
    let out = Command::new("powershell")
        .args(["-NoProfile", "-Command", &script])
        .output()
        .expect("powershell");
    println!("{}", String::from_utf8_lossy(&out.stdout).trim());
    let err = String::from_utf8_lossy(&out.stderr);
    if !err.trim().is_empty() {
        println!("{}", err.trim());
    }
    println!("done; the target is left running.");
}
