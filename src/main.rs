fn usage() -> ! {
    eprintln!(
        "{} {}\n\n\
         usage: beacontap [--attach <pid>] [--launch <exe> [--args \"<args>\"]] [--packets] [--follow-name]\n\
                \x20         [--headless [--out <folder>] [--duration <seconds>]] [--spike [seconds]]\n\n\
         --attach <pid>       start watching a running process\n\
         --launch <exe>       start the program and watch it; --args adds arguments\n\
         --packets            turn the packet layer on from the start\n\
         --follow-name        also follow new processes named like a tracked one\n\
         --headless           no window: capture until the target exits or --duration is up,\n\
                \x20             then write JSON, CSV and pcapng into --out (default: current folder)\n\
                \x20             and print their paths; --attach needs --duration\n\
         --spike [seconds]    headless ETW checks (needs an administrator prompt), default 15 s\n\
         --log                verbose logging to stderr",
        beacontap::APP_NAME,
        beacontap::APP_VERSION
    );
    std::process::exit(2)
}

fn main() {
    println!("Hello, world!");
}
