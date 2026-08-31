use beacontap::ui::{App, StartupAction};

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
    let args: Vec<String> = std::env::args().skip(1).collect();
    let mut startup = StartupAction::default();
    let mut spike: Option<u64> = None;
    let mut verbose = false;
    let mut headless = false;
    let mut follow_name = false;
    let mut out: Option<std::path::PathBuf> = None;
    let mut duration: Option<u64> = None;
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--attach" => {
                i += 1;
                startup.attach = args.get(i).and_then(|s| s.parse().ok()).or_else(|| usage());
            }
            "--launch" => {
                i += 1;
                let exe = args.get(i).cloned().unwrap_or_else(|| usage());
                startup.launch = Some((exe, String::new()));
            }
            "--args" => {
                i += 1;
                let a = args.get(i).cloned().unwrap_or_else(|| usage());
                if let Some((_, args_slot)) = startup.launch.as_mut() {
                    *args_slot = a;
                } else {
                    usage();
                }
            }
            "--spike" => {
                let secs = args.get(i + 1).and_then(|s| s.parse::<u64>().ok());
                if secs.is_some() {
                    i += 1;
                }
                spike = Some(secs.unwrap_or(15));
            }
            "--packets" => startup.packets = true,
            "--follow-name" => follow_name = true,
            "--headless" => headless = true,
            "--out" => {
                i += 1;
                out = Some(args.get(i).map(std::path::PathBuf::from).unwrap_or_else(|| usage()));
            }
            "--duration" => {
                i += 1;
                duration = Some(args.get(i).and_then(|s| s.parse().ok()).unwrap_or_else(|| usage()));
            }
            "--log" | "-v" => verbose = true,
            "-h" | "--help" | "/?" => usage(),
            other => {
                eprintln!("unknown argument {other}");
                usage();
            }
        }
        i += 1;
    }

    let level = if verbose { "debug" } else { "info" };
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or(level))
        .format_timestamp_millis()
        .init();

    if let Some(secs) = spike {
        std::process::exit(beacontap::capture::spike::run(secs));
    }
    if headless {
        let opts = beacontap::headless::HeadlessOptions {
            attach: startup.attach,
            launch: startup.launch.clone(),
            packets: startup.packets,
            out: out.unwrap_or_else(|| std::path::PathBuf::from(".")),
            duration: duration.map(std::time::Duration::from_secs),
            follow_same_name: follow_name,
        };
        std::process::exit(beacontap::headless::run(opts));
    }
    if follow_name {
        startup.follow_same_name = true;
    }

    // The window size comes from the settings file; everything else in it is read by the app.
    let (saved, _) = beacontap::settings::load();
    let size = saved
        .window_size
        .filter(|[w, h]| w.is_finite() && h.is_finite() && *w >= 820.0 && *h >= 520.0 && *w <= 8192.0 && *h <= 8192.0)
        .unwrap_or([1200.0, 760.0]);
    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_title(beacontap::APP_NAME)
            .with_app_id("com.razkom.beacontap")
            .with_inner_size(size)
            .with_min_inner_size([820.0, 520.0])
            .with_maximized(saved.window_maximized),
        ..Default::default()
    };
    if let Err(e) = eframe::run_native(
        beacontap::APP_NAME,
        options,
        Box::new(move |cc| Ok(Box::new(App::new(cc, startup)))),
    ) {
        eprintln!("window failed: {e}");
        std::process::exit(1);
    }
}
