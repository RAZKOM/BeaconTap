# BeaconTap

See what a program talks to on the network, and nothing else.

BeaconTap is a network monitor for Windows that watches one process tree instead of the whole machine. Pick a running program, or launch one from inside BeaconTap, and it follows that program and every child it spawns: which hosts they connect to, over what, how much data, and when.

I wrote it because Wireshark shows you everything on the wire and makes you work out which process sent it, and Resource Monitor tells you the process but not much else. I wanted both at once.

![BeaconTap watching a browser](docs/screenshot.png)

It's a single native exe written in Rust. No installer, no telemetry, and it never sends anything over the network itself. MIT licensed. Made by [RAZKOM](https://razkom.com).

## Building

You need Rust 1.95+ and Windows 10 1809+ (x64).

```
cargo build --release
target\release\beacontap.exe
```

`cargo test` runs the unit tests. They replay recorded events, so they don't need admin or a live capture.

