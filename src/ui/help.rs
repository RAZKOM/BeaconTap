//! In-app help: a window with short plain-language topics, opened from the toolbar or F1.
//! The text lives here as data so it ships inside the exe and needs no files or network.

use egui::{Context, RichText, Ui};

pub struct Topic {
    pub title: &'static str,
    /// Paragraphs separated by blank lines. A paragraph starting with `## ` is a heading,
    /// one starting with `• ` is a bullet.
    pub body: &'static str,
}

pub const TOPICS: &[Topic] = &[
    Topic {
        title: "Start here",
        body: "BeaconTap shows what one program on this PC talks to on the network: every \
connection it opens, where each one goes, and how much data moves. It follows the program and \
anything the program starts.

## In four steps

1. Run BeaconTap as administrator. Windows only hands this kind of information to \
administrators. If a yellow bar says you are not one, click \"Relaunch as administrator\".

2. Click \"Choose target…\". Pick a program that is already running, or start one from the \
\"Launch & watch\" tab.

3. Watch. The Connections tab fills as the program sends and receives. The Destinations tab \
sums it up by site. The Timeline tab shows when.

4. Click \"Packets: off\" to turn the packet layer on if you want site names for encrypted \
traffic, or a packet file for Wireshark. It is off by default because it costs CPU.

Nothing leaves this PC. BeaconTap makes no network connections of its own and sends no data \
anywhere.",
    },
    Topic {
        title: "Choosing a target",
        body: "A target is one program plus everything it starts. BeaconTap calls that family \
the process tree and shows it in the left pane.

## Running process

Lists every program on the PC right now. Type part of a name to find it. A browser shows up \
many times, once per tab or helper; pick the one whose command line is shortest, and the \
others are picked up as its children.

## Launch & watch

Starts the program for you, which is the only way to catch its very first connection. \
BeaconTap creates it paused, registers it, then lets it run. Tick \"Hold the process \
suspended\" to start the capture first and release the program when you are ready.

The program is started without administrator rights, as if you had double-clicked it. Most \
programs expect that. Tick \"Run the target as administrator\" only for tools that need it.

## Follow by name

Some programs ask Windows, a service or an installer to start their helpers. The helper is \
then not a child of the program and BeaconTap would miss it. \"Also follow new processes with \
the same name\" catches a new process whose name matches a tracked one, wherever it was \
started. It is off by default because it also catches unrelated copies of the same program.",
    },
    Topic {
        title: "The process tree",
        body: "The left pane lists the target and every process it started, with the data each \
one moved. Click a process to narrow every tab to that process and its children. Click \"All \
tracked processes\" to widen again.

A greyed process has exited. It stays in the list so its connections remain readable.

Processes that were followed by name appear as extra top-level entries.",
    },
    Topic {
        title: "Connections tab",
        body: "One row per connection: one TCP connection, or one pair of UDP addresses. Rows \
stay after the connection closes, greyed, unless \"Hide closed\" is ticked.

## Columns

• Process: which process in the tree owns the connection. Hover for the PID.

• Proto: TCP or UDP. TCP is a connection with a start and an end. UDP is loose packets, used \
by DNS, calls, games and QUIC, the protocol behind HTTP/3.

• Port: the local port number. Mostly noise; it tells connections apart.

• Remote: the address and port on the other side. Port 443 is HTTPS, 80 is plain HTTP, 53 is \
DNS.

• Name: the site name BeaconTap worked out for the remote address. Hover to see where it came \
from; see \"Names and where they come from\". A blue DNS tag marks a connection to an encrypted DNS \
resolver.

• State: connecting, established or closed; datagram for UDP.

• Up, Down, Total: bytes sent and received, as the Windows kernel counted them at the socket.

• Last, First: how long ago the connection was last and first seen.

Click a column header to sort. Type in the search box to keep only rows that mention the \
text, in any column.

## Loopback

Connections from the PC to itself (127.0.0.1, ::1) are hidden by default because they are \
rarely interesting. The checkbox shows them and says how many there are.",
    },
    Topic {
        title: "Destinations tab",
        body: "The same connections grouped by where they go: one row per name, or per address \
when no name is known, with the number of connections, which processes used it, and totals.

\"Group by domain\" folds subdomains together: cdn.example.com and api.example.com become \
example.com, which is usually the company you care about.

Click a row to jump to the Connections tab filtered to that destination.

The Via column says how the name was found. See \"Names and where they come from\".",
    },
    Topic {
        title: "Timeline tab",
        body: "One strip per process: bytes per second over the last minute, five minutes or \
fifteen. Sent is drawn above the line, received below. Every strip uses the same scale, so a \
tall bar in one process means the same amount in another. Hover a bar for the numbers.

Use it to answer \"when did it talk\": a burst at start-up, a steady trickle, or a spike when \
you clicked something.",
    },
    Topic {
        title: "Names and where they come from",
        body: "The network only carries numeric addresses. BeaconTap attaches a name to an \
address in three ways. The Via column, and the hover on a name, say which one was used.

• dns: the program asked Windows to look up a name and got this address back. \"dns (tree)\" \
means another process in the tree asked. \"dns (machine)\" means some other program on the PC \
asked, which is a weaker hint.

• sni: the program said the site's name in the clear at the start of an encrypted TLS \
connection. This is the most reliable kind. It needs the packet layer.

• sni (quic): the same name, read from a QUIC connection (HTTP/3 over UDP), which browsers \
use for most large sites. It also needs the packet layer.

• sni (ech, real name hidden): the connection used Encrypted Client Hello. The real name is \
hidden by design; the shown name is the public front, often a content network.

No name at all means none of the above happened: the address came from a list inside the \
program, from a lookup BeaconTap did not see, or through an encrypted resolver.

## Encrypted DNS

Browsers and some systems send their lookups to a resolver over HTTPS, TLS or QUIC instead of \
asking Windows. BeaconTap cannot read those, but it recognises the conversation with the \
resolver itself and marks it with a blue DNS tag in the Name column. If you see that tag, expect \
bare addresses elsewhere: the names went through that connection. Turning the packet layer \
on helps, because the site name is also said in the clear when the encrypted connection to \
the site itself starts.

BeaconTap never looks names up itself. That would be a network connection of its own, and it \
would tell a DNS server what you are watching.",
    },
    Topic {
        title: "The packet layer",
        body: "By default BeaconTap listens only to the Windows kernel's bookkeeping: which \
process opened which connection and how many bytes went through. That is cheap and answers \
most questions.

\"Packets: on\" adds a second source, a copy of every network frame on every adapter. \
BeaconTap matches frames to the connections it already knows and uses them for:

• site names from TLS and QUIC (see \"Names and where they come from\"),

• DNS answers that bypassed the Windows resolver,

• byte counts as they are on the wire, and

• the pcapng export for Wireshark.

It costs CPU and memory in proportion to the traffic on the whole PC, not only the target's, \
so it is off by default. Frames that match a tracked connection are kept up to a 64 MB store; \
older ones are dropped and the export says how many.

Turn it on before the interesting connection starts. A name is only in the first packets.",
    },
    Topic {
        title: "Administrator rights",
        body: "Windows hands process, connection and packet events only to administrators. \
Without them BeaconTap can show the process list but cannot capture anything.

Click \"Relaunch as administrator\" in the yellow bar. Windows asks for consent, this window \
closes and a new one opens with the same settings.

A program launched from BeaconTap does not get those rights unless you tick the option in the \
launch form. It starts with the desktop's normal rights.",
    },
    Topic {
        title: "Exporting",
        body: "The Export menu writes what you see to a file.

• Connections as CSV: one row per connection, every column, for a spreadsheet.

• Destinations as CSV: one row per destination.

• Session as JSON: everything, including the process tree with command lines and the engine's \
counters, for scripts.

• Packets as pcapng: the captured frames for Wireshark. Needs the packet layer on. Every \
packet carries a comment with the owning process and the site name; in Wireshark add the \
\"Packet comments\" column or read it in the frame details.

Exports are written in the background and a message says when they are done. The last folder \
is remembered.",
    },
    Topic {
        title: "When something is missing",
        body: "## No connections at all

The target has not sent anything yet, or it did its talking before the capture started. \
Launch it from BeaconTap to see the beginning. The top right must say \"capturing\".

## Connections but no names

Turn the packet layer on, then open the site again; names are only read at the start of a \
connection. Some names cannot be read at all, see \"Names and where they come from\".

## A helper process is not in the tree

See \"Follow by name\" under \"Choosing a target\".

## \"unattributed\" in the status bar

Network events whose process never appeared. Usually a process that exited before BeaconTap \
started watching. Harmless.

## \"packets lost\" in the status bar

Windows could not deliver every frame, usually under very heavy traffic. The byte counts are \
still right, since they come from the kernel, but some names may be missing.

## A red bar says the capture is not running

The capture failed to start, and the bar says why. \"Copy message\" puts the text on the \
clipboard. The usual cause is missing administrator rights.",
    },
    Topic {
        title: "Glossary",
        body: "• Process: one running program. A program can run as several processes.

• PID: the number Windows gives a process. It is reused after the process exits, which is why \
BeaconTap also remembers when each one started.

• Process tree: a process, everything it started, and what those started.

• Connection, flow: one conversation between two addresses and ports. BeaconTap uses both \
words for the same thing.

• TCP: a reliable two-way connection with a start and an end. Web pages, mail, most things.

• UDP: single packets with no connection. DNS, QUIC, calls, games.

• Port: a number on each end of a connection that says which program or service the data is \
for. 443 is HTTPS.

• DNS: the service that turns a name like example.com into an address.

• TLS: the encryption under HTTPS. Its first message names the site in the clear.

• SNI: Server Name Indication, that name.

• QUIC: a newer transport over UDP, used by HTTP/3. Browsers use it for most large sites.

• ECH: Encrypted Client Hello, a TLS extension that hides the SNI.

• Loopback: traffic from the PC to itself.

• ETW: Event Tracing for Windows, the kernel's event feed BeaconTap listens to.

• pcapng: the packet capture file format Wireshark reads.",
    },
];

#[derive(Default)]
pub struct HelpWindow {
    pub open: bool,
    topic: usize,
}

impl HelpWindow {
    pub fn open(&mut self) {
        self.open = true;
    }

    /// Open on the topic with this title, if there is one.
    pub fn open_topic(&mut self, title: &str) {
        if let Some(i) = TOPICS.iter().position(|t| t.title == title) {
            self.topic = i;
        }
        self.open = true;
    }

    pub fn show(&mut self, ctx: &Context) {
        if ctx.input(|i| i.key_pressed(egui::Key::F1)) {
            self.open = true;
        }
        if !self.open {
            return;
        }
        let mut open = self.open;
        egui::Window::new("Help")
            .open(&mut open)
            .default_size([800.0, 560.0])
            .min_size([520.0, 300.0])
            .resizable(true)
            .collapsible(false)
            .show(ctx, |ui| self.body(ui));
        self.open = open;
    }

    fn body(&mut self, ui: &mut Ui) {
        // A new window measures its content in a sizing pass with wrapping off, which would
        // make the widest paragraph set the window width. Always wrap here.
        ui.style_mut().wrap_mode = Some(egui::TextWrapMode::Wrap);
        let avail = ui.available_height();
        ui.horizontal_top(|ui| {
            ui.vertical(|ui| {
                ui.set_width(200.0);
                ui.set_min_height(avail);
                for (i, t) in TOPICS.iter().enumerate() {
                    if ui.selectable_label(self.topic == i, t.title).clicked() {
                        self.topic = i;
                    }
                }
                ui.add_space(8.0);
                ui.weak("F1 opens this window.");
            });
            ui.separator();
            // The split above is a horizontal layout; the text column must be top-down.
            ui.vertical(|ui| {
                egui::ScrollArea::vertical()
                    .id_salt(("help-body", self.topic))
                    .auto_shrink([false, false])
                    .show(ui, |ui| {
                        let t = &TOPICS[self.topic];
                        ui.set_max_width(ui.available_width().min(760.0) - 8.0);
                        ui.heading(t.title);
                        ui.add_space(6.0);
                        render_body(ui, t.body);
                    });
            });
        });
    }
}

/// Lay out a topic body: paragraphs, `## ` headings and `• ` bullets.
pub fn render_body(ui: &mut Ui, body: &str) {
    for para in body.split("\n\n") {
        let para = para.trim();
        if para.is_empty() {
            continue;
        }
        if let Some(h) = para.strip_prefix("## ") {
            ui.add_space(6.0);
            ui.label(RichText::new(h).strong());
            ui.add_space(2.0);
        } else if let Some(b) = para.strip_prefix("• ") {
            ui.horizontal_wrapped(|ui| {
                ui.label("•");
                ui.label(b);
            });
        } else {
            ui.label(para);
        }
        ui.add_space(4.0);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn topics_are_well_formed() {
        let titles: Vec<&str> = TOPICS.iter().map(|t| t.title).collect();
        for t in TOPICS {
            assert!(!t.body.trim().is_empty(), "{} is empty", t.title);
            assert!(t.body.len() < 4000, "{} is too long to read in a window", t.title);
            for para in t.body.split("\n\n") {
                assert!(!para.contains('\n'), "{}: a paragraph has a stray line break: {para:?}", t.title);
            }
            // Cross references name real topics.
            for (start, _) in t.body.match_indices("see \"") {
                let rest = &t.body[start + 5..];
                let name = &rest[..rest.find('"').unwrap()];
                assert!(titles.contains(&name), "{}: refers to unknown topic {name:?}", t.title);
            }
        }
        let mut w = HelpWindow::default();
        w.open_topic("Glossary");
        assert!(w.open);
        assert_eq!(TOPICS[w.topic].title, "Glossary");
    }
}
