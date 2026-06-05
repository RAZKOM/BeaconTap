//! Session export: JSON and CSV from a [`Snapshot`], pcapng from a [`PacketDump`]. Pure
//! functions that produce bytes; the UI picks the file and writes it on a worker thread.

pub mod pcapng;

