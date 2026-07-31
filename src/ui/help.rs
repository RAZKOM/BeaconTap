//! In-app help: a window with short plain-language topics, opened from the toolbar or F1.
//! The text lives here as data so it ships inside the exe and needs no files or network.

#[derive(Default)]
pub struct HelpWindow {
    pub open: bool,
    topic: usize,
}

impl HelpWindow {
    pub fn open(&mut self) {
        self.open = true;
    }

}

