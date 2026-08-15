//! In-app help: a window with short plain-language topics, opened from the toolbar or F1.
//! The text lives here as data so it ships inside the exe and needs no files or network.

pub struct Topic {
    pub title: &'static str,
    /// Paragraphs separated by blank lines. A paragraph starting with `## ` is a heading,
    /// one starting with `• ` is a bullet.
    pub body: &'static str,
}

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

