//! Left pane: the tracked process tree with per-node totals.

use super::fmt_bytes;
use crate::model::{ProcessKey, ProcessNode, Snapshot};
use egui::{Color32, RichText, Ui};

pub struct TreePane;

impl TreePane {
    fn node(
        ui: &mut Ui,
        snapshot: &Snapshot,
        key: ProcessKey,
        selected: &mut Option<ProcessKey>,
        depth: usize,
    ) {
        let Some(node) = snapshot.nodes.get(&key) else {
            return;
        };
        let is_selected = *selected == Some(key);
        // Roots after the first were adopted by name, not started by the target.
        let adopted = depth == 0 && node.root && snapshot.roots.first() != Some(&key);
        let label = Self::label(node, adopted);
        let has_children = !node.children.is_empty();

        let row = ui.horizontal(|ui| {
            ui.add_space(depth as f32 * 14.0);
            let id = ui.make_persistent_id(("tree", key.pid, key.start));
            let mut open_state = egui::collapsing_header::CollapsingState::load_with_default_open(
                ui.ctx(),
                id,
                true,
            );
            if has_children {
                open_state.show_toggle_button(ui, egui::collapsing_header::paint_default_icon);
            } else {
                ui.add_space(18.0);
            }
            let resp = ui.selectable_label(is_selected, label);
            if resp.clicked() {
                *selected = Some(key);
            }
            resp.on_hover_ui(|ui| {
                Self::tooltip(ui, node);
                if adopted {
                    ui.weak("followed by name: started by a process outside the tree");
                }
            });
            open_state.store(ui.ctx());
            open_state.is_open()
        });
        if has_children && row.inner {
            for child in &node.children {
                Self::node(ui, snapshot, *child, selected, depth + 1);
            }
        }
    }

    fn label(node: &ProcessNode, adopted: bool) -> egui::text::LayoutJob {
        let mut job = egui::text::LayoutJob::default();
        let base = if node.is_live() {
            Color32::PLACEHOLDER
        } else {
            Color32::GRAY
        };
        let name = RichText::new(&node.name).color(base);
        name.append_to(
            &mut job,
            &egui::Style::default(),
            egui::FontSelection::Default,
            egui::Align::Center,
        );
        let meta = RichText::new(format!("  {}", node.key.pid)).weak().small();
        meta.append_to(
            &mut job,
            &egui::Style::default(),
            egui::FontSelection::Default,
            egui::Align::Center,
        );
        if adopted {
            RichText::new("  by name").small().weak().append_to(
                &mut job,
                &egui::Style::default(),
                egui::FontSelection::Default,
                egui::Align::Center,
            );
        }
        if node.elevated == Some(true) {
            RichText::new("  admin")
                .small()
                .color(Color32::from_rgb(220, 160, 60))
                .append_to(
                    &mut job,
                    &egui::Style::default(),
                    egui::FontSelection::Default,
                    egui::Align::Center,
                );
        }
        let bytes = node.subtree.bytes();
        let bytes_text = if bytes > 0 {
            format!("   {}", fmt_bytes(bytes))
        } else {
            String::new()
        };
        RichText::new(bytes_text)
            .monospace()
            .small()
            .weak()
            .append_to(
                &mut job,
                &egui::Style::default(),
                egui::FontSelection::Default,
                egui::Align::Center,
            );
        job
    }

    fn tooltip(ui: &mut Ui, node: &ProcessNode) {
        ui.set_max_width(520.0);
        ui.strong(&node.name);
        ui.label(format!("PID {}", node.key.pid));
        if let Some(p) = &node.image_path {
            ui.label(p);
        }
        if let Some(c) = &node.cmdline {
            ui.monospace(c);
        } else {
            ui.weak("command line unavailable");
        }
        if let Some(s) = node.session_id {
            ui.weak(format!("session {s}"));
        }
        if let Some(code) = node.exit_code {
            ui.weak(format!("exited with code {code}"));
        } else if node.exited.is_some() {
            ui.weak("exited");
        }
    }
}
