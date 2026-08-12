//! Timeline tab: one strip per tracked process, bytes per second, up above the midline and
//! down below, on a shared scale. The whole tree is the first row.

use super::fmt_bytes;
use crate::model::timeline::{Bucket, Series, BUCKET_NS};
use crate::model::{now, ProcessKey, Snapshot};
use egui::{Color32, Pos2, Rect, RichText, Sense, Stroke, Ui, Vec2};
use time::{OffsetDateTime, UtcOffset};

const ROW_H: f32 = 34.0;
const LABEL_W: f32 = 190.0;

pub struct TimelineView {
    pub window_secs: i64,
    offset: UtcOffset,
}

impl Default for TimelineView {
    fn default() -> Self {
        Self::new()
    }
}

struct Row {
    key: Option<ProcessKey>,
    label: String,
    depth: usize,
    live: bool,
}

impl TimelineView {
    pub fn new() -> Self {
        TimelineView {
            window_secs: 300,
            offset: UtcOffset::current_local_offset().unwrap_or(UtcOffset::UTC),
        }
    }

    fn clock(&self, sec: i64) -> String {
        match OffsetDateTime::from_unix_timestamp(sec) {
            Ok(t) => {
                let t = t.to_offset(self.offset);
                format!("{:02}:{:02}:{:02}", t.hour(), t.minute(), t.second())
            }
            Err(_) => "?".into(),
        }
    }

    fn rows(snapshot: &Snapshot) -> Vec<Row> {
        let mut rows = vec![Row {
            key: None,
            label: "All tracked".into(),
            depth: 0,
            live: true,
        }];
        let mut stack: Vec<(ProcessKey, usize)> = snapshot
            .roots
            .iter()
            .rev()
            .map(|r| (*r, 0))
            .collect();
        while let Some((k, depth)) = stack.pop() {
            if let Some(n) = snapshot.nodes.get(&k) {
                rows.push(Row {
                    key: Some(k),
                    label: format!("{}  {}", n.name, k.pid),
                    depth,
                    live: n.is_live(),
                });
                for c in n.children.iter().rev() {
                    stack.push((*c, depth + 1));
                }
            }
        }
        rows
    }

    fn series(snapshot: &Snapshot, key: Option<ProcessKey>) -> Option<&Series> {
        match key {
            None => Some(&snapshot.timeline.total),
            Some(k) => snapshot.timeline.per_process.get(&k),
        }
    }

    pub fn show(&mut self, ui: &mut Ui, snapshot: &Snapshot, selected: Option<ProcessKey>) {
        ui.horizontal(|ui| {
            ui.label("Window")
                .on_hover_text("How much history the strips show. Hover a bar for its numbers.");
            ui.selectable_value(&mut self.window_secs, 60, "1 min");
            ui.selectable_value(&mut self.window_secs, 300, "5 min");
            ui.selectable_value(&mut self.window_secs, 900, "15 min");
            ui.separator();
            ui.weak("bytes per second, sent above the line, received below, one scale for every row");
        });
        ui.add_space(2.0);
        if snapshot.roots.is_empty() {
            ui.add_space(12.0);
            ui.weak("No target yet. Choose a process or launch one.");
            return;
        }
        let now_sec = now().div_euclid(BUCKET_NS);
        let start_sec = now_sec - self.window_secs + 1;
        let rows = Self::rows(snapshot);
        // Shared scale: the largest single-direction second in view, over the process rows.
        let mut peak: u64 = 1;
        for r in rows.iter().skip(1) {
            if let Some(s) = Self::series(snapshot, r.key) {
                for sec in start_sec.max(s.first_sec)..=now_sec.min(s.last_sec()) {
                    let b = s.get(sec);
                    peak = peak.max(b.up).max(b.down);
                }
            }
        }
        let total_peak = Self::series(snapshot, None)
            .map(|s| {
                (start_sec.max(s.first_sec)..=now_sec.min(s.last_sec()))
                    .map(|sec| {
                        let b = s.get(sec);
                        b.up.max(b.down)
                    })
                    .max()
                    .unwrap_or(0)
            })
            .unwrap_or(0)
            .max(1);

        // Axis.
        ui.horizontal(|ui| {
            ui.add_space(LABEL_W);
            let (rect, _) = ui.allocate_exact_size(
                Vec2::new(ui.available_width(), 16.0),
                Sense::hover(),
            );
            let painter = ui.painter_at(rect);
            let ticks = 6;
            for i in 0..=ticks {
                let frac = i as f32 / ticks as f32;
                let x = rect.left() + frac * rect.width();
                let sec = start_sec + ((self.window_secs - 1) as f32 * frac) as i64;
                let text = if i == ticks { "now".to_string() } else { self.clock(sec) };
                let anchor = if i == ticks {
                    egui::Align2::RIGHT_CENTER
                } else if i == 0 {
                    egui::Align2::LEFT_CENTER
                } else {
                    egui::Align2::CENTER_CENTER
                };
                painter.text(
                    Pos2::new(x, rect.center().y),
                    anchor,
                    text,
                    egui::FontId::proportional(11.0),
                    Color32::GRAY,
                );
            }
        });

        egui::ScrollArea::vertical()
            .auto_shrink([false, false])
            .show(ui, |ui| {
                for (i, r) in rows.iter().enumerate() {
                    let is_total = r.key.is_none();
                    let scale = if is_total { total_peak } else { peak };
                    let highlighted = selected.is_some() && r.key == selected;
                    ui.horizontal(|ui| {
                        ui.add_space(4.0 + r.depth as f32 * 12.0);
                        let mut text = RichText::new(&r.label);
                        if is_total {
                            text = text.strong();
                        } else if !r.live {
                            text = text.color(Color32::GRAY);
                        }
                        if highlighted {
                            text = text.color(Color32::LIGHT_BLUE);
                        }
                        let label_w = (LABEL_W - 4.0 - r.depth as f32 * 12.0).max(40.0);
                        ui.add_sized(
                            Vec2::new(label_w, ROW_H),
                            egui::Label::new(text).truncate(),
                        );
                        let (rect, resp) = ui.allocate_exact_size(
                            Vec2::new(ui.available_width(), ROW_H),
                            Sense::hover(),
                        );
                        self.strip(ui, rect, &resp, Self::series(snapshot, r.key), start_sec, now_sec, scale, i);
                    });
                }
                ui.add_space(4.0);
                ui.weak(format!(
                    "scale: {}/s per half row for processes, {}/s for the total",
                    fmt_bytes(peak),
                    fmt_bytes(total_peak)
                ));
            });
    }

    #[allow(clippy::too_many_arguments)]
    fn strip(
        &self,
        ui: &Ui,
        rect: Rect,
        resp: &egui::Response,
        series: Option<&Series>,
        start_sec: i64,
        now_sec: i64,
        scale: u64,
        row_index: usize,
    ) {
        let painter = ui.painter_at(rect);
        let bg = if row_index.is_multiple_of(2) {
            Color32::from_gray(28)
        } else {
            Color32::from_gray(32)
        };
        painter.rect_filled(rect, 2.0, bg);
        let mid = rect.center().y;
        painter.line_segment(
            [Pos2::new(rect.left(), mid), Pos2::new(rect.right(), mid)],
            Stroke::new(1.0, Color32::from_gray(60)),
        );
        let Some(series) = series else {
            return;
        };
        let n = (now_sec - start_sec + 1) as f32;
        let w = rect.width() / n;
        let half = rect.height() / 2.0 - 1.0;
        let up_col = Color32::from_rgb(90, 200, 120);
        let down_col = Color32::from_rgb(90, 150, 230);
        let scale_f = scale as f64;
        let height = |v: u64| -> f32 {
            if v == 0 {
                0.0
            } else {
                // Square root so a quiet second next to a burst is still visible.
                (((v as f64) / scale_f).sqrt() as f32 * half).max(1.0)
            }
        };
        let first = start_sec.max(series.first_sec);
        let last = now_sec.min(series.last_sec());
        for sec in first..=last {
            let b: Bucket = series.get(sec);
            if b.up == 0 && b.down == 0 {
                continue;
            }
            let x0 = rect.left() + (sec - start_sec) as f32 * w;
            let x1 = (x0 + w).max(x0 + 1.0);
            if b.up > 0 {
                let h = height(b.up);
                painter.rect_filled(
                    Rect::from_min_max(Pos2::new(x0, mid - h), Pos2::new(x1, mid)),
                    0.0,
                    up_col,
                );
            }
            if b.down > 0 {
                let h = height(b.down);
                painter.rect_filled(
                    Rect::from_min_max(Pos2::new(x0, mid), Pos2::new(x1, mid + h)),
                    0.0,
                    down_col,
                );
            }
        }
        if let Some(pos) = resp.hover_pos() {
            let sec = start_sec + ((pos.x - rect.left()) / w) as i64;
            let b = series.get(sec);
            let x = rect.left() + (sec - start_sec) as f32 * w;
            painter.line_segment(
                [Pos2::new(x, rect.top()), Pos2::new(x, rect.bottom())],
                Stroke::new(1.0, Color32::from_gray(120)),
            );
            resp.clone().on_hover_text(format!(
                "{}\nup {}/s\ndown {}/s",
                self.clock(sec),
                fmt_bytes(b.up),
                fmt_bytes(b.down)
            ));
        }
    }
}
