//! In-memory ring buffer of recent log lines for the API dashboard.
//!
//! Installed as a `tracing` Layer alongside the normal fmt subscriber so the
//! `/logs` endpoint can show the same runtime output without reading files.

use once_cell::sync::Lazy;
use serde::Serialize;
use std::collections::VecDeque;
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};
use tracing::{Event, Level, Subscriber};
use tracing_subscriber::layer::Context;
use tracing_subscriber::registry::LookupSpan;
use tracing_subscriber::Layer;

/// Max lines kept in memory (oldest dropped first).
const CAPACITY: usize = 2000;

static BUFFER: Lazy<Mutex<VecDeque<LogLine>>> =
    Lazy::new(|| Mutex::new(VecDeque::with_capacity(CAPACITY)));

#[derive(Debug, Clone, Serialize)]
pub struct LogLine {
    /// Unix milliseconds when the event was emitted.
    pub ts_ms: u64,
    /// TRACE / DEBUG / INFO / WARN / ERROR
    pub level: String,
    /// Formatted message (target + fields).
    pub msg: String,
}

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

/// Snapshot of the buffer (oldest → newest). Optional `limit` returns the
/// most recent N lines.
pub fn list(limit: Option<usize>) -> Vec<LogLine> {
    let guard = BUFFER.lock().unwrap_or_else(|e| e.into_inner());
    let n = limit.unwrap_or(guard.len()).min(guard.len());
    guard.iter().rev().take(n).cloned().collect::<Vec<_>>().into_iter().rev().collect()
}

/// Clear the in-memory buffer (used by DELETE /logs).
pub fn clear() {
    if let Ok(mut g) = BUFFER.lock() {
        g.clear();
    }
}

fn push(level: Level, msg: String) {
    let line = LogLine {
        ts_ms: now_ms(),
        level: level_str(level).to_string(),
        msg,
    };
    if let Ok(mut g) = BUFFER.lock() {
        if g.len() >= CAPACITY {
            g.pop_front();
        }
        g.push_back(line);
    }
}

fn level_str(l: Level) -> &'static str {
    match l {
        Level::ERROR => "ERROR",
        Level::WARN => "WARN",
        Level::INFO => "INFO",
        Level::DEBUG => "DEBUG",
        Level::TRACE => "TRACE",
    }
}

/// Collects the event message + key fields into a single string.
struct FieldVisitor {
    message: Option<String>,
    fields: Vec<(String, String)>,
}

impl tracing::field::Visit for FieldVisitor {
    fn record_debug(&mut self, field: &tracing::field::Field, value: &dyn std::fmt::Debug) {
        let s = format!("{value:?}");
        if field.name() == "message" {
            self.message = Some(s.trim_matches('"').to_string());
        } else {
            self.fields.push((field.name().to_string(), s));
        }
    }

    fn record_str(&mut self, field: &tracing::field::Field, value: &str) {
        if field.name() == "message" {
            self.message = Some(value.to_string());
        } else {
            self.fields
                .push((field.name().to_string(), value.to_string()));
        }
    }

    fn record_i64(&mut self, field: &tracing::field::Field, value: i64) {
        self.fields
            .push((field.name().to_string(), value.to_string()));
    }

    fn record_u64(&mut self, field: &tracing::field::Field, value: u64) {
        self.fields
            .push((field.name().to_string(), value.to_string()));
    }

    fn record_bool(&mut self, field: &tracing::field::Field, value: bool) {
        self.fields
            .push((field.name().to_string(), value.to_string()));
    }
}

/// Tracing layer that appends formatted events into the ring buffer.
pub struct BufferLayer;

impl<S> Layer<S> for BufferLayer
where
    S: Subscriber + for<'a> LookupSpan<'a>,
{
    fn on_event(&self, event: &Event<'_>, _ctx: Context<'_, S>) {
        let meta = event.metadata();
        let mut vis = FieldVisitor {
            message: None,
            fields: Vec::new(),
        };
        event.record(&mut vis);

        let mut msg = String::new();
        let target = meta.target();
        // Skip noisy internal targets if desired; keep all for now.
        if !target.is_empty() && target != "ant" {
            msg.push_str(target);
            msg.push_str(": ");
        }
        if let Some(m) = vis.message {
            msg.push_str(&m);
        }
        for (k, v) in vis.fields {
            if !msg.is_empty() {
                msg.push(' ');
            }
            msg.push_str(&k);
            msg.push('=');
            msg.push_str(&v);
        }
        if msg.is_empty() {
            msg = meta.name().to_string();
        }
        push(*meta.level(), msg);
    }
}
