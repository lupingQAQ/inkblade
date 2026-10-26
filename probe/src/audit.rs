//! Audit line writer.  Protocol bytes own stdout in `run --stdio`; audit
//! therefore goes to stderr (and an optional file) in that mode.

use std::fs::OpenOptions;
use std::io::Write;
use std::path::PathBuf;
use std::sync::Mutex;

use crate::json;
use crate::util;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AuditSink {
    Stdout,
    Stderr,
}

pub struct Audit {
    sink: AuditSink,
    path: Option<PathBuf>,
    probe_id: String,
    lock: Mutex<()>,
}

impl Audit {
    pub fn new(sink: AuditSink, path: Option<PathBuf>, probe_id: &str) -> Self {
        Self {
            sink,
            path,
            probe_id: probe_id.to_string(),
            lock: Mutex::new(()),
        }
    }

    pub fn event(&self, event: &str, detail: json::Value) {
        let line = json::object(vec![
            ("ts", json::number(util::now())),
            ("probe_id", json::string(self.probe_id.clone())),
            ("event", json::string(event)),
            ("detail", detail),
        ])
        .to_json();
        let _guard = self.lock.lock();
        if let Some(path) = &self.path {
            if let Ok(mut file) = OpenOptions::new().create(true).append(true).open(path) {
                let _ = writeln!(file, "{line}");
            }
        }
        match self.sink {
            AuditSink::Stdout => {
                let _ = writeln!(std::io::stdout(), "{line}");
            }
            AuditSink::Stderr => {
                let _ = writeln!(std::io::stderr(), "{line}");
            }
        }
    }
}
