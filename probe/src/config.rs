//! Runtime options shared by the CLI and the protocol server.

use std::path::PathBuf;

use crate::audit::AuditSink;

#[derive(Clone, Debug)]
pub struct Options {
    pub token: String,
    pub read_only: bool,
    pub allow_cmds: Vec<String>,
    pub max_output: usize,
    pub max_timeout_ms: u64,
    pub probe_id: String,
    pub parent_id: Option<String>,
    pub audit_path: Option<PathBuf>,
    pub audit_sink: AuditSink,
    pub templates_dir: Option<PathBuf>,
    pub max_window: usize,
    pub keep_binary: bool,
    // Bypass plan inputs (see `inkblade-probe bypass --help`).  Kept here so
    // the same plan works for the CLI and for `run --stdio` task dispatch.
    pub bypass_plan: Option<String>,
    pub bypass_techniques: Vec<String>,
    pub bypass_script: Option<String>,
    pub bypass_script_b64: Option<String>,
    pub bypass_workdir: Option<String>,
    pub bypass_monitored: Vec<String>,
    pub bypass_target_namespace: Option<String>,
    pub bypass_target_pod: Option<String>,
    pub bypass_container: Option<String>,
}

impl Options {
    pub fn allows_write(&self) -> bool {
        !self.read_only
    }

    pub fn max_output_bytes(&self) -> usize {
        self.max_output.clamp(1024, 16 * 1024 * 1024)
    }

    pub fn timeout_ms(&self, requested: Option<u64>) -> u64 {
        requested
            .unwrap_or(5_000)
            .clamp(50, self.max_timeout_ms.max(50))
    }
}

impl Default for Options {
    fn default() -> Self {
        Self {
            token: String::new(),
            read_only: true,
            allow_cmds: Vec::new(),
            max_output: 1024 * 1024,
            max_timeout_ms: 30_000,
            probe_id: String::new(),
            parent_id: None,
            audit_path: None,
            audit_sink: AuditSink::Stderr,
            templates_dir: None,
            max_window: 4,
            keep_binary: false,
            bypass_plan: None,
            bypass_techniques: Vec::new(),
            bypass_script: None,
            bypass_script_b64: None,
            bypass_workdir: None,
            bypass_monitored: Vec::new(),
            bypass_target_namespace: None,
            bypass_target_pod: None,
            bypass_container: None,
        }
    }
}
