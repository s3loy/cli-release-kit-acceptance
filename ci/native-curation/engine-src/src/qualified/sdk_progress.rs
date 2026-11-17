use std::{
    fs::Metadata,
    path::{Path, PathBuf},
    time::{Duration, Instant},
};

pub(super) struct Progress {
    root: PathBuf,
    phase: &'static str,
    started: Instant,
    last: Instant,
    entries: u64,
    files: u64,
    links: u64,
    file_bytes: u64,
}

impl Progress {
    pub(super) fn new(root: &Path, phase: &'static str) -> Self {
        let now = Instant::now();
        let progress = Self {
            root: root.to_owned(),
            phase,
            started: now,
            last: now,
            entries: 0,
            files: 0,
            links: 0,
            file_bytes: 0,
        };
        progress.emit("started", root);
        progress
    }

    pub(super) fn visit(&mut self, path: &Path, metadata: &Metadata) {
        self.entries += 1;
        if metadata.file_type().is_symlink() {
            self.links += 1;
        } else if metadata.is_file() {
            self.files += 1;
            self.file_bytes += metadata.len();
        }
        if self.last.elapsed() >= Duration::from_secs(2) {
            self.emit("progress", path);
            self.last = Instant::now();
        }
    }

    pub(super) fn finish(self) {
        self.emit("completed", &self.root);
    }

    fn emit(&self, state: &str, path: &Path) {
        eprintln!(
            "{}",
            serde_json::json!({
                "event": "sdk-inspection",
                "phase": self.phase,
                "state": state,
                "root": self.root.to_string_lossy(),
                "path": path.to_string_lossy(),
                "elapsed_ms": self.started.elapsed().as_millis(),
                "entries": self.entries,
                "files": self.files,
                "links": self.links,
                "file_bytes": self.file_bytes,
            })
        );
    }
}
