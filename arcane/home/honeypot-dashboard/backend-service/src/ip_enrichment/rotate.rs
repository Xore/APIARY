//! Ported from ip-enrichment-worker/rotate.go: a self-rotating output file
//! writer (close, rename aside with a timestamp suffix, reopen fresh) — the
//! enriched-output equivalent of the raw sensor writers' own rotation, so
//! OUT_DIR/*.json never grows unbounded. Filebeat's file_identity defaults
//! to inode/device, not path, so its harvester stays attached to the
//! renamed file through EOF and picks up the fresh one via the same glob —
//! no coordination needed with the harvester.

use chrono::Utc;
use std::fs::{self, File, OpenOptions};
use std::io::Write;
use std::path::PathBuf;

pub struct OutputWriter {
    file: File,
    path: PathBuf,
    size: u64,
    max: u64,
}

impl OutputWriter {
    pub fn open(path: PathBuf, max_bytes: u64) -> std::io::Result<Self> {
        let file = OpenOptions::new().create(true).append(true).open(&path)?;
        let size = file.metadata().map(|m| m.len()).unwrap_or(0);
        Ok(Self { file, path, size, max: max_bytes })
    }

    /// Closes the current file, renames it aside, reopens fresh at the
    /// original path. On any failure this leaves `self.file` as whatever it
    /// was before — a still-open, over-threshold file beats losing the
    /// descriptor and silently dropping every subsequent write.
    fn rotate(&mut self) {
        // Second-granularity timestamps collide when two rotations happen
        // within the same wall-clock second — disambiguate with a counter
        // suffix instead of trusting the clock alone.
        let stamp = Utc::now().format("%Y%m%d-%H%M%S").to_string();
        let mut target = PathBuf::from(format!("{}.{stamp}", self.path.display()));
        if target.exists() {
            let mut n = 2u32;
            loop {
                let candidate = PathBuf::from(format!("{}.{n}", target.display()));
                if !candidate.exists() {
                    target = candidate;
                    break;
                }
                n += 1;
            }
        }
        if let Err(error) = fs::rename(&self.path, &target) {
            tracing::warn!(path = %self.path.display(), %error, "ip-enrichment: rename for rotation failed");
        }
        match OpenOptions::new().create(true).append(true).open(&self.path) {
            Ok(f) => {
                self.file = f;
                self.size = 0;
            }
            Err(error) => {
                tracing::warn!(path = %self.path.display(), %error, "ip-enrichment: reopen after rotation failed");
            }
        }
    }

    /// Writes every line (checking the rotation threshold once, up front —
    /// a batch straddling the threshold finishes in the file it started
    /// in). Returns whether every line was written; on a partial/failed
    /// write the caller must not advance/persist its input offset.
    pub fn write_lines(&mut self, lines: &[Vec<u8>]) -> bool {
        if self.max > 0 && self.size >= self.max {
            self.rotate();
        }
        for line in lines {
            if let Err(error) = self.file.write_all(line).and_then(|_| self.file.write_all(b"\n")) {
                tracing::warn!(path = %self.path.display(), %error, "ip-enrichment: write output failed");
                return false;
            }
            self.size += line.len() as u64 + 1;
        }
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rotates_once_the_size_threshold_is_crossed() {
        let dir = std::env::temp_dir().join(format!("ip-enrich-rotate-test-{}", std::process::id()));
        fs::create_dir_all(&dir).unwrap();
        let path = dir.join("cowrie.json");
        let mut w = OutputWriter::open(path.clone(), 10).unwrap();
        assert!(w.write_lines(&[b"01234567890123".to_vec()])); // over the 10-byte cap already
        assert!(w.write_lines(&[b"x".to_vec()])); // triggers rotation on entry
        let rotated: Vec<_> = fs::read_dir(&dir)
            .unwrap()
            .filter_map(|e| e.ok())
            .filter(|e| e.file_name().to_string_lossy().starts_with("cowrie.json."))
            .collect();
        assert_eq!(rotated.len(), 1, "expected exactly one rotated generation");
        fs::remove_dir_all(&dir).ok();
    }
}
