//! Ported from ip-enrichment-worker/tail.go: offset-persisted incremental
//! file reads so a worker restart resumes where it left off (no re-shipped
//! duplicates, no silently-skipped lines while it was down), and a
//! rename-based log rotation (the file now shorter than the last offset)
//! resumes from byte 0 of the fresh file instead of erroring or blocking.

use std::fs;
use std::io::{Read, Seek, SeekFrom};
use std::path::Path;

pub fn load_offset(state_path: &Path) -> Option<i64> {
    let raw = fs::read_to_string(state_path).ok()?;
    raw.trim().parse::<i64>().ok()
}

pub fn save_offset(state_path: &Path, offset: i64) -> std::io::Result<()> {
    fs::write(state_path, offset.to_string())
}

/// Reads every complete (newline-terminated) line from `path` starting at
/// `offset`. A trailing partial line is left unconsumed so the next call
/// re-reads it whole once it's complete. Returns `(lines, new_offset)`.
pub fn read_new_lines(path: &Path, offset: i64) -> std::io::Result<(Vec<Vec<u8>>, i64)> {
    let meta = fs::metadata(path)?;
    let mut offset = offset;
    if (meta.len() as i64) < offset {
        offset = 0;
    }

    let mut f = fs::File::open(path)?;
    if offset > 0 {
        f.seek(SeekFrom::Start(offset as u64))?;
    }
    let mut data = Vec::new();
    f.read_to_end(&mut data)?;

    let last = match data.iter().rposition(|&b| b == b'\n') {
        Some(idx) => idx,
        None => return Ok((Vec::new(), offset)),
    };
    let complete = &data[..=last];
    let new_offset = offset + complete.len() as i64;
    let lines = complete
        .split(|&b| b == b'\n')
        .map(|l| {
            let start = l.iter().position(|&b| !b.is_ascii_whitespace()).unwrap_or(l.len());
            let end = l.iter().rposition(|&b| !b.is_ascii_whitespace()).map(|i| i + 1).unwrap_or(0);
            if start < end { l[start..end].to_vec() } else { Vec::new() }
        })
        .filter(|l| !l.is_empty())
        .collect();
    Ok((lines, new_offset))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    #[test]
    fn reads_only_complete_lines_and_leaves_partial_unconsumed() {
        let dir = std::env::temp_dir().join(format!("ip-enrich-tail-test-{}", std::process::id()));
        fs::create_dir_all(&dir).unwrap();
        let path = dir.join("f.json");
        fs::write(&path, b"{\"a\":1}\n{\"a\":2}\nparti").unwrap();
        let (lines, offset) = read_new_lines(&path, 0).unwrap();
        assert_eq!(lines.len(), 2);
        assert_eq!(lines[0], b"{\"a\":1}");
        // offset stops before the trailing partial line
        let mut f = fs::OpenOptions::new().append(true).open(&path).unwrap();
        writeln!(f, "al").unwrap();
        let (lines2, _offset2) = read_new_lines(&path, offset).unwrap();
        assert_eq!(lines2.len(), 1);
        assert_eq!(lines2[0], b"partial");
        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn resumes_from_zero_when_file_shrank_below_offset() {
        let dir = std::env::temp_dir().join(format!("ip-enrich-tail-test2-{}", std::process::id()));
        fs::create_dir_all(&dir).unwrap();
        let path = dir.join("f.json");
        fs::write(&path, b"short\n").unwrap();
        let (lines, _offset) = read_new_lines(&path, 1000).unwrap();
        assert_eq!(lines.len(), 1);
        assert_eq!(lines[0], b"short");
        fs::remove_dir_all(&dir).ok();
    }
}
