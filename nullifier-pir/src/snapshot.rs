//! Snapshot download and fixed-width nullifier access.

use std::fs::{self, File};
use std::io::{self, BufReader, Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};

use anyhow::{bail, Context, Result};
use reqwest::blocking::Client;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::encoding::{
    encode_item_into, pir_row_count, ITEM_BYTES, NULLIFIERS_PER_ITEM, NULLIFIER_BYTES,
    SIMPLEPIR_COEFFS_PER_ITEM,
};

pub const DEFAULT_SNAPSHOT_URL: &str =
    "https://vote.fra1.cdn.digitaloceanspaces.com/snapshots/3317500/nullifiers.bin";

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SnapshotMetadata {
    pub source_url: Option<String>,
    pub path: PathBuf,
    pub bytes: u64,
    pub record_count: usize,
    pub pir_row_count: usize,
    pub nullifier_bytes: usize,
    pub nullifiers_per_item: usize,
    pub sha256: String,
    pub etag: Option<String>,
}

#[derive(Debug, Clone)]
pub struct NullifierSnapshot {
    path: PathBuf,
    bytes: u64,
    record_count: usize,
}

impl NullifierSnapshot {
    pub fn open(path: impl AsRef<Path>) -> Result<Self> {
        let path = path.as_ref().to_path_buf();
        let bytes = fs::metadata(&path)
            .with_context(|| format!("stat snapshot {}", path.display()))?
            .len();
        validate_snapshot_len(bytes)?;
        Ok(Self {
            path,
            bytes,
            record_count: (bytes / NULLIFIER_BYTES as u64) as usize,
        })
    }

    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }

    #[must_use]
    pub fn bytes(&self) -> u64 {
        self.bytes
    }

    #[must_use]
    pub fn record_count(&self) -> usize {
        self.record_count
    }

    #[must_use]
    pub fn pir_row_count(&self) -> usize {
        pir_row_count(self.record_count)
    }

    pub fn metadata(&self, source_url: Option<String>, sha256: String) -> SnapshotMetadata {
        SnapshotMetadata {
            source_url,
            path: self.path.clone(),
            bytes: self.bytes,
            record_count: self.record_count,
            pir_row_count: self.pir_row_count(),
            nullifier_bytes: NULLIFIER_BYTES,
            nullifiers_per_item: NULLIFIERS_PER_ITEM,
            sha256,
            etag: None,
        }
    }

    pub fn read_nullifier(&self, index: usize) -> Result<[u8; NULLIFIER_BYTES]> {
        if index >= self.record_count {
            bail!(
                "nullifier index {index} is out of bounds for {} records",
                self.record_count
            );
        }

        let mut file =
            File::open(&self.path).with_context(|| format!("open {}", self.path.display()))?;
        file.seek(SeekFrom::Start((index * NULLIFIER_BYTES) as u64))?;
        let mut out = [0u8; NULLIFIER_BYTES];
        file.read_exact(&mut out)?;
        Ok(out)
    }

    pub fn find_nullifier(&self, needle: &[u8; NULLIFIER_BYTES]) -> Result<Option<usize>> {
        let mut reader = BufReader::new(
            File::open(&self.path).with_context(|| format!("open {}", self.path.display()))?,
        );
        let mut current = [0u8; NULLIFIER_BYTES];
        for index in 0..self.record_count {
            reader.read_exact(&mut current)?;
            if &current == needle {
                return Ok(Some(index));
            }
        }
        Ok(None)
    }

    pub fn coeff_iter(&self, db_rows: usize) -> Result<SnapshotCoeffIter> {
        let file =
            File::open(&self.path).with_context(|| format!("open {}", self.path.display()))?;
        Ok(SnapshotCoeffIter {
            reader: BufReader::new(file),
            record_count: self.record_count,
            actual_rows: self.pir_row_count(),
            db_rows,
            current_row: 0,
            item: vec![0u8; ITEM_BYTES],
            coeffs: [0u16; SIMPLEPIR_COEFFS_PER_ITEM],
            coeff_idx: SIMPLEPIR_COEFFS_PER_ITEM,
        })
    }
}

pub struct SnapshotCoeffIter {
    reader: BufReader<File>,
    record_count: usize,
    actual_rows: usize,
    db_rows: usize,
    current_row: usize,
    /// Reusable read buffer, so a row does not allocate.
    item: Vec<u8>,
    coeffs: [u16; SIMPLEPIR_COEFFS_PER_ITEM],
    coeff_idx: usize,
}

impl SnapshotCoeffIter {
    /// Refill `coeffs` from the next row.
    ///
    /// `#[inline(never)]` is load-bearing, not cosmetic. This runs once every
    /// `SIMPLEPIR_COEFFS_PER_ITEM` calls to `next`, but it owns the only large
    /// stack frame in the iterator. Inlined into `next` it made every element
    /// pay that frame's setup and stack probing: 147.6 ns per element against
    /// 5.7 ns, which was 140 s of a 202 s cold start on the production
    /// snapshot. `encode_item_into` removes most of the frame; keeping the
    /// split makes the hot path independent of that.
    #[inline(never)]
    fn load_next_row(&mut self) -> io::Result<bool> {
        if self.current_row >= self.db_rows {
            return Ok(false);
        }

        if self.current_row < self.actual_rows {
            let remaining_records = self.record_count - self.current_row * NULLIFIERS_PER_ITEM;
            let records_in_row = remaining_records.min(NULLIFIERS_PER_ITEM);
            let bytes_in_row = records_in_row * NULLIFIER_BYTES;
            self.reader.read_exact(&mut self.item[..bytes_in_row])?;
            // Slice to exactly the bytes read: a short final row must not pick
            // up the previous row's trailing bytes, and the encoder treats
            // anything past the slice as zero.
            encode_item_into(&self.item[..bytes_in_row], &mut self.coeffs);
        } else {
            self.coeffs = [0u16; SIMPLEPIR_COEFFS_PER_ITEM];
        }

        self.current_row += 1;
        self.coeff_idx = 0;
        Ok(true)
    }
}

impl Iterator for SnapshotCoeffIter {
    type Item = u16;

    fn next(&mut self) -> Option<Self::Item> {
        if self.coeff_idx == SIMPLEPIR_COEFFS_PER_ITEM
            && !self.load_next_row().expect("read next snapshot row")
        {
            return None;
        }

        let value = self.coeffs[self.coeff_idx];
        self.coeff_idx += 1;
        Some(value)
    }
}

pub fn validate_snapshot_len(bytes: u64) -> Result<()> {
    if bytes == 0 {
        bail!("snapshot is empty");
    }
    if bytes % NULLIFIER_BYTES as u64 != 0 {
        bail!("snapshot length {bytes} is not divisible by {NULLIFIER_BYTES}-byte nullifiers");
    }
    Ok(())
}

pub fn download_snapshot(url: &str, output: impl AsRef<Path>) -> Result<SnapshotMetadata> {
    let output = output.as_ref();
    if let Some(parent) = output.parent() {
        fs::create_dir_all(parent)
            .with_context(|| format!("create output directory {}", parent.display()))?;
    }

    let client = Client::new();
    let mut response = client
        .get(url)
        .send()
        .with_context(|| format!("download {url}"))?
        .error_for_status()
        .with_context(|| format!("download {url}"))?;

    let etag = response
        .headers()
        .get(reqwest::header::ETAG)
        .and_then(|value| value.to_str().ok())
        .map(ToOwned::to_owned);
    if let Some(len) = response.content_length() {
        validate_snapshot_len(len)?;
    }

    let tmp_path = output.with_extension("part");
    let mut tmp = File::create(&tmp_path)
        .with_context(|| format!("create temporary file {}", tmp_path.display()))?;
    let mut hasher = Sha256::new();
    let mut bytes = 0u64;
    let mut buffer = [0u8; 1024 * 1024];

    loop {
        let read = response.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        tmp.write_all(&buffer[..read])?;
        hasher.update(&buffer[..read]);
        bytes += read as u64;
    }
    tmp.flush()?;
    validate_snapshot_len(bytes)?;
    fs::rename(&tmp_path, output)
        .with_context(|| format!("move {} to {}", tmp_path.display(), output.display()))?;

    let snapshot = NullifierSnapshot::open(output)?;
    let mut metadata = snapshot.metadata(Some(url.to_string()), format!("{:x}", hasher.finalize()));
    metadata.etag = etag;
    write_metadata(output, &metadata)?;
    Ok(metadata)
}

pub fn sha256_file(path: impl AsRef<Path>) -> Result<String> {
    let path = path.as_ref();
    let mut file = File::open(path).with_context(|| format!("open {}", path.display()))?;
    let mut hasher = Sha256::new();
    let mut buffer = [0u8; 1024 * 1024];
    loop {
        let read = file.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        hasher.update(&buffer[..read]);
    }
    Ok(format!("{:x}", hasher.finalize()))
}

pub fn write_metadata(snapshot_path: &Path, metadata: &SnapshotMetadata) -> Result<()> {
    let metadata_path = metadata_path(snapshot_path);
    let file = File::create(&metadata_path)
        .with_context(|| format!("create metadata {}", metadata_path.display()))?;
    serde_json::to_writer_pretty(file, metadata)?;
    Ok(())
}

#[must_use]
pub fn metadata_path(snapshot_path: &Path) -> PathBuf {
    snapshot_path.with_extension("json")
}

#[cfg(test)]
mod tests {
    use std::io::Write;

    use tempfile::NamedTempFile;

    use super::*;
    use crate::encoding::{decode_item_coefficients, extract_nullifier};

    #[test]
    fn validates_fixed_width_snapshot_length() {
        assert!(validate_snapshot_len(32).is_ok());
        assert!(validate_snapshot_len(64).is_ok());
        assert!(validate_snapshot_len(31).is_err());
        assert!(validate_snapshot_len(0).is_err());
    }

    /// A short final row that *follows* a full row is the production case: the
    /// deployed snapshot's last row holds 733 of 1,792 records. The iterator
    /// reuses one read buffer across rows, so the bytes past the short read are
    /// the previous row's. Only slicing the buffer to the bytes actually read
    /// keeps them out; reading the whole buffer would silently emit the
    /// previous row's nullifiers as the tail of the last row.
    #[test]
    fn short_final_row_after_a_full_row_is_zero_padded() {
        let mut file = NamedTempFile::new().expect("temp file");
        // A full row of distinct, non-zero records...
        for idx in 0..NULLIFIERS_PER_ITEM {
            let mut record = [0u8; NULLIFIER_BYTES];
            record[0] = 0xAA;
            record[1..3].copy_from_slice(&(idx as u16).to_le_bytes());
            file.write_all(&record).expect("write full row");
        }
        // ...then a short row with just three.
        let tail: Vec<[u8; NULLIFIER_BYTES]> = (0..3)
            .map(|i| {
                let mut r = [0u8; NULLIFIER_BYTES];
                r[0] = 0x11 + i as u8;
                r
            })
            .collect();
        for record in &tail {
            file.write_all(record).expect("write tail");
        }
        file.flush().expect("flush");

        let snapshot = NullifierSnapshot::open(file.path()).expect("open snapshot");
        assert_eq!(snapshot.record_count(), NULLIFIERS_PER_ITEM + 3);
        assert_eq!(snapshot.pir_row_count(), 2);

        let coeffs: Vec<u64> = snapshot
            .coeff_iter(2)
            .expect("iterator")
            .map(u64::from)
            .collect();
        let last_row = decode_item_coefficients(&coeffs[SIMPLEPIR_COEFFS_PER_ITEM..]);

        for (offset, expected) in tail.iter().enumerate() {
            assert_eq!(
                extract_nullifier(&last_row, offset),
                Some(*expected),
                "record {offset} of the short row"
            );
        }
        // Everything past the three real records must be zero, not the
        // preceding row's 0xAA-tagged data.
        assert!(
            last_row[tail.len() * NULLIFIER_BYTES..]
                .iter()
                .all(|byte| *byte == 0),
            "short final row leaked bytes from the previous row"
        );
    }

    #[test]
    fn coeff_iterator_pads_partial_and_extra_rows() {
        let mut file = NamedTempFile::new().expect("temp file");
        let first = [1u8; NULLIFIER_BYTES];
        let second = [2u8; NULLIFIER_BYTES];
        file.write_all(&first).expect("write first");
        file.write_all(&second).expect("write second");

        let snapshot = NullifierSnapshot::open(file.path()).expect("open snapshot");
        let coeffs: Vec<_> = snapshot
            .coeff_iter(2)
            .expect("iterator")
            .map(u64::from)
            .collect();
        assert_eq!(coeffs.len(), 2 * SIMPLEPIR_COEFFS_PER_ITEM);

        let item = decode_item_coefficients(&coeffs[..SIMPLEPIR_COEFFS_PER_ITEM]);
        assert_eq!(extract_nullifier(&item, 0), Some(first));
        assert_eq!(extract_nullifier(&item, 1), Some(second));

        let padded = decode_item_coefficients(&coeffs[SIMPLEPIR_COEFFS_PER_ITEM..]);
        assert!(padded.iter().all(|byte| *byte == 0));
    }

    #[test]
    fn find_nullifier_returns_global_index() {
        let mut file = NamedTempFile::new().expect("temp file");
        file.write_all(&[1u8; NULLIFIER_BYTES])
            .expect("write first");
        file.write_all(&[2u8; NULLIFIER_BYTES])
            .expect("write second");

        let snapshot = NullifierSnapshot::open(file.path()).expect("open snapshot");
        assert_eq!(
            snapshot
                .find_nullifier(&[2u8; NULLIFIER_BYTES])
                .expect("find"),
            Some(1)
        );
        assert_eq!(
            snapshot
                .find_nullifier(&[3u8; NULLIFIER_BYTES])
                .expect("find"),
            None
        );
    }
}
