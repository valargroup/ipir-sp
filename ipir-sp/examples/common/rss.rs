//! Process memory checkpoints for benchmark examples. Values are bytes.
//! Linux reads /proc/self/status (VmRSS, VmHWM) and can reset the peak via
//! /proc/self/clear_refs; other Unix hosts report the getrusage peak only.
#![allow(dead_code)]

/// Current resident set size and peak since start (or since the last reset).
#[derive(Clone, Copy, Debug, Default)]
pub struct Sample {
    pub rss: Option<u64>,
    pub peak: Option<u64>,
}
impl Sample {
    pub fn json(self) -> serde_json::Value {
        serde_json::json!({"rss": self.rss, "peak": self.peak})
    }
}

pub fn sample() -> Sample {
    #[cfg(target_os = "linux")]
    {
        let status = std::fs::read_to_string("/proc/self/status").unwrap_or_default();
        let field = |name: &str| {
            status
                .lines()
                .find(|l| l.starts_with(name))
                .and_then(|l| l.split_whitespace().nth(1))
                .and_then(|kib| kib.parse::<u64>().ok())
                .map(|kib| kib * 1024)
        };
        Sample {
            rss: field("VmRSS:"),
            peak: field("VmHWM:"),
        }
    }
    #[cfg(not(target_os = "linux"))]
    {
        // SAFETY: getrusage writes into the provided struct.
        let mut usage: libc::rusage = unsafe { std::mem::zeroed() };
        let ok = unsafe { libc::getrusage(libc::RUSAGE_SELF, &mut usage) } == 0;
        // macOS reports ru_maxrss in bytes; other BSDs use KiB.
        let scale = if cfg!(target_os = "macos") { 1 } else { 1024 };
        Sample {
            rss: None,
            peak: ok.then(|| usage.ru_maxrss as u64 * scale),
        }
    }
}

/// Reset the peak (VmHWM) to the current RSS. Returns whether it worked.
pub fn reset_peak() -> bool {
    #[cfg(target_os = "linux")]
    {
        std::fs::write("/proc/self/clear_refs", "5").is_ok()
    }
    #[cfg(not(target_os = "linux"))]
    {
        false
    }
}

/// Return freed heap pages to the OS where the allocator supports it (glibc).
pub fn trim() -> bool {
    #[cfg(all(target_os = "linux", target_env = "gnu"))]
    {
        // SAFETY: malloc_trim has no preconditions.
        unsafe { libc::malloc_trim(0) != 0 }
    }
    #[cfg(not(all(target_os = "linux", target_env = "gnu")))]
    {
        false
    }
}
