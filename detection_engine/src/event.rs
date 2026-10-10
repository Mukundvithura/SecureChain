//! One normalized sensor event, as `sensors` writes it: a JSON object per line.
//!
//! The field set is the normalizer's (`sensors/sensors/src/normalize.rs`); see
//! `sensors/README.md` for what each means. Fields the normalizer could not
//! establish are absent from the record, hence the `Option`s.

use serde::Deserialize;

/// What the process did. The normalizer flattens the sensor kind and its
/// reason into this one field, so rules switch on it alone.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Action {
    Exec,
    Write,
    SecretRead,
    Connect,
}

/// One step of the parent chain the normalizer walked, nearest first.
#[derive(Debug, Clone, Deserialize)]
pub struct Ancestor {
    pub pid: u32,
    pub comm: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct Event {
    /// Epoch nanoseconds; monotonic across one capture.
    pub ts: u64,
    /// RFC 3339 local time, carried through into reports.
    #[serde(default)]
    pub time: String,
    pub action: Action,
    pub pid: u32,
    #[serde(default)]
    pub ppid: u32,
    pub uid: u32,
    #[serde(default)]
    pub comm: String,
    pub exe: Option<String>,
    pub cmdline: Option<String>,
    pub container: Option<String>,
    #[serde(default)]
    pub ancestry: Vec<Ancestor>,
    /// Exec: the binary. Write and secret_read: the resolved file.
    pub path: Option<String>,
    pub daddr: Option<String>,
    pub dport: Option<u16>,
}

impl Event {
    /// Whether a connect goes nowhere off-host. Exfiltration and payload
    /// download need a remote peer, so the network rules ignore these.
    pub fn is_loopback(&self) -> bool {
        self.daddr
            .as_deref()
            .is_some_and(|a| a.starts_with("127.") || a == "0.0.0.0")
    }
}
