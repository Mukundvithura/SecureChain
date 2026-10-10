//! ATT&CK tactics, in the order ATT&CK lists them. C3 reads that order as the
//! kill chain, so the derive order of [`Tactic`] is load-bearing.

use serde::Serialize;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
pub enum Tactic {
    #[serde(rename = "Initial Access")]
    InitialAccess,
    Execution,
    Persistence,
    #[serde(rename = "Privilege Escalation")]
    PrivilegeEscalation,
    #[serde(rename = "Defense Evasion")]
    DefenseEvasion,
    #[serde(rename = "Credential Access")]
    CredentialAccess,
    Collection,
    #[serde(rename = "Command and Control")]
    CommandAndControl,
    Exfiltration,
}

impl Tactic {
    pub fn name(self) -> &'static str {
        match self {
            Tactic::InitialAccess => "Initial Access",
            Tactic::Execution => "Execution",
            Tactic::Persistence => "Persistence",
            Tactic::PrivilegeEscalation => "Privilege Escalation",
            Tactic::DefenseEvasion => "Defense Evasion",
            Tactic::CredentialAccess => "Credential Access",
            Tactic::Collection => "Collection",
            Tactic::CommandAndControl => "Command and Control",
            Tactic::Exfiltration => "Exfiltration",
        }
    }
}
