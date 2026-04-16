/// Built-in correlation rules covering cross-domain attack chains.
///
/// Rules are defined as `once_cell::sync::Lazy` statics and collected into
/// the `BUILTIN_RULES` slice used by `RuleRegistry::from_builtin()`.
use once_cell::sync::Lazy;

use crate::schema::{MitreFramework, MitreMapping, Severity, SourceDomain};

use super::{EventCondition, Rule};

// ─────────────────────────────────────────────────────────────
//  Helper constructors
// ─────────────────────────────────────────────────────────────

fn mitre(framework: MitreFramework, id: &str, technique: &str, tactic: &str, confidence: f32) -> MitreMapping {
    MitreMapping {
        framework,
        technique_id: id.to_string(),
        technique:    technique.to_string(),
        tactic:       tactic.to_string(),
        confidence,
    }
}

fn cond() -> EventCondition {
    EventCondition {
        source_domain:   None,
        source_type:     None,
        mitre_technique: None,
        min_severity:    None,
        action:          None,
        src_ip:          None,
        dst_ip:          None,
        user:            None,
        tag:             None,
        within_seconds:  None,
    }
}

// ─────────────────────────────────────────────────────────────
//  Rule 1 — IT/OT lateral movement
// ─────────────────────────────────────────────────────────────

static IT_OT_LATERAL_MOVEMENT: Lazy<Rule> = Lazy::new(|| Rule {
    name:        "it_ot_lateral_movement".to_string(),
    version:     "1.0.0".to_string(),
    description: "IT credential abuse (T1078) followed by OT command (T1565) within 5 minutes — \
                  indicates an adversary pivoting from the corporate network into the OT environment."
        .to_string(),
    severity:    Severity::Critical,
    window_secs: 300,
    conditions:  vec![
        EventCondition {
            source_domain:   Some(SourceDomain::It),
            mitre_technique: Some("T1078".to_string()),
            ..cond()
        },
        EventCondition {
            source_domain:   Some(SourceDomain::Ot),
            mitre_technique: Some("T1565".to_string()),
            within_seconds:  Some(300),
            ..cond()
        },
    ],
    min_match:          0,
    unique_ips:         false,
    unique_users:       false,
    tags:               vec!["lateral-movement".to_string(), "it-ot-pivot".to_string()],
    mitre_mappings:     vec![
        mitre(MitreFramework::Enterprise, "T1078", "Valid Accounts", "defense-evasion", 0.9),
        mitre(MitreFramework::Ics, "T1565", "Manipulate I/O Image", "inhibit-response-function", 0.85),
    ],
    alert:              true,
    threat_score_delta: 30.0,
});

// ─────────────────────────────────────────────────────────────
//  Rule 2 — Cloud-to-OT pivot
// ─────────────────────────────────────────────────────────────

static CLOUD_TO_OT_PIVOT: Lazy<Rule> = Lazy::new(|| Rule {
    name:        "cloud_to_ot_pivot".to_string(),
    version:     "1.0.0".to_string(),
    description: "Cloud IAM compromise (T1548) followed by OT network connection within 10 minutes."
        .to_string(),
    severity:    Severity::Critical,
    window_secs: 600,
    conditions:  vec![
        EventCondition {
            source_domain:   Some(SourceDomain::Cloud),
            mitre_technique: Some("T1548".to_string()),
            ..cond()
        },
        EventCondition {
            source_domain:   Some(SourceDomain::Ot),
            within_seconds:  Some(600),
            ..cond()
        },
    ],
    min_match:          0,
    unique_ips:         false,
    unique_users:       false,
    tags:               vec!["cloud-pivot".to_string(), "it-ot-pivot".to_string()],
    mitre_mappings:     vec![
        mitre(MitreFramework::Enterprise, "T1548", "Abuse Elevation Control Mechanism", "privilege-escalation", 0.88),
    ],
    alert:              true,
    threat_score_delta: 35.0,
});

// ─────────────────────────────────────────────────────────────
//  Rule 3 — Brute-force then login
// ─────────────────────────────────────────────────────────────

static BRUTE_FORCE_THEN_LOGIN: Lazy<Rule> = Lazy::new(|| Rule {
    name:        "brute_force_then_login".to_string(),
    version:     "1.0.0".to_string(),
    description: "Three or more authentication failures (T1110) followed by a successful login \
                  (T1078) from the same IP within 5 minutes."
        .to_string(),
    severity:    Severity::High,
    window_secs: 300,
    conditions:  vec![
        EventCondition {
            mitre_technique: Some("T1110".to_string()),
            min_severity:    Some(Severity::Low),
            ..cond()
        },
        EventCondition {
            mitre_technique: Some("T1110".to_string()),
            ..cond()
        },
        EventCondition {
            mitre_technique: Some("T1110".to_string()),
            ..cond()
        },
        EventCondition {
            mitre_technique: Some("T1078".to_string()),
            within_seconds:  Some(300),
            ..cond()
        },
    ],
    min_match:          0,
    unique_ips:         false,
    unique_users:       false,
    tags:               vec!["brute-force".to_string(), "credential-access".to_string()],
    mitre_mappings:     vec![
        mitre(MitreFramework::Enterprise, "T1110", "Brute Force", "credential-access", 0.92),
        mitre(MitreFramework::Enterprise, "T1078", "Valid Accounts", "defense-evasion", 0.85),
    ],
    alert:              true,
    threat_score_delta: 20.0,
});

// ─────────────────────────────────────────────────────────────
//  Rule 4 — Kerberoasting sequence
// ─────────────────────────────────────────────────────────────

static KERBEROASTING_SEQUENCE: Lazy<Rule> = Lazy::new(|| Rule {
    name:        "kerberoasting_sequence".to_string(),
    version:     "1.0.0".to_string(),
    description: "AS-REP roasting (T1558.003) followed by Pass-the-Hash (T1550.002) within 15 minutes."
        .to_string(),
    severity:    Severity::Critical,
    window_secs: 900,
    conditions:  vec![
        EventCondition {
            mitre_technique: Some("T1558".to_string()),
            ..cond()
        },
        EventCondition {
            mitre_technique: Some("T1550".to_string()),
            within_seconds:  Some(900),
            ..cond()
        },
    ],
    min_match:          0,
    unique_ips:         false,
    unique_users:       false,
    tags:               vec!["kerberoasting".to_string(), "credential-access".to_string()],
    mitre_mappings:     vec![
        mitre(MitreFramework::Enterprise, "T1558.003", "Steal or Forge Kerberos Tickets: AS-REP Roasting", "credential-access", 0.93),
        mitre(MitreFramework::Enterprise, "T1550.002", "Use Alternate Authentication Material: Pass the Hash", "lateral-movement", 0.90),
    ],
    alert:              true,
    threat_score_delta: 35.0,
});

// ─────────────────────────────────────────────────────────────
//  Rule 5 — Ransomware precursor
// ─────────────────────────────────────────────────────────────

static RANSOMWARE_PRECURSOR: Lazy<Rule> = Lazy::new(|| Rule {
    name:        "ransomware_precursor".to_string(),
    version:     "1.0.0".to_string(),
    description: "Scripting engine process creation (T1059) followed by file access and lateral \
                  movement activity within 10 minutes — ransomware staging pattern."
        .to_string(),
    severity:    Severity::Critical,
    window_secs: 600,
    conditions:  vec![
        EventCondition {
            mitre_technique: Some("T1059".to_string()),
            ..cond()
        },
        EventCondition {
            action:         Some("file_access".to_string()),
            within_seconds: Some(600),
            ..cond()
        },
        EventCondition {
            tag:            Some("lateral-movement".to_string()),
            within_seconds: Some(600),
            ..cond()
        },
    ],
    min_match:          0,
    unique_ips:         false,
    unique_users:       false,
    tags:               vec!["ransomware".to_string(), "precursor".to_string()],
    mitre_mappings:     vec![
        mitre(MitreFramework::Enterprise, "T1059", "Command and Scripting Interpreter", "execution", 0.88),
    ],
    alert:              true,
    threat_score_delta: 40.0,
});

// ─────────────────────────────────────────────────────────────
//  Rule 6 — DCSync attack
// ─────────────────────────────────────────────────────────────

static DCSYNC_ATTACK: Lazy<Rule> = Lazy::new(|| Rule {
    name:        "dcsync_attack".to_string(),
    version:     "1.0.0".to_string(),
    description: "DCSync credential dump (T1003.006) detected — high-confidence single-event alert."
        .to_string(),
    severity:    Severity::Critical,
    window_secs: 60,
    conditions:  vec![
        EventCondition {
            mitre_technique: Some("T1003".to_string()),
            min_severity:    Some(Severity::High),
            ..cond()
        },
    ],
    min_match:          0,
    unique_ips:         false,
    unique_users:       false,
    tags:               vec!["dcsync".to_string(), "credential-dump".to_string()],
    mitre_mappings:     vec![
        mitre(MitreFramework::Enterprise, "T1003.006", "OS Credential Dumping: DCSync", "credential-access", 0.97),
    ],
    alert:              true,
    threat_score_delta: 45.0,
});

// ─────────────────────────────────────────────────────────────
//  Rule 7 — Scheduled task persistence
// ─────────────────────────────────────────────────────────────

static SCHEDULED_TASK_PERSISTENCE: Lazy<Rule> = Lazy::new(|| Rule {
    name:        "scheduled_task_persistence".to_string(),
    version:     "1.0.0".to_string(),
    description: "Scheduled task creation (T1053.005) followed by suspicious command execution \
                  (T1059) within 5 minutes — persistence mechanism."
        .to_string(),
    severity:    Severity::High,
    window_secs: 300,
    conditions:  vec![
        EventCondition {
            mitre_technique: Some("T1053".to_string()),
            ..cond()
        },
        EventCondition {
            mitre_technique: Some("T1059".to_string()),
            within_seconds:  Some(300),
            ..cond()
        },
    ],
    min_match:          0,
    unique_ips:         false,
    unique_users:       false,
    tags:               vec!["persistence".to_string(), "scheduled-task".to_string()],
    mitre_mappings:     vec![
        mitre(MitreFramework::Enterprise, "T1053.005", "Scheduled Task/Job: Scheduled Task", "persistence", 0.90),
        mitre(MitreFramework::Enterprise, "T1059", "Command and Scripting Interpreter", "execution", 0.85),
    ],
    alert:              true,
    threat_score_delta: 20.0,
});

// ─────────────────────────────────────────────────────────────
//  Rule 8 — Cloud exfil sequence
// ─────────────────────────────────────────────────────────────

static CLOUD_EXFIL_SEQUENCE: Lazy<Rule> = Lazy::new(|| Rule {
    name:        "cloud_exfil_sequence".to_string(),
    version:     "1.0.0".to_string(),
    description: "S3 data access / cloud storage read (T1530) followed by a large DNS query \
                  within 5 minutes — potential data exfiltration via DNS tunneling."
        .to_string(),
    severity:    Severity::High,
    window_secs: 300,
    conditions:  vec![
        EventCondition {
            source_domain:   Some(SourceDomain::Cloud),
            mitre_technique: Some("T1530".to_string()),
            ..cond()
        },
        EventCondition {
            tag:             Some("large-dns-query".to_string()),
            within_seconds:  Some(300),
            ..cond()
        },
    ],
    min_match:          0,
    unique_ips:         false,
    unique_users:       false,
    tags:               vec!["exfiltration".to_string(), "dns-tunneling".to_string()],
    mitre_mappings:     vec![
        mitre(MitreFramework::Enterprise, "T1530", "Data from Cloud Storage", "collection", 0.87),
        mitre(MitreFramework::Enterprise, "T1048", "Exfiltration Over Alternative Protocol", "exfiltration", 0.80),
    ],
    alert:              true,
    threat_score_delta: 25.0,
});

// ─────────────────────────────────────────────────────────────
//  Rule 9 — K8s privilege escalation
// ─────────────────────────────────────────────────────────────

static K8S_PRIVILEGE_ESCALATION: Lazy<Rule> = Lazy::new(|| Rule {
    name:        "k8s_privilege_escalation".to_string(),
    version:     "1.0.0".to_string(),
    description: "Kubernetes cluster-admin binding creation within 1 minute of a suspicious \
                  exec or interactive shell — privilege escalation in a K8s cluster."
        .to_string(),
    severity:    Severity::High,
    window_secs: 120,
    conditions:  vec![
        EventCondition {
            source_domain:   Some(SourceDomain::Cloud),
            tag:             Some("k8s-exec".to_string()),
            ..cond()
        },
        EventCondition {
            source_domain:   Some(SourceDomain::Cloud),
            tag:             Some("k8s-clusterrolebinding".to_string()),
            within_seconds:  Some(60),
            ..cond()
        },
    ],
    min_match:          0,
    unique_ips:         false,
    unique_users:       false,
    tags:               vec!["kubernetes".to_string(), "privilege-escalation".to_string()],
    mitre_mappings:     vec![
        mitre(MitreFramework::Enterprise, "T1611", "Escape to Host", "privilege-escalation", 0.85),
    ],
    alert:              true,
    threat_score_delta: 25.0,
});

// ─────────────────────────────────────────────────────────────
//  Rule 10 — OT write anomaly from IT subnet
// ─────────────────────────────────────────────────────────────

static OT_WRITE_ANOMALY: Lazy<Rule> = Lazy::new(|| Rule {
    name:        "ot_write_anomaly".to_string(),
    version:     "1.0.0".to_string(),
    description: "OT write command (function_code indicating write) originating from an IT \
                  subnet — unexpected cross-zone write into industrial control system."
        .to_string(),
    severity:    Severity::Critical,
    window_secs: 60,
    conditions:  vec![
        EventCondition {
            source_domain:   Some(SourceDomain::Ot),
            action:          Some("ot_write".to_string()),
            ..cond()
        },
    ],
    min_match:          0,
    unique_ips:         false,
    unique_users:       false,
    tags:               vec!["ot-write".to_string(), "ics-attack".to_string()],
    mitre_mappings:     vec![
        mitre(MitreFramework::Ics, "T0836", "Modify Parameter", "impair-process-control", 0.93),
    ],
    alert:              true,
    threat_score_delta: 40.0,
});

// ─────────────────────────────────────────────────────────────
//  Rule 11 — PowerShell download and execute
// ─────────────────────────────────────────────────────────────

static POWERSHELL_DOWNLOAD_EXEC: Lazy<Rule> = Lazy::new(|| Rule {
    name:        "powershell_download_exec".to_string(),
    version:     "1.0.0".to_string(),
    description: "PowerShell (T1059.001) command containing a download indicator \
                  (Invoke-WebRequest, DownloadString, etc.) — dropper or stage-2 retrieval."
        .to_string(),
    severity:    Severity::High,
    window_secs: 60,
    conditions:  vec![
        EventCondition {
            mitre_technique: Some("T1059".to_string()),
            tag:             Some("powershell-download".to_string()),
            ..cond()
        },
    ],
    min_match:          0,
    unique_ips:         false,
    unique_users:       false,
    tags:               vec!["powershell".to_string(), "download-exec".to_string()],
    mitre_mappings:     vec![
        mitre(MitreFramework::Enterprise, "T1059.001", "Command and Scripting Interpreter: PowerShell", "execution", 0.92),
    ],
    alert:              true,
    threat_score_delta: 22.0,
});

// ─────────────────────────────────────────────────────────────
//  Rule 12 — Service install persistence
// ─────────────────────────────────────────────────────────────

static SERVICE_INSTALL_PERSISTENCE: Lazy<Rule> = Lazy::new(|| Rule {
    name:        "service_install_persistence".to_string(),
    version:     "1.0.0".to_string(),
    description: "Windows service installation (T1543.003) followed by process creation within \
                  2 minutes — malicious service being started immediately after install."
        .to_string(),
    severity:    Severity::High,
    window_secs: 180,
    conditions:  vec![
        EventCondition {
            mitre_technique: Some("T1543".to_string()),
            ..cond()
        },
        EventCondition {
            action:          Some("process_creation".to_string()),
            within_seconds:  Some(120),
            ..cond()
        },
    ],
    min_match:          0,
    unique_ips:         false,
    unique_users:       false,
    tags:               vec!["persistence".to_string(), "service-install".to_string()],
    mitre_mappings:     vec![
        mitre(MitreFramework::Enterprise, "T1543.003", "Create or Modify System Process: Windows Service", "persistence", 0.90),
    ],
    alert:              true,
    threat_score_delta: 20.0,
});

// ─────────────────────────────────────────────────────────────
//  Rule 13 — Cloud console login anomaly
// ─────────────────────────────────────────────────────────────

static CLOUD_CONSOLE_LOGIN_ANOMALY: Lazy<Rule> = Lazy::new(|| Rule {
    name:        "cloud_console_login_anomaly".to_string(),
    version:     "1.0.0".to_string(),
    description: "Failed cloud console login followed by a successful login from a different \
                  country within 10 minutes — account takeover or credential stuffing."
        .to_string(),
    severity:    Severity::High,
    window_secs: 600,
    conditions:  vec![
        EventCondition {
            source_domain:   Some(SourceDomain::Cloud),
            action:          Some("console_login_failed".to_string()),
            ..cond()
        },
        EventCondition {
            source_domain:   Some(SourceDomain::Cloud),
            action:          Some("console_login_success".to_string()),
            within_seconds:  Some(600),
            ..cond()
        },
    ],
    min_match:          0,
    unique_ips:         true,
    unique_users:       false,
    tags:               vec!["cloud-login".to_string(), "credential-stuffing".to_string()],
    mitre_mappings:     vec![
        mitre(MitreFramework::Enterprise, "T1078.004", "Valid Accounts: Cloud Accounts", "defense-evasion", 0.88),
    ],
    alert:              true,
    threat_score_delta: 22.0,
});

// ─────────────────────────────────────────────────────────────
//  Rule 14 — Mimikatz detected
// ─────────────────────────────────────────────────────────────

static MIMIKATZ_DETECTED: Lazy<Rule> = Lazy::new(|| Rule {
    name:        "mimikatz_detected".to_string(),
    version:     "1.0.0".to_string(),
    description: "Tag \"mimikatz\" present or command line contains \"mimikatz\" keyword — \
                  well-known credential dumping tool."
        .to_string(),
    severity:    Severity::Critical,
    window_secs: 60,
    conditions:  vec![
        EventCondition {
            tag: Some("mimikatz".to_string()),
            ..cond()
        },
    ],
    min_match:          0,
    unique_ips:         false,
    unique_users:       false,
    tags:               vec!["mimikatz".to_string(), "credential-dump".to_string()],
    mitre_mappings:     vec![
        mitre(MitreFramework::Enterprise, "T1003", "OS Credential Dumping", "credential-access", 0.98),
    ],
    alert:              true,
    threat_score_delta: 50.0,
});

// ─────────────────────────────────────────────────────────────
//  Rule 15 — WMI lateral movement
// ─────────────────────────────────────────────────────────────

static WMI_LATERAL_MOVEMENT: Lazy<Rule> = Lazy::new(|| Rule {
    name:        "wmi_lateral_movement".to_string(),
    version:     "1.0.0".to_string(),
    description: "WMI remote execution events on multiple hosts within 5 minutes — \
                  automated lateral movement via WMI."
        .to_string(),
    severity:    Severity::High,
    window_secs: 300,
    conditions:  vec![
        EventCondition {
            tag:            Some("wmi-exec".to_string()),
            ..cond()
        },
        EventCondition {
            tag:            Some("wmi-exec".to_string()),
            within_seconds: Some(300),
            ..cond()
        },
    ],
    min_match:          0,
    unique_ips:         true,
    unique_users:       false,
    tags:               vec!["wmi".to_string(), "lateral-movement".to_string()],
    mitre_mappings:     vec![
        mitre(MitreFramework::Enterprise, "T1047", "Windows Management Instrumentation", "execution", 0.90),
    ],
    alert:              true,
    threat_score_delta: 20.0,
});

// ─────────────────────────────────────────────────────────────
//  Rule 16 — Pass-the-Hash chain
// ─────────────────────────────────────────────────────────────

static PASS_THE_HASH_CHAIN: Lazy<Rule> = Lazy::new(|| Rule {
    name:        "pass_the_hash_chain".to_string(),
    version:     "1.0.0".to_string(),
    description: "Pass-the-Hash (T1550.002) followed by a successful logon (T1078) within \
                  3 minutes — hash used immediately to authenticate."
        .to_string(),
    severity:    Severity::Critical,
    window_secs: 300,
    conditions:  vec![
        EventCondition {
            mitre_technique: Some("T1550".to_string()),
            ..cond()
        },
        EventCondition {
            mitre_technique: Some("T1078".to_string()),
            within_seconds:  Some(180),
            ..cond()
        },
    ],
    min_match:          0,
    unique_ips:         false,
    unique_users:       false,
    tags:               vec!["pass-the-hash".to_string(), "lateral-movement".to_string()],
    mitre_mappings:     vec![
        mitre(MitreFramework::Enterprise, "T1550.002", "Use Alternate Authentication Material: Pass the Hash", "lateral-movement", 0.93),
        mitre(MitreFramework::Enterprise, "T1078", "Valid Accounts", "defense-evasion", 0.88),
    ],
    alert:              true,
    threat_score_delta: 35.0,
});

// ─────────────────────────────────────────────────────────────
//  Rule 17 — ICS firmware update anomaly
// ─────────────────────────────────────────────────────────────

static ICS_FIRMWARE_UPDATE: Lazy<Rule> = Lazy::new(|| Rule {
    name:        "ics_firmware_update".to_string(),
    version:     "1.0.0".to_string(),
    description: "Firmware version change detected on an OT/ICS device — unexpected firmware \
                  modification may indicate supply-chain attack or device tampering."
        .to_string(),
    severity:    Severity::High,
    window_secs: 60,
    conditions:  vec![
        EventCondition {
            source_domain: Some(SourceDomain::Ot),
            tag:           Some("firmware-change".to_string()),
            ..cond()
        },
    ],
    min_match:          0,
    unique_ips:         false,
    unique_users:       false,
    tags:               vec!["ics".to_string(), "firmware".to_string(), "supply-chain".to_string()],
    mitre_mappings:     vec![
        mitre(MitreFramework::Ics, "T0857", "System Firmware", "persistence", 0.88),
    ],
    alert:              true,
    threat_score_delta: 30.0,
});

// ─────────────────────────────────────────────────────────────
//  Rule 18 — Cloud MFA bypass
// ─────────────────────────────────────────────────────────────

static CLOUD_MFA_BYPASS: Lazy<Rule> = Lazy::new(|| Rule {
    name:        "cloud_mfa_bypass".to_string(),
    version:     "1.0.0".to_string(),
    description: "Cloud console login without MFA from a new or unusual IP address — \
                  potential MFA bypass or credential compromise."
        .to_string(),
    severity:    Severity::High,
    window_secs: 60,
    conditions:  vec![
        EventCondition {
            source_domain: Some(SourceDomain::Cloud),
            tag:           Some("no-mfa".to_string()),
            action:        Some("console_login_success".to_string()),
            ..cond()
        },
    ],
    min_match:          0,
    unique_ips:         false,
    unique_users:       false,
    tags:               vec!["mfa-bypass".to_string(), "cloud-login".to_string()],
    mitre_mappings:     vec![
        mitre(MitreFramework::Enterprise, "T1556", "Modify Authentication Process", "credential-access", 0.85),
    ],
    alert:              true,
    threat_score_delta: 22.0,
});

// ─────────────────────────────────────────────────────────────
//  Rule 19 — Registry run-key persistence
// ─────────────────────────────────────────────────────────────

static REGISTRY_RUN_PERSISTENCE: Lazy<Rule> = Lazy::new(|| Rule {
    name:        "registry_run_persistence".to_string(),
    version:     "1.0.0".to_string(),
    description: "Registry Run key modification (T1547) followed by process creation within \
                  2 minutes — persistence via auto-run registry entry."
        .to_string(),
    severity:    Severity::Medium,
    window_secs: 180,
    conditions:  vec![
        EventCondition {
            mitre_technique: Some("T1547".to_string()),
            ..cond()
        },
        EventCondition {
            action:          Some("process_creation".to_string()),
            within_seconds:  Some(120),
            ..cond()
        },
    ],
    min_match:          0,
    unique_ips:         false,
    unique_users:       false,
    tags:               vec!["persistence".to_string(), "registry".to_string()],
    mitre_mappings:     vec![
        mitre(MitreFramework::Enterprise, "T1547.001", "Boot or Logon Autostart Execution: Registry Run Keys", "persistence", 0.87),
    ],
    alert:              true,
    threat_score_delta: 15.0,
});

// ─────────────────────────────────────────────────────────────
//  Rule 20 — Cross-tenant impersonation
// ─────────────────────────────────────────────────────────────

static CROSS_TENANT_IMPERSONATION: Lazy<Rule> = Lazy::new(|| Rule {
    name:        "cross_tenant_impersonation".to_string(),
    version:     "1.0.0".to_string(),
    description: "AssumeRole / cross-account access (T1548.005) from an unusual or unexpected \
                  IP address — potential cross-tenant or cross-account impersonation."
        .to_string(),
    severity:    Severity::High,
    window_secs: 60,
    conditions:  vec![
        EventCondition {
            source_domain:   Some(SourceDomain::Cloud),
            mitre_technique: Some("T1548".to_string()),
            tag:             Some("assume-role".to_string()),
            ..cond()
        },
    ],
    min_match:          0,
    unique_ips:         false,
    unique_users:       false,
    tags:               vec!["impersonation".to_string(), "cloud-iam".to_string()],
    mitre_mappings:     vec![
        mitre(MitreFramework::Enterprise, "T1548.005", "Abuse Elevation Control Mechanism: Temporary Elevated Cloud Access", "privilege-escalation", 0.88),
    ],
    alert:              true,
    threat_score_delta: 25.0,
});

// ─────────────────────────────────────────────────────────────
//  Rule 21 — K8s secret access
// ─────────────────────────────────────────────────────────────

static K8S_SECRET_ACCESS: Lazy<Rule> = Lazy::new(|| Rule {
    name:        "k8s_secret_access".to_string(),
    version:     "1.0.0".to_string(),
    description: "Kubernetes secrets/get API call from a non-service-account principal — \
                  unauthorized secret access in a K8s cluster."
        .to_string(),
    severity:    Severity::High,
    window_secs: 60,
    conditions:  vec![
        EventCondition {
            source_domain: Some(SourceDomain::Cloud),
            tag:           Some("k8s-secret-access".to_string()),
            ..cond()
        },
    ],
    min_match:          0,
    unique_ips:         false,
    unique_users:       false,
    tags:               vec!["kubernetes".to_string(), "secret-access".to_string()],
    mitre_mappings:     vec![
        mitre(MitreFramework::Enterprise, "T1552.007", "Unsecured Credentials: Container API", "credential-access", 0.90),
    ],
    alert:              true,
    threat_score_delta: 25.0,
});

// ─────────────────────────────────────────────────────────────
//  Rule 22 — OT scan detected
// ─────────────────────────────────────────────────────────────

static OT_SCAN_DETECTED: Lazy<Rule> = Lazy::new(|| Rule {
    name:        "ot_scan_detected".to_string(),
    version:     "1.0.0".to_string(),
    description: "Multiple Modbus read function codes targeting different unit_ids within 30 \
                  seconds — OT network reconnaissance / scanning."
        .to_string(),
    severity:    Severity::Medium,
    window_secs: 60,
    conditions:  vec![
        EventCondition {
            source_domain: Some(SourceDomain::Ot),
            action:        Some("modbus_read".to_string()),
            ..cond()
        },
        EventCondition {
            source_domain:  Some(SourceDomain::Ot),
            action:         Some("modbus_read".to_string()),
            within_seconds: Some(30),
            ..cond()
        },
        EventCondition {
            source_domain:  Some(SourceDomain::Ot),
            action:         Some("modbus_read".to_string()),
            within_seconds: Some(30),
            ..cond()
        },
    ],
    min_match:          0,
    unique_ips:         false,
    unique_users:       false,
    tags:               vec!["ot-scan".to_string(), "reconnaissance".to_string(), "modbus".to_string()],
    mitre_mappings:     vec![
        mitre(MitreFramework::Ics, "T0846", "Remote System Discovery", "discovery", 0.85),
    ],
    alert:              true,
    threat_score_delta: 12.0,
});

// ─────────────────────────────────────────────────────────────
//  BUILTIN_RULES slice
// ─────────────────────────────────────────────────────────────

/// All built-in correlation rules.  Each element is a reference to a
/// `Lazy<Rule>` static, so rules are initialized exactly once.
pub static BUILTIN_RULES: Lazy<Vec<Rule>> = Lazy::new(|| {
    vec![
        IT_OT_LATERAL_MOVEMENT.clone(),
        CLOUD_TO_OT_PIVOT.clone(),
        BRUTE_FORCE_THEN_LOGIN.clone(),
        KERBEROASTING_SEQUENCE.clone(),
        RANSOMWARE_PRECURSOR.clone(),
        DCSYNC_ATTACK.clone(),
        SCHEDULED_TASK_PERSISTENCE.clone(),
        CLOUD_EXFIL_SEQUENCE.clone(),
        K8S_PRIVILEGE_ESCALATION.clone(),
        OT_WRITE_ANOMALY.clone(),
        POWERSHELL_DOWNLOAD_EXEC.clone(),
        SERVICE_INSTALL_PERSISTENCE.clone(),
        CLOUD_CONSOLE_LOGIN_ANOMALY.clone(),
        MIMIKATZ_DETECTED.clone(),
        WMI_LATERAL_MOVEMENT.clone(),
        PASS_THE_HASH_CHAIN.clone(),
        ICS_FIRMWARE_UPDATE.clone(),
        CLOUD_MFA_BYPASS.clone(),
        REGISTRY_RUN_PERSISTENCE.clone(),
        CROSS_TENANT_IMPERSONATION.clone(),
        K8S_SECRET_ACCESS.clone(),
        OT_SCAN_DETECTED.clone(),
    ]
});
