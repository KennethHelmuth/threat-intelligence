rule win_salatstealer_20260630
{
    meta:
        description = "Auto-generated stub for win.salatstealer based on 4 hashes"
        author      = "ti-pipeline (auto-generated)"
        date        = "2026-06-30"
        version     = "1.0"
        source      = "ThreatFox"
        family      = "win.salatstealer"
        hash_count  = "4"

    strings:
        // Hashes (SHA-256) – reference only; add byte-strings/imphash conditions below
        // f59b521321526c8e255c6e5a9ed71d063349cab55a4a0b7207c6aa0039fb32be
        // 5563f909b93845410a8014ddffa5adf6
        // 9977df7ffd04173d38e0aefe3d028052e164aaa69c1facfe63af55b473dd9e24
        // 7f79817eb5e3579ce8957a42c31c65fa

    condition:
        // TODO: replace with byte-level strings, pe.imphash(), or hash.sha256() checks
        // Example: pe.imphash() == "aabbccdd..."
        false  // stub – analyst must complete this rule
}
