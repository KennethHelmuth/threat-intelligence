rule win_gcleaner_20261111
{
    meta:
        description = "Auto-generated stub for win.gcleaner based on 1 hashes"
        author      = "ti-pipeline (auto-generated)"
        date        = "2026-11-11"
        version     = "1.0"
        source      = "ThreatFox"
        family      = "win.gcleaner"
        hash_count  = "1"

    strings:
        // Hashes (SHA-256) – reference only; add byte-strings/imphash conditions below
        // 17033faffac3c967a6bd8ef494191a293a3782dbf730a040c4da52f66825d2b0

    condition:
        // TODO: replace with byte-level strings, pe.imphash(), or hash.sha256() checks
        // Example: pe.imphash() == "aabbccdd..."
        false  // stub – analyst must complete this rule
}
