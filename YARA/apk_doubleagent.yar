rule apk_doubleagent
{
    meta:
        description = "Auto-generated stub for apk.doubleagent based on 2 hashes"
        author      = "ti-pipeline (auto-generated)"
        date        = "2026-11-16"
        version     = "1.0"
        source      = "ThreatFox"
        family      = "apk.doubleagent"
        hash_count  = "2"

    strings:
        // Hashes (SHA-256) – reference only; add byte-strings/imphash conditions below
        // ab8d4dcf414df4d731e7254939180fa5
        // 9538d7a05b4c5ff1534f28bc144cc9fde2a710cdd33aa496383e0e131abbf314

    condition:
        // TODO: replace with byte-level strings, pe.imphash(), or hash.sha256() checks
        // Example: pe.imphash() == "aabbccdd..."
        false  // stub – analyst must complete this rule
}
