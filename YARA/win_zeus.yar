rule win_zeus
{
    meta:
        description = "Auto-generated stub for win.zeus based on 2 hashes"
        author      = "ti-pipeline (auto-generated)"
        date        = "2026-07-15"
        version     = "1.0"
        source      = "ThreatFox"
        family      = "win.zeus"
        hash_count  = "2"

    strings:
        // Hashes (SHA-256) – reference only; add byte-strings/imphash conditions below
        // 8c50b7a1ddc3e95f1106e7515fb36811c298257135b3b376c82bee04391e6cfa
        // 0a15d395369645b594180541e13f05d7

    condition:
        // TODO: replace with byte-level strings, pe.imphash(), or hash.sha256() checks
        // Example: pe.imphash() == "aabbccdd..."
        false  // stub – analyst must complete this rule
}
