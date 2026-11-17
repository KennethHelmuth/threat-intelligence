rule win_salatstealer_20261117
{
    meta:
        description = "Auto-generated stub for win.salatstealer based on 2 hashes"
        author      = "ti-pipeline (auto-generated)"
        date        = "2026-11-17"
        version     = "1.0"
        source      = "ThreatFox"
        family      = "win.salatstealer"
        hash_count  = "2"

    strings:
        // Hashes (SHA-256) – reference only; add byte-strings/imphash conditions below
        // 1ff4daa1a5014ec60598302fe58752dc9a5b789646d6f51f3b307f7a0f909b37
        // 64c16da27d7c500b1583e7cab12e1b305dc18974f563aa2ad4f192e8b304eb42

    condition:
        // TODO: replace with byte-level strings, pe.imphash(), or hash.sha256() checks
        // Example: pe.imphash() == "aabbccdd..."
        false  // stub – analyst must complete this rule
}
