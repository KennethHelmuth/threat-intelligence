rule apk_loki
{
    meta:
        description = "Auto-generated stub for apk.loki based on 2 hashes"
        author      = "ti-pipeline (auto-generated)"
        date        = "2026-07-11"
        version     = "1.0"
        source      = "ThreatFox"
        family      = "apk.loki"
        hash_count  = "2"

    strings:
        // Hashes (SHA-256) – reference only; add byte-strings/imphash conditions below
        // 8ed6ba61d3f45cc25d65f72605ed3f18
        // 558695e3c131c802602abb91b368cb4a1f04b6cf48b4e8ffaf86f1ec30394730

    condition:
        // TODO: replace with byte-level strings, pe.imphash(), or hash.sha256() checks
        // Example: pe.imphash() == "aabbccdd..."
        false  // stub – analyst must complete this rule
}
