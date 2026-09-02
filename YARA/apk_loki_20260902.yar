rule apk_loki_20260902
{
    meta:
        description = "Auto-generated stub for apk.loki based on 2 hashes"
        author      = "ti-pipeline (auto-generated)"
        date        = "2026-09-02"
        version     = "1.0"
        source      = "ThreatFox"
        family      = "apk.loki"
        hash_count  = "2"

    strings:
        // Hashes (SHA-256) – reference only; add byte-strings/imphash conditions below
        // 1b92d7190164658d01f5d9fa78525171ad8b4d07bf61507f83c36de906eeb0d5
        // fd127ea7d3e1375b723541cdf5d52132

    condition:
        // TODO: replace with byte-level strings, pe.imphash(), or hash.sha256() checks
        // Example: pe.imphash() == "aabbccdd..."
        false  // stub – analyst must complete this rule
}
