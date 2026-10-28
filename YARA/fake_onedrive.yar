rule fake_onedrive
{
    meta:
        description = "Auto-generated stub for fake_onedrive based on 2 hashes"
        author      = "ti-pipeline (auto-generated)"
        date        = "2026-10-28"
        version     = "1.0"
        source      = "OTX"
        family      = "fake_onedrive"
        hash_count  = "2"

    strings:
        // Hashes (SHA-256) – reference only; add byte-strings/imphash conditions below
        // c9281ea6828b9de4443ac56361ac29da
        // 9ca705d6466d4d71c3fb0cae5097933afe1de1bc139d53bb63565a52dc9ebccb

    condition:
        // TODO: replace with byte-level strings, pe.imphash(), or hash.sha256() checks
        // Example: pe.imphash() == "aabbccdd..."
        false  // stub – analyst must complete this rule
}
