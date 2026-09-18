rule win_arkei_stealer_20260918
{
    meta:
        description = "Auto-generated stub for win.arkei_stealer based on 2 hashes"
        author      = "ti-pipeline (auto-generated)"
        date        = "2026-09-18"
        version     = "1.0"
        source      = "ThreatFox"
        family      = "win.arkei_stealer"
        hash_count  = "2"

    strings:
        // Hashes (SHA-256) – reference only; add byte-strings/imphash conditions below
        // 0f0813c1e7e1787d105f8904243200f6
        // d0577b1ed38ab7fe3ba4594c58232fd3f413232f6a40e23b86dfc3eeb39c5cd8

    condition:
        // TODO: replace with byte-level strings, pe.imphash(), or hash.sha256() checks
        // Example: pe.imphash() == "aabbccdd..."
        false  // stub – analyst must complete this rule
}
