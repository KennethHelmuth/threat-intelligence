rule win_stealc_20261029
{
    meta:
        description = "Auto-generated stub for win.stealc based on 2 hashes"
        author      = "ti-pipeline (auto-generated)"
        date        = "2026-10-29"
        version     = "1.0"
        source      = "ThreatFox"
        family      = "win.stealc"
        hash_count  = "2"

    strings:
        // Hashes (SHA-256) – reference only; add byte-strings/imphash conditions below
        // 78fb06eef2722709feb14cd85ecd74e5
        // 655d159778124a3e86adaa7fb139de2c107b9936f2d719b54756de98b8135deb

    condition:
        // TODO: replace with byte-level strings, pe.imphash(), or hash.sha256() checks
        // Example: pe.imphash() == "aabbccdd..."
        false  // stub – analyst must complete this rule
}
