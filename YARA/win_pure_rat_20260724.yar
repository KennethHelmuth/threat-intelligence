rule win_pure_rat_20260724
{
    meta:
        description = "Auto-generated stub for win.pure_rat based on 2 hashes"
        author      = "ti-pipeline (auto-generated)"
        date        = "2026-07-24"
        version     = "1.0"
        source      = "ThreatFox"
        family      = "win.pure_rat"
        hash_count  = "2"

    strings:
        // Hashes (SHA-256) – reference only; add byte-strings/imphash conditions below
        // 13aa55915fe8418214edc3f57138e29e
        // 5f2979cd7d8192bb50266546557be153907b952d73f911122655c79c9ba73591

    condition:
        // TODO: replace with byte-level strings, pe.imphash(), or hash.sha256() checks
        // Example: pe.imphash() == "aabbccdd..."
        false  // stub – analyst must complete this rule
}
