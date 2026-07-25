rule win_gcleaner_20260725
{
    meta:
        description = "Auto-generated stub for win.gcleaner based on 2 hashes"
        author      = "ti-pipeline (auto-generated)"
        date        = "2026-07-25"
        version     = "1.0"
        source      = "ThreatFox"
        family      = "win.gcleaner"
        hash_count  = "2"

    strings:
        // Hashes (SHA-256) – reference only; add byte-strings/imphash conditions below
        // 8498ec75a9609ce1d1a27138fccf246a
        // e2ade9d3303ff03e5e73c8d90da926e3c2390aa3698924d2397c692138c9a141

    condition:
        // TODO: replace with byte-level strings, pe.imphash(), or hash.sha256() checks
        // Example: pe.imphash() == "aabbccdd..."
        false  // stub – analyst must complete this rule
}
