rule win_asyncrat_20260703
{
    meta:
        description = "Auto-generated stub for win.asyncrat based on 4 hashes"
        author      = "ti-pipeline (auto-generated)"
        date        = "2026-07-03"
        version     = "1.0"
        source      = "ThreatFox"
        family      = "win.asyncrat"
        hash_count  = "4"

    strings:
        // Hashes (SHA-256) – reference only; add byte-strings/imphash conditions below
        // 179e5c88bbd34e45830e7ee3610d5216
        // 0aac658075b7d9e81419d0beaa3db796569bc14fd57512f4479fb36e9cc4c1a2
        // 538860d455edc8108e667b8498a41fe3
        // fe126b87922ff8049c4b19d6588324a3bb4874020b943e86de176445ebe7c7b9

    condition:
        // TODO: replace with byte-level strings, pe.imphash(), or hash.sha256() checks
        // Example: pe.imphash() == "aabbccdd..."
        false  // stub – analyst must complete this rule
}
