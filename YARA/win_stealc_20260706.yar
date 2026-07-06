rule win_stealc_20260706
{
    meta:
        description = "Auto-generated stub for win.stealc based on 4 hashes"
        author      = "ti-pipeline (auto-generated)"
        date        = "2026-07-06"
        version     = "1.0"
        source      = "ThreatFox"
        family      = "win.stealc"
        hash_count  = "4"

    strings:
        // Hashes (SHA-256) – reference only; add byte-strings/imphash conditions below
        // 716608d7e9a26e980f916e73792abcb86bbb21fb949436b7f359afcaf730b078
        // dc903b2967c0c943084a0d5c0d131cf1
        // d3f9acfa6119f28d666e25d7e078570a
        // 1095cf2951bbc8b1ecd33798afad192449a102aa1b976fb60bf566a08d693587

    condition:
        // TODO: replace with byte-level strings, pe.imphash(), or hash.sha256() checks
        // Example: pe.imphash() == "aabbccdd..."
        false  // stub – analyst must complete this rule
}
