rule win_gcleaner_20260711
{
    meta:
        description = "Auto-generated stub for win.gcleaner based on 2 hashes"
        author      = "ti-pipeline (auto-generated)"
        date        = "2026-07-11"
        version     = "1.0"
        source      = "ThreatFox"
        family      = "win.gcleaner"
        hash_count  = "2"

    strings:
        // Hashes (SHA-256) – reference only; add byte-strings/imphash conditions below
        // 7197e9097b977d138f3856a8aca3a3b3c6b28b82cc76a3667ef1364e820195cb
        // 845a1bc9408c542cf748ba647c2e680e

    condition:
        // TODO: replace with byte-level strings, pe.imphash(), or hash.sha256() checks
        // Example: pe.imphash() == "aabbccdd..."
        false  // stub – analyst must complete this rule
}
