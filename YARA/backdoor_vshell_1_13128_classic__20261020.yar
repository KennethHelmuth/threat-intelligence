rule backdoor_vshell_1_13128_classic__20261020
{
    meta:
        description = "Auto-generated stub for backdoor_vshell!1_13128_(classic) based on 3 hashes"
        author      = "ti-pipeline (auto-generated)"
        date        = "2026-10-20"
        version     = "1.0"
        source      = "MalwareBazaar"
        family      = "backdoor_vshell!1_13128_(classic)"
        hash_count  = "3"

    strings:
        // Hashes (SHA-256) – reference only; add byte-strings/imphash conditions below
        // f5da783380784216a5979a7ac7285792a4ca2e04a4a7c3bd921ef9a7f5eaa3a0
        // c018650f7847d0566d56933e5953bdd5227133f645cba35d3c1e69879b455924
        // f7046c0941b75bdbf5f547d4c0b70f3d41bdd50b36f49e42e29ceaee3671e623

    condition:
        // TODO: replace with byte-level strings, pe.imphash(), or hash.sha256() checks
        // Example: pe.imphash() == "aabbccdd..."
        false  // stub – analyst must complete this rule
}
