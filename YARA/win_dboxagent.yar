rule win_dboxagent
{
    meta:
        description = "Auto-generated stub for win.dboxagent based on 2 hashes"
        author      = "ti-pipeline (auto-generated)"
        date        = "2026-09-06"
        version     = "1.0"
        source      = "ThreatFox"
        family      = "win.dboxagent"
        hash_count  = "2"

    strings:
        // Hashes (SHA-256) – reference only; add byte-strings/imphash conditions below
        // 0a106aaf4a0999a5364bc53d697e2f10
        // d4f52e3470104f6a7e291b0df2bec8a63b70013eef74b49214a32e887be4e6f6

    condition:
        // TODO: replace with byte-level strings, pe.imphash(), or hash.sha256() checks
        // Example: pe.imphash() == "aabbccdd..."
        false  // stub – analyst must complete this rule
}
