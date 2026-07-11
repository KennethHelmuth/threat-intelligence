rule win_xworm_20260711
{
    meta:
        description = "Auto-generated stub for win.xworm based on 2 hashes"
        author      = "ti-pipeline (auto-generated)"
        date        = "2026-07-11"
        version     = "1.0"
        source      = "ThreatFox"
        family      = "win.xworm"
        hash_count  = "2"

    strings:
        // Hashes (SHA-256) – reference only; add byte-strings/imphash conditions below
        // 6e66f889923ccb7dc34641a4d7ddc234
        // 7ee796a8fef94d38a6ef3d906fe3d37052b5b6c2435420dcc75e459fbc501a68

    condition:
        // TODO: replace with byte-level strings, pe.imphash(), or hash.sha256() checks
        // Example: pe.imphash() == "aabbccdd..."
        false  // stub – analyst must complete this rule
}
