rule win_remotex_20260715
{
    meta:
        description = "Auto-generated stub for win.remotex based on 2 hashes"
        author      = "ti-pipeline (auto-generated)"
        date        = "2026-07-15"
        version     = "1.0"
        source      = "ThreatFox"
        family      = "win.remotex"
        hash_count  = "2"

    strings:
        // Hashes (SHA-256) – reference only; add byte-strings/imphash conditions below
        // fcdf36f4778815825ab6128b2e46dd61
        // 85168dcb0ef99f785cbb51ec6481a0c6940a099cec3671faaef59e5f3978de45

    condition:
        // TODO: replace with byte-level strings, pe.imphash(), or hash.sha256() checks
        // Example: pe.imphash() == "aabbccdd..."
        false  // stub – analyst must complete this rule
}
