rule win_collection_rat
{
    meta:
        description = "Auto-generated stub for win.collection_rat based on 2 hashes"
        author      = "ti-pipeline (auto-generated)"
        date        = "2026-10-07"
        version     = "1.0"
        source      = "ThreatFox"
        family      = "win.collection_rat"
        hash_count  = "2"

    strings:
        // Hashes (SHA-256) – reference only; add byte-strings/imphash conditions below
        // 63a4f55282106baed0ef20a3017768fd1fca367d63bf12206768e18211b985a0
        // 4951465b8b9db30de15a8034b4e62137

    condition:
        // TODO: replace with byte-level strings, pe.imphash(), or hash.sha256() checks
        // Example: pe.imphash() == "aabbccdd..."
        false  // stub – analyst must complete this rule
}
