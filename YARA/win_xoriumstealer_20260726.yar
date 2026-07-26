rule win_xoriumstealer_20260726
{
    meta:
        description = "Auto-generated stub for win.xoriumstealer based on 2 hashes"
        author      = "ti-pipeline (auto-generated)"
        date        = "2026-07-26"
        version     = "1.0"
        source      = "ThreatFox"
        family      = "win.xoriumstealer"
        hash_count  = "2"

    strings:
        // Hashes (SHA-256) – reference only; add byte-strings/imphash conditions below
        // 364d3883e81da01bb449083552e5f1526ec734bdf40b27e71a4670fc3df12e76
        // 65c3aa0a48027921f2f94df9fd45c422

    condition:
        // TODO: replace with byte-level strings, pe.imphash(), or hash.sha256() checks
        // Example: pe.imphash() == "aabbccdd..."
        false  // stub – analyst must complete this rule
}
