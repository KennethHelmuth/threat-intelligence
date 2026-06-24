rule win_stealc_20260624
{
    meta:
        description = "Auto-generated stub for win.stealc based on 10 hashes"
        author      = "ti-pipeline (auto-generated)"
        date        = "2026-06-24"
        version     = "1.0"
        source      = "ThreatFox"
        family      = "win.stealc"
        hash_count  = "10"

    strings:
        // Hashes (SHA-256) – reference only; add byte-strings/imphash conditions below
        // 79187195d75a83469f94d84887157251
        // 87c61136236dbb9ab635e379d866fe49
        // 1188d1f47cfc3797e1eb004e531b11b7a191a21475d97226dfa607db380b650b
        // d2b4cb1d964d01bce7246acb289f2a23
        // 33166e17fdb736cdfbe304002b081db17069618d5110e30b3a01d9086d5e1273
        // 820e7ddb14f8b3de26b54c56d8b67749
        // 69e82da57188417c62f945e4d4747954ee3e75edfc82e7da9c28f67cef18430a
        // ab0553ff56ec4cd19d58b115c03513e6
        // dad8e703aa0e0077992d417f2825b9fd7b3c54058f76212547ffb0da2e072e02
        // f56297a4158c79b49c9079ba634ea9595461717fb0955affe308ea05633ec9f1

    condition:
        // TODO: replace with byte-level strings, pe.imphash(), or hash.sha256() checks
        // Example: pe.imphash() == "aabbccdd..."
        false  // stub – analyst must complete this rule
}
