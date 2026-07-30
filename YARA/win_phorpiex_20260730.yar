rule win_phorpiex_20260730
{
    meta:
        description = "Auto-generated stub for win.phorpiex based on 10 hashes"
        author      = "ti-pipeline (auto-generated)"
        date        = "2026-07-30"
        version     = "1.0"
        source      = "ThreatFox"
        family      = "win.phorpiex"
        hash_count  = "10"

    strings:
        // Hashes (SHA-256) – reference only; add byte-strings/imphash conditions below
        // 06ba9a25b7493b4c4340e7f4a9a74230
        // 4f55629fddb7c272fe500b6a132fb15341d2f58ca29fb597be19ebdb77e1994d
        // 96508589d281460eab4eb1819c80e89bdffdb5fe86b8fe1400bb9268deb09e74
        // 1ab31f82e6c8455c61f3a14b753a7ace
        // b91d0d56c1d7ed94962d0f6501761db3573b1090fac15d9424e8b3c8b1914c9a
        // e5a7e8a76088d1cb0db01c805588bbf2
        // 0ed62134ba816c2c604a319692d97201
        // ebd140217102e211a74b341198292a392a0e25ecf5ec1a53fb411c14c3b7b6f8
        // 6edb9c07dccb6bbf836fb28a6560e921
        // d664021eff6b92368479a4b9401272f9f869bddb0a22da5434747bb0433fff45

    condition:
        // TODO: replace with byte-level strings, pe.imphash(), or hash.sha256() checks
        // Example: pe.imphash() == "aabbccdd..."
        false  // stub – analyst must complete this rule
}
