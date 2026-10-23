rule doina
{
    meta:
        description = "Auto-generated stub for doina based on 11 hashes"
        author      = "ti-pipeline (auto-generated)"
        date        = "2026-10-23"
        version     = "1.0"
        source      = "OTX"
        family      = "doina"
        hash_count  = "11"

    strings:
        // Hashes (SHA-256) – reference only; add byte-strings/imphash conditions below
        // 2bb937c7eac0843313ee402735768e25
        // 923db163b89884e3f371cf322ee1a071515e2477
        // 035d396b3a329f59d680dc36a0a639eb7fb306bea97e42f5f53293dce817e8b7
        // 24a293a662600b2292d9259baebba1c09b41df82a5c9c20f8572625ae759696f
        // 408b7fc4f08f2a9044046025f05995e8cbd5c96c39844aaa8a7eb8ee4697ea89
        // 42527a4388ef4ade6f4eaf52706f0ab31cb4e9ced3a56a6b15402551f9f01208
        // 87a047160eb1a9b92e6ede511252dfc624b0f5a7185ac2cec1c7ebde8cdf4eea
        // 891cc3ca2d29e9b185a8913e93810f48859d2be1f23ddd977a15cdbeed509e0e
        // b8419a676a3d4af04ea98287a2b85052fae5c06e6278ca9d8bfa4b5b396b39a6
        // bc9e2dac08fb4f83dddb44f89bf7082bb4134697fbf6a99ad8ce30c634e9fe8a
        // d864b28c302db9ed10baf8def0fb26bac0b97d27349d22c4e9390d30fce54649

    condition:
        // TODO: replace with byte-level strings, pe.imphash(), or hash.sha256() checks
        // Example: pe.imphash() == "aabbccdd..."
        false  // stub – analyst must complete this rule
}
