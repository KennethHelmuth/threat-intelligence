rule coruna_20261118
{
    meta:
        description = "Auto-generated stub for coruna based on 4 hashes"
        author      = "ti-pipeline (auto-generated)"
        date        = "2026-11-18"
        version     = "1.0"
        source      = "OTX"
        family      = "coruna"
        hash_count  = "4"

    strings:
        // Hashes (SHA-256) – reference only; add byte-strings/imphash conditions below
        // f7b84b9a94f749f8ced3f0112d0a66894e8bbc3b4aa5592021d1b8976a9bad40
        // 44b43284186ac0f53e0afbfaf849c703
        // a46f6787524b787f7331ce19673cef1d7929f755
        // 814a963c0da480e2449d9b6664480156e1cd6d731014117401bf635badec3a0f

    condition:
        // TODO: replace with byte-level strings, pe.imphash(), or hash.sha256() checks
        // Example: pe.imphash() == "aabbccdd..."
        false  // stub – analyst must complete this rule
}
