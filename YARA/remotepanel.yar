rule remotepanel
{
    meta:
        description = "Auto-generated stub for remotepanel based on 6 hashes"
        author      = "ti-pipeline (auto-generated)"
        date        = "2026-09-26"
        version     = "1.0"
        source      = "OTX"
        family      = "remotepanel"
        hash_count  = "6"

    strings:
        // Hashes (SHA-256) – reference only; add byte-strings/imphash conditions below
        // 30f9387b6aa2dd249d93cec58786251a224faaec57673a4b8104a33a01dfe62b
        // 351f0d27d2f0105186446693eed5794419ad79d7e6e647fc2fe74dbffb25f9ad
        // 5060c8184993d5ac04701ffa2c1d30451e40a7b2dbfc084eceaabb5084704991
        // a7e8c9e157d3ce37913a32aaa861b5248da4cc5288fa99a6b291524af5e3b9c6
        // b7a5c52cedd9cd5425a7f85b8d3b4b869b805c70c7991375a2c4ab612ff7906d
        // fec29bbd8e50b6635ef683f03f6e018c9627aa6362a2f167115424e50b8c1b10

    condition:
        // TODO: replace with byte-level strings, pe.imphash(), or hash.sha256() checks
        // Example: pe.imphash() == "aabbccdd..."
        false  // stub – analyst must complete this rule
}
