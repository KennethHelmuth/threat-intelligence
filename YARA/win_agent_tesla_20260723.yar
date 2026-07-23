rule win_agent_tesla_20260723
{
    meta:
        description = "Auto-generated stub for win.agent_tesla based on 10 hashes"
        author      = "ti-pipeline (auto-generated)"
        date        = "2026-07-23"
        version     = "1.0"
        source      = "ThreatFox"
        family      = "win.agent_tesla"
        hash_count  = "10"

    strings:
        // Hashes (SHA-256) – reference only; add byte-strings/imphash conditions below
        // 9d59e6476c4022f7dbb738d7207cad30
        // 6dc941968b3bc93e3f5709972f0ce23395eb65465fa23ddd68b8cb6ca52ddd0c
        // b7721cf13508b02083feb0b010534423
        // 9992545ef435706e582bd516988195df8bae9985ff70d30ea2c20dc5206dfe3b
        // 2d569c5eaec74172ee46fb7af42962fc
        // b134896ab4f8a75cb79f559a1f3aa65b5cae52a3c39fb95ac8371d600c2c92a9
        // f12c120af203e20c35f019ff8eefc52a3cc5fae18b4a55e9a8c835d6ee88f098
        // a6482ea44033007a9da963cd3ff5ce49
        // 7cec47740ae2e3a5914bb46bc2d0ffc6
        // b811dce1aae1c0e0da249d5eb19dfd5b2640214627c9603b97f6f79c25a22e97

    condition:
        // TODO: replace with byte-level strings, pe.imphash(), or hash.sha256() checks
        // Example: pe.imphash() == "aabbccdd..."
        false  // stub – analyst must complete this rule
}
