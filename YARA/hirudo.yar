rule hirudo
{
    meta:
        description = "Auto-generated stub for hirudo based on 8 hashes"
        author      = "ti-pipeline (auto-generated)"
        date        = "2026-10-16"
        version     = "1.0"
        source      = "OTX"
        family      = "hirudo"
        hash_count  = "8"

    strings:
        // Hashes (SHA-256) – reference only; add byte-strings/imphash conditions below
        // 3ccd2c02cf0661613816ca30032b4cdd
        // 3b14859a3a1219515f89ff453c7031f3dc8a95d7
        // 0097a0406be20544e98e981075427f40789db40fe4a53b1b4523383a945328b7
        // 2e45277acfde3fb704179476b08f428f66a03670bbdbf2e8ec79c0b0333c009b
        // 425cd7072b5e9386ac94e97fe272980b6ef36240df6b5d77b371ab7378004c83
        // b2270c29b3d0a49a716730d6ef108cffec0b1a4b159dd02e93333fb85e492b99
        // d51f2bd7ffb49c224d8eaec2c8ca1c8ab9fce2fd5fdceea01eb54296c2f47b4d
        // f796eb9ecf516e4f1fafcf89200d9f7d8ddd234f705e63f1bc8fc3ef583f0248

    condition:
        // TODO: replace with byte-level strings, pe.imphash(), or hash.sha256() checks
        // Example: pe.imphash() == "aabbccdd..."
        false  // stub – analyst must complete this rule
}
