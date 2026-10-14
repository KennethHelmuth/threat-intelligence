rule win_salatstealer_20261014
{
    meta:
        description = "Auto-generated stub for win.salatstealer based on 4 hashes"
        author      = "ti-pipeline (auto-generated)"
        date        = "2026-10-14"
        version     = "1.0"
        source      = "ThreatFox"
        family      = "win.salatstealer"
        hash_count  = "4"

    strings:
        // Hashes (SHA-256) – reference only; add byte-strings/imphash conditions below
        // 885c38bde7effc7a8af889efc78a1224
        // 2b94ca38bb03b91ff7e21aecd1626c63940617476c5a430fc0f5be17cd2b0964
        // 8a5d17ac34596b46b71d0316841654f4
        // c72861fd6e134f05f7aa27c2a6345002f9a0b4d4474fe12555ca0f159e7257b7

    condition:
        // TODO: replace with byte-level strings, pe.imphash(), or hash.sha256() checks
        // Example: pe.imphash() == "aabbccdd..."
        false  // stub – analyst must complete this rule
}
