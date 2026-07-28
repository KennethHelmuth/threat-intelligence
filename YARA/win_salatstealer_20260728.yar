rule win_salatstealer_20260728
{
    meta:
        description = "Auto-generated stub for win.salatstealer based on 6 hashes"
        author      = "ti-pipeline (auto-generated)"
        date        = "2026-07-28"
        version     = "1.0"
        source      = "ThreatFox"
        family      = "win.salatstealer"
        hash_count  = "6"

    strings:
        // Hashes (SHA-256) – reference only; add byte-strings/imphash conditions below
        // cffac6c24519fd656a99ddfe63611a27
        // ab4394c429efc69b6927a5eb6ecfe7e2cc3df99dd2d279f96729d72a8283e85f
        // a7c07b87c4968d7ac8120e2c6fb40ccd615d1bd25d4445fbe129d7c66235740a
        // f27c7e9e44efa74a367eff0200584d01
        // 89d0178c292a0230d69c1de53f5e55994d195329cbbbacbaa7fb2e6101917b63
        // b9974299de794e9b5e30ec95f7849e97

    condition:
        // TODO: replace with byte-level strings, pe.imphash(), or hash.sha256() checks
        // Example: pe.imphash() == "aabbccdd..."
        false  // stub – analyst must complete this rule
}
