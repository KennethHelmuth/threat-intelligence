rule win_salatstealer_20261119
{
    meta:
        description = "Auto-generated stub for win.salatstealer based on 5 hashes"
        author      = "ti-pipeline (auto-generated)"
        date        = "2026-11-19"
        version     = "1.0"
        source      = "ThreatFox"
        family      = "win.salatstealer"
        hash_count  = "5"

    strings:
        // Hashes (SHA-256) – reference only; add byte-strings/imphash conditions below
        // 1504be43c17da2682cd43e9a201b149a8f6862037739ac5e34df4b3acb33306a
        // fac670b7b1021fc4d4b515ec5244b70ac1d939aaed399e6ae4acbe221f4c6a33
        // 860b1f4d348f880652f0469864e97b0c
        // 6815b65f894493f175099caddde86422e0bead3309b398813324db11b761540b
        // c7125cc57ec08e84e25d503095d340dc

    condition:
        // TODO: replace with byte-level strings, pe.imphash(), or hash.sha256() checks
        // Example: pe.imphash() == "aabbccdd..."
        false  // stub – analyst must complete this rule
}
