rule win_reverse_rat
{
    meta:
        description = "Auto-generated stub for win.reverse_rat based on 2 hashes"
        author      = "ti-pipeline (auto-generated)"
        date        = "2026-10-13"
        version     = "1.0"
        source      = "ThreatFox"
        family      = "win.reverse_rat"
        hash_count  = "2"

    strings:
        // Hashes (SHA-256) – reference only; add byte-strings/imphash conditions below
        // babce0070440b5d81c045f20e741d60368e436b1e9d88e5661bf8325a9972e78
        // 8d5dc248d2dbdff62f6719185703f757

    condition:
        // TODO: replace with byte-level strings, pe.imphash(), or hash.sha256() checks
        // Example: pe.imphash() == "aabbccdd..."
        false  // stub – analyst must complete this rule
}
