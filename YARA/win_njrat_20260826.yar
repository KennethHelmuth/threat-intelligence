rule win_njrat_20260826
{
    meta:
        description = "Auto-generated stub for win.njrat based on 6 hashes"
        author      = "ti-pipeline (auto-generated)"
        date        = "2026-08-26"
        version     = "1.0"
        source      = "ThreatFox"
        family      = "win.njrat"
        hash_count  = "6"

    strings:
        // Hashes (SHA-256) – reference only; add byte-strings/imphash conditions below
        // 13fe4fd84d2f0fe65fe209c4ee390752
        // 895fea5f9576b02251d5c3b6d49e5d4611d4255789744d56599d5b5ede7dd563
        // 32295f0896a1603bdf37be339787dac7df37dc7c08bfae6bb1f5f157ca85b71c
        // 2f490ac81c015798c477a5d882f425d5
        // 3e08292340a925412039c40af6eefec9a30fca1e60246baca93caf9f4bd3e53c
        // dee3308c48a52fc15394c3e89221226d

    condition:
        // TODO: replace with byte-level strings, pe.imphash(), or hash.sha256() checks
        // Example: pe.imphash() == "aabbccdd..."
        false  // stub – analyst must complete this rule
}
