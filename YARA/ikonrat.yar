rule ikonrat
{
    meta:
        description = "Auto-generated stub for ikonrat based on 4 hashes"
        author      = "ti-pipeline (auto-generated)"
        date        = "2026-11-26"
        version     = "1.0"
        source      = "OTX"
        family      = "ikonrat"
        hash_count  = "4"

    strings:
        // Hashes (SHA-256) – reference only; add byte-strings/imphash conditions below
        // 137c26e7db76a9626240473ab53a8fceedb1f0a9ca3580a3e66bd1f9d02e407e
        // 686dcfd8e7e33f2df80085d0b03b078958f32ba7a0aa735e07b4dde9f4bf3022
        // a3a5e2c42cc88336ef7ae7b2e118cd770162a72067df5304b97c774c6ff7562a
        // b2c593bdc096fa20f3fe00f1ea4a59b5320f884415a008f66b4283b935c9cfe1

    condition:
        // TODO: replace with byte-level strings, pe.imphash(), or hash.sha256() checks
        // Example: pe.imphash() == "aabbccdd..."
        false  // stub – analyst must complete this rule
}
