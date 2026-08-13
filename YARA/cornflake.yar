rule cornflake
{
    meta:
        description = "Auto-generated stub for cornflake based on 6 hashes"
        author      = "ti-pipeline (auto-generated)"
        date        = "2026-08-13"
        version     = "1.0"
        source      = "OTX"
        family      = "cornflake"
        hash_count  = "6"

    strings:
        // Hashes (SHA-256) – reference only; add byte-strings/imphash conditions below
        // 918fa52ae45ed60ba7cc8bdc99c3cbe9ab92e0375ec31fc05d0d4513be11c593
        // be99857449d2856dd5a84e21c8a3d5e0e01456adb44062ddec5a6b4970d8d42c
        // c6f4df18cb880500f3921a179c3a3766
        // fba867df17721879df9d8dcca68d6900
        // 510af9bb00ff5d4a6856b1291af55db9f6e13551
        // 937e75e0e1c82eecab69e9b8ad481bd7e0845308

    condition:
        // TODO: replace with byte-level strings, pe.imphash(), or hash.sha256() checks
        // Example: pe.imphash() == "aabbccdd..."
        false  // stub – analyst must complete this rule
}
