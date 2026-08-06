rule backdoor_linux_mirai_rmpra
{
    meta:
        description = "Auto-generated stub for backdoor_linux_mirai_rmpra based on 1 hashes"
        author      = "ti-pipeline (auto-generated)"
        date        = "2026-08-06"
        version     = "1.0"
        source      = "MalwareBazaar"
        family      = "backdoor_linux_mirai_rmpra"
        hash_count  = "1"

    strings:
        // Hashes (SHA-256) – reference only; add byte-strings/imphash conditions below
        // 23cb10bd16bcc36e97e538e6d6d7271cbed14e49f535dc535c2c4859dbd56c25

    condition:
        // TODO: replace with byte-level strings, pe.imphash(), or hash.sha256() checks
        // Example: pe.imphash() == "aabbccdd..."
        false  // stub – analyst must complete this rule
}
