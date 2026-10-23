rule backdoor_linux_mirai_uvtra
{
    meta:
        description = "Auto-generated stub for backdoor_linux_mirai_uvtra based on 2 hashes"
        author      = "ti-pipeline (auto-generated)"
        date        = "2026-10-23"
        version     = "1.0"
        source      = "MalwareBazaar"
        family      = "backdoor_linux_mirai_uvtra"
        hash_count  = "2"

    strings:
        // Hashes (SHA-256) – reference only; add byte-strings/imphash conditions below
        // faf0bc67308eb8eb4261e918c57e187eef458d87d6ba64a591b2e6672b771d9d
        // 87f4c9758c73198c38289dcc3cdbe032b9ebc5d39115f2c2cb187d2396edc2c1

    condition:
        // TODO: replace with byte-level strings, pe.imphash(), or hash.sha256() checks
        // Example: pe.imphash() == "aabbccdd..."
        false  // stub – analyst must complete this rule
}
