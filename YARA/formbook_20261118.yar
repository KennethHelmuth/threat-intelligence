rule formbook_20261118
{
    meta:
        description = "Auto-generated stub for formbook based on 5 hashes"
        author      = "ti-pipeline (auto-generated)"
        date        = "2026-11-18"
        version     = "1.0"
        source      = "MalwareBazaar"
        family      = "formbook"
        hash_count  = "5"

    strings:
        // Hashes (SHA-256) – reference only; add byte-strings/imphash conditions below
        // 8f92be363039893c07a578bf0be3cffd5b22f6cc402c18269ba6e650db81a93f
        // 99e03781b4c52c5c5440082e54fff18857e59fe8161bf92184649ebcac7a6000
        // c50ced1116cae74556951a395ce9bb2f958a519105093b38025009b7046a9f07
        // 20370532a621f2611b51ad0369fb1f48c5208f49a971b56b44f1e2d321c41cb0
        // 0692bcfd2eb11a5ec2f5b1076e6cc4cd4c911adbc8ac34b7350c9797a25e432d

    condition:
        // TODO: replace with byte-level strings, pe.imphash(), or hash.sha256() checks
        // Example: pe.imphash() == "aabbccdd..."
        false  // stub – analyst must complete this rule
}
