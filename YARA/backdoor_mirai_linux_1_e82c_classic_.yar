rule backdoor_mirai_linux_1_e82c_classic_
{
    meta:
        description = "Auto-generated stub for backdoor_mirai/linux!1_e82c_(classic) based on 2 hashes"
        author      = "ti-pipeline (auto-generated)"
        date        = "2026-11-22"
        version     = "1.0"
        source      = "MalwareBazaar"
        family      = "backdoor_mirai/linux!1_e82c_(classic)"
        hash_count  = "2"

    strings:
        // Hashes (SHA-256) – reference only; add byte-strings/imphash conditions below
        // ea3ba48d47911939b516dabb21ed302bb3a66a61916d86a9f60d8a0df7975ed1
        // e1adcb6d7f294e4c50c6507350f0e705b027482b3c84de02146c6c52ab6fd6f0

    condition:
        // TODO: replace with byte-level strings, pe.imphash(), or hash.sha256() checks
        // Example: pe.imphash() == "aabbccdd..."
        false  // stub – analyst must complete this rule
}
