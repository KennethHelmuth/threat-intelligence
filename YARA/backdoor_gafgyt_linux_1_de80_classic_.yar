rule backdoor_gafgyt_linux_1_de80_classic_
{
    meta:
        description = "Auto-generated stub for backdoor_gafgyt/linux!1_de80_(classic) based on 1 hashes"
        author      = "ti-pipeline (auto-generated)"
        date        = "2026-10-12"
        version     = "1.0"
        source      = "MalwareBazaar"
        family      = "backdoor_gafgyt/linux!1_de80_(classic)"
        hash_count  = "1"

    strings:
        // Hashes (SHA-256) – reference only; add byte-strings/imphash conditions below
        // ff5ab417d41ff6ab5fdfd03daea132cc11f5707ad3e801166748a1da3383443e

    condition:
        // TODO: replace with byte-level strings, pe.imphash(), or hash.sha256() checks
        // Example: pe.imphash() == "aabbccdd..."
        false  // stub – analyst must complete this rule
}
