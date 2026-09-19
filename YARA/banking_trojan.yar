rule banking_trojan
{
    meta:
        description = "Auto-generated stub for banking_trojan based on 7 hashes"
        author      = "ti-pipeline (auto-generated)"
        date        = "2026-09-19"
        version     = "1.0"
        source      = "OTX"
        family      = "banking_trojan"
        hash_count  = "7"

    strings:
        // Hashes (SHA-256) – reference only; add byte-strings/imphash conditions below
        // 00810c2e0ad5031b9fe5d2cfb4a6fb45a1c424d6b92be7ba3b1aaa7c55b10f8e
        // 03a1d2eca771a276ac9c29a4bf219d31beb20848998cacda8b06375bd2795b10
        // 06990ee09a29d2cdde32cb639d50e6c1e078da96a7bdabd03a68a0bb209d07b1
        // 10ab0f8ee0829fb24bf2c915f5bb0f35a2d84ed1d69049d42ca32cfa36250c11
        // 5ac6a2b0d20c5508027e6fde6503a5e0105be59f2a57e6659caa14e4ac0d5939
        // 67427f232762fe32afab1d0d14b1d6e7f7920f5b151e133fb68c9dfc333ec69a
        // cf176cf0ff50c74f08f127ef3b09be63a6f9e3ad69fa48233d4c805898368b2a

    condition:
        // TODO: replace with byte-level strings, pe.imphash(), or hash.sha256() checks
        // Example: pe.imphash() == "aabbccdd..."
        false  // stub – analyst must complete this rule
}
