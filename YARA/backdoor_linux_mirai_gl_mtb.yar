rule backdoor_linux_mirai_gl_mtb
{
    meta:
        description = "Auto-generated stub for backdoor:linux/mirai_gl!mtb based on 1 hashes"
        author      = "ti-pipeline (auto-generated)"
        date        = "2026-10-09"
        version     = "1.0"
        source      = "MalwareBazaar"
        family      = "backdoor:linux/mirai_gl!mtb"
        hash_count  = "1"

    strings:
        // Hashes (SHA-256) – reference only; add byte-strings/imphash conditions below
        // 178ee12744a15f48fb6ebfba3191af933b59b4c6a86f430175bc3a87a0d2710a

    condition:
        // TODO: replace with byte-level strings, pe.imphash(), or hash.sha256() checks
        // Example: pe.imphash() == "aabbccdd..."
        false  // stub – analyst must complete this rule
}
