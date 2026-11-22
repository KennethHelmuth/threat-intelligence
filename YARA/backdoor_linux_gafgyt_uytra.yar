rule backdoor_linux_gafgyt_uytra
{
    meta:
        description = "Auto-generated stub for backdoor_linux_gafgyt_uytra based on 2 hashes"
        author      = "ti-pipeline (auto-generated)"
        date        = "2026-11-22"
        version     = "1.0"
        source      = "MalwareBazaar"
        family      = "backdoor_linux_gafgyt_uytra"
        hash_count  = "2"

    strings:
        // Hashes (SHA-256) – reference only; add byte-strings/imphash conditions below
        // 2ae7c72ba12d52355551550aa6c2147549a40260524bbb2c8bbb359b0474bc56
        // 486d258731b76f0922d79542593cc97880100f589028743a0a79b7380c19ee31

    condition:
        // TODO: replace with byte-level strings, pe.imphash(), or hash.sha256() checks
        // Example: pe.imphash() == "aabbccdd..."
        false  // stub – analyst must complete this rule
}
