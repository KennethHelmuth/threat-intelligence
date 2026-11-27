rule backdoor_linux_fmhj_20261127
{
    meta:
        description = "Auto-generated stub for backdoor_linux_fmhj based on 1 hashes"
        author      = "ti-pipeline (auto-generated)"
        date        = "2026-11-27"
        version     = "1.0"
        source      = "MalwareBazaar"
        family      = "backdoor_linux_fmhj"
        hash_count  = "1"

    strings:
        // Hashes (SHA-256) – reference only; add byte-strings/imphash conditions below
        // 8a0220a06604d08a75adb50f2c75bcd5c44457c39effce59e7c07dbd93fc2341

    condition:
        // TODO: replace with byte-level strings, pe.imphash(), or hash.sha256() checks
        // Example: pe.imphash() == "aabbccdd..."
        false  // stub – analyst must complete this rule
}
