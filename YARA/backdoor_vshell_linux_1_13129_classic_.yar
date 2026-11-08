rule backdoor_vshell_linux_1_13129_classic_
{
    meta:
        description = "Auto-generated stub for backdoor_vshell/linux!1_13129_(classic) based on 1 hashes"
        author      = "ti-pipeline (auto-generated)"
        date        = "2026-11-08"
        version     = "1.0"
        source      = "MalwareBazaar"
        family      = "backdoor_vshell/linux!1_13129_(classic)"
        hash_count  = "1"

    strings:
        // Hashes (SHA-256) – reference only; add byte-strings/imphash conditions below
        // d6b522eff9a195b37235acbf602131f63076d834a323277c04e648c211942671

    condition:
        // TODO: replace with byte-level strings, pe.imphash(), or hash.sha256() checks
        // Example: pe.imphash() == "aabbccdd..."
        false  // stub – analyst must complete this rule
}
