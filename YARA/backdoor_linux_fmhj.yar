rule backdoor_linux_fmhj
{
    meta:
        description = "Auto-generated stub for backdoor_linux_fmhj based on 2 hashes"
        author      = "ti-pipeline (auto-generated)"
        date        = "2026-09-16"
        version     = "1.0"
        source      = "MalwareBazaar"
        family      = "backdoor_linux_fmhj"
        hash_count  = "2"

    strings:
        // Hashes (SHA-256) – reference only; add byte-strings/imphash conditions below
        // 2aa16ffb145e1ad6a8972908f7abb035fc1982855d64a3cf843fd4dff6186576
        // 649b488b6795b6782cc6c3c03dd22b06dd173a21d5d4b046eed69743926a2b6e

    condition:
        // TODO: replace with byte-level strings, pe.imphash(), or hash.sha256() checks
        // Example: pe.imphash() == "aabbccdd..."
        false  // stub – analyst must complete this rule
}
