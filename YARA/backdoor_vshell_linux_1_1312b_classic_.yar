rule backdoor_vshell_linux_1_1312b_classic_
{
    meta:
        description = "Auto-generated stub for backdoor_vshell/linux!1_1312b_(classic) based on 2 hashes"
        author      = "ti-pipeline (auto-generated)"
        date        = "2026-11-08"
        version     = "1.0"
        source      = "MalwareBazaar"
        family      = "backdoor_vshell/linux!1_1312b_(classic)"
        hash_count  = "2"

    strings:
        // Hashes (SHA-256) – reference only; add byte-strings/imphash conditions below
        // 9bf11533b250a32c79d7b8734252eee95cbcf29fde23322e4c584854d16bdf68
        // 2d49cf640c7810483aa6f999e0f5177a19305c0bc4545d21c9b935f46bc091e1

    condition:
        // TODO: replace with byte-level strings, pe.imphash(), or hash.sha256() checks
        // Example: pe.imphash() == "aabbccdd..."
        false  // stub – analyst must complete this rule
}
