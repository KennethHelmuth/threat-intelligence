rule backdoor_linux_fnqr_20260917
{
    meta:
        description = "Auto-generated stub for backdoor_linux_fnqr based on 1 hashes"
        author      = "ti-pipeline (auto-generated)"
        date        = "2026-09-17"
        version     = "1.0"
        source      = "MalwareBazaar"
        family      = "backdoor_linux_fnqr"
        hash_count  = "1"

    strings:
        // Hashes (SHA-256) – reference only; add byte-strings/imphash conditions below
        // d722a46e3c3acfd16f83a466dc21290ef041d51504dc050382cbadaeffed2e4c

    condition:
        // TODO: replace with byte-level strings, pe.imphash(), or hash.sha256() checks
        // Example: pe.imphash() == "aabbccdd..."
        false  // stub – analyst must complete this rule
}
