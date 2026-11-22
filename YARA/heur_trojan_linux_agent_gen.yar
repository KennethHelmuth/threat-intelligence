rule heur_trojan_linux_agent_gen
{
    meta:
        description = "Auto-generated stub for heur:trojan_linux_agent_gen based on 3 hashes"
        author      = "ti-pipeline (auto-generated)"
        date        = "2026-11-22"
        version     = "1.0"
        source      = "MalwareBazaar"
        family      = "heur:trojan_linux_agent_gen"
        hash_count  = "3"

    strings:
        // Hashes (SHA-256) – reference only; add byte-strings/imphash conditions below
        // 42e9e779b677a744028b1276672d6ec010a96773cd143dd38cf32fdf104a4957
        // 7be5b6eef6df0540a745b8e725a5fdc4ff4ce95c878afcf6f0b4f88a36bdd223
        // e8e60fbba93bc587135a5a474bc52dec8dd6ec0d051d38554d71ecf9f6f463e2

    condition:
        // TODO: replace with byte-level strings, pe.imphash(), or hash.sha256() checks
        // Example: pe.imphash() == "aabbccdd..."
        false  // stub – analyst must complete this rule
}
