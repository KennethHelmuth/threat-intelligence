rule win_agent_tesla_20260725
{
    meta:
        description = "Auto-generated stub for win.agent_tesla based on 6 hashes"
        author      = "ti-pipeline (auto-generated)"
        date        = "2026-07-25"
        version     = "1.0"
        source      = "ThreatFox"
        family      = "win.agent_tesla"
        hash_count  = "6"

    strings:
        // Hashes (SHA-256) – reference only; add byte-strings/imphash conditions below
        // fb26fdde000d289ac423f5dd74865e43
        // 51816d9ac510766a54a0cc31569c5fd97b46742e0de82f18854ea042bfdfdf7b
        // dcdfeeea89d07b5bc81e0f61051f34c2
        // 3970af3e3ddea2312a082d7ff46fb171d2f4ad3dd5fe7038d4e8dc13265dd7dc
        // 06152fd52179cf9263e0c201d5d566d6
        // 478a9a9ebc5993baaa14c360bd1f3a8269b92571abe6613de1f457dd448c76fa

    condition:
        // TODO: replace with byte-level strings, pe.imphash(), or hash.sha256() checks
        // Example: pe.imphash() == "aabbccdd..."
        false  // stub – analyst must complete this rule
}
