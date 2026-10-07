rule win_agent_tesla_20261007
{
    meta:
        description = "Auto-generated stub for win.agent_tesla based on 2 hashes"
        author      = "ti-pipeline (auto-generated)"
        date        = "2026-10-07"
        version     = "1.0"
        source      = "ThreatFox"
        family      = "win.agent_tesla"
        hash_count  = "2"

    strings:
        // Hashes (SHA-256) – reference only; add byte-strings/imphash conditions below
        // fd0d23011657d0185f6e4fb5fe57eb7894c9fc606b9ae5fc6b977efcb2ef1eeb
        // 00b61ee4c9907cb2dc9daadeacaa3e05

    condition:
        // TODO: replace with byte-level strings, pe.imphash(), or hash.sha256() checks
        // Example: pe.imphash() == "aabbccdd..."
        false  // stub – analyst must complete this rule
}
