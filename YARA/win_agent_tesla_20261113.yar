rule win_agent_tesla_20261113
{
    meta:
        description = "Auto-generated stub for win.agent_tesla based on 5 hashes"
        author      = "ti-pipeline (auto-generated)"
        date        = "2026-11-13"
        version     = "1.0"
        source      = "ThreatFox"
        family      = "win.agent_tesla"
        hash_count  = "5"

    strings:
        // Hashes (SHA-256) – reference only; add byte-strings/imphash conditions below
        // b834bc2a2c14ad7ae30043fcb1f53a78f7cc069bb93c7e903006eb183c446222
        // 7ad0210242fdce5b7617f0a79069e85541f6eb0c798c5d888141dde2e07f065b
        // 3a5492b2b40df6cd1bf5382bc8016490
        // 271c82fcedf35dcd77ddafbfdd11ce1d
        // 26400d63a755cae8ae5516f556910d7ce74577aedbbe11ec0b9906e0f96d23a8

    condition:
        // TODO: replace with byte-level strings, pe.imphash(), or hash.sha256() checks
        // Example: pe.imphash() == "aabbccdd..."
        false  // stub – analyst must complete this rule
}
