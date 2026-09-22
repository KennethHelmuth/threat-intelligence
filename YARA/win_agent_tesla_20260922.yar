rule win_agent_tesla_20260922
{
    meta:
        description = "Auto-generated stub for win.agent_tesla based on 6 hashes"
        author      = "ti-pipeline (auto-generated)"
        date        = "2026-09-22"
        version     = "1.0"
        source      = "ThreatFox"
        family      = "win.agent_tesla"
        hash_count  = "6"

    strings:
        // Hashes (SHA-256) – reference only; add byte-strings/imphash conditions below
        // 89c1a2c27470e898513e95d6175c382cd5a33fd6a509cde700b213214ecf0b80
        // 9a3d0e61430550fc5f788c7cef6c1644
        // 6214f3fcc00cd747d244f0e2ab635618
        // c65486c9a6e7ad11cf87ed332d09a70e613ec18805851609b6abde5b618a479c
        // 5395d02944c8a772316499b75d62a25e
        // cd779076639126e20c3a7f2db656f376977953493fa33cc1ac232c4631f19810

    condition:
        // TODO: replace with byte-level strings, pe.imphash(), or hash.sha256() checks
        // Example: pe.imphash() == "aabbccdd..."
        false  // stub – analyst must complete this rule
}
