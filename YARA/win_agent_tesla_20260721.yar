rule win_agent_tesla_20260721
{
    meta:
        description = "Auto-generated stub for win.agent_tesla based on 8 hashes"
        author      = "ti-pipeline (auto-generated)"
        date        = "2026-07-21"
        version     = "1.0"
        source      = "ThreatFox"
        family      = "win.agent_tesla"
        hash_count  = "8"

    strings:
        // Hashes (SHA-256) – reference only; add byte-strings/imphash conditions below
        // 58328b7f4fecb0407da1947937b41162e23a61559d6f49526ec1683febad6ddc
        // 10cc531b5f4765f53cd3a58a2c23ffcf
        // 2112d749000ec32a1eeb719eb1e0daee69cda7946eab3049f5d2fd83bac566c2
        // d8d19575c1de6c091ebf0624596478fa
        // 791d27fd45d5ac5f25235b46547129ad
        // 940f0d74f64672c50d4b6ed704aefa743d81b7cdfbeb6666a00f690f80b7b001
        // e6290924b6e7a434776239ae19e79b02e88c3a6bef1b0e1d61041cc4176dec6e
        // a757a8b09d99acc2835fd0d26541e46c

    condition:
        // TODO: replace with byte-level strings, pe.imphash(), or hash.sha256() checks
        // Example: pe.imphash() == "aabbccdd..."
        false  // stub – analyst must complete this rule
}
