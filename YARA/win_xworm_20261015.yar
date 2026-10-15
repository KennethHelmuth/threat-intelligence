rule win_xworm_20261015
{
    meta:
        description = "Auto-generated stub for win.xworm based on 2 hashes"
        author      = "ti-pipeline (auto-generated)"
        date        = "2026-10-15"
        version     = "1.0"
        source      = "ThreatFox"
        family      = "win.xworm"
        hash_count  = "2"

    strings:
        // Hashes (SHA-256) – reference only; add byte-strings/imphash conditions below
        // ba6f71de3fb70549ae9cf7ea82268666
        // c520275b04c1fbdabdac631aaf4141cd3fd8bc485aa9cfaed7c65e7ccac12c14

    condition:
        // TODO: replace with byte-level strings, pe.imphash(), or hash.sha256() checks
        // Example: pe.imphash() == "aabbccdd..."
        false  // stub – analyst must complete this rule
}
