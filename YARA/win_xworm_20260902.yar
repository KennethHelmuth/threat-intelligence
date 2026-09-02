rule win_xworm_20260902
{
    meta:
        description = "Auto-generated stub for win.xworm based on 2 hashes"
        author      = "ti-pipeline (auto-generated)"
        date        = "2026-09-02"
        version     = "1.0"
        source      = "ThreatFox"
        family      = "win.xworm"
        hash_count  = "2"

    strings:
        // Hashes (SHA-256) – reference only; add byte-strings/imphash conditions below
        // 3ef284d34290f2f784e12e005c1698b5
        // eac9fafb8e19bb12618199b48c79fb94cab8e447b09973b1443464a3f13ea5ed

    condition:
        // TODO: replace with byte-level strings, pe.imphash(), or hash.sha256() checks
        // Example: pe.imphash() == "aabbccdd..."
        false  // stub – analyst must complete this rule
}
