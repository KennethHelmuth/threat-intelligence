rule win_orcus_rat
{
    meta:
        description = "Auto-generated stub for win.orcus_rat based on 4 hashes"
        author      = "ti-pipeline (auto-generated)"
        date        = "2026-06-23"
        version     = "1.0"
        source      = "ThreatFox"
        family      = "win.orcus_rat"
        hash_count  = "4"

    strings:
        // Hashes (SHA-256) – reference only; add byte-strings/imphash conditions below
        // a65959f323391321beba89312391a706
        // 8208dedd51639c570af2d9fc3388cfb3320505618700a843a0d6544bee88dac0
        // 286ab1c862a170f4ccdba9ee6b870445
        // d41252ddc4fab7295681019cfb2f1c1e899e2f480c306bfad78b24c38165a807

    condition:
        // TODO: replace with byte-level strings, pe.imphash(), or hash.sha256() checks
        // Example: pe.imphash() == "aabbccdd..."
        false  // stub – analyst must complete this rule
}
