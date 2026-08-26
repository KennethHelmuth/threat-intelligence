rule win_habitsrat
{
    meta:
        description = "Auto-generated stub for win.habitsrat based on 2 hashes"
        author      = "ti-pipeline (auto-generated)"
        date        = "2026-08-26"
        version     = "1.0"
        source      = "ThreatFox"
        family      = "win.habitsrat"
        hash_count  = "2"

    strings:
        // Hashes (SHA-256) – reference only; add byte-strings/imphash conditions below
        // 676a249f36ca2fe67297e167f622679023b4f474c634c690a7db96d75a00d8ad
        // b2b14596a08d505ce385c914c6a971f8

    condition:
        // TODO: replace with byte-level strings, pe.imphash(), or hash.sha256() checks
        // Example: pe.imphash() == "aabbccdd..."
        false  // stub – analyst must complete this rule
}
