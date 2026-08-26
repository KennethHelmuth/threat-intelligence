rule win_amadey_20260826
{
    meta:
        description = "Auto-generated stub for win.amadey based on 2 hashes"
        author      = "ti-pipeline (auto-generated)"
        date        = "2026-08-26"
        version     = "1.0"
        source      = "ThreatFox"
        family      = "win.amadey"
        hash_count  = "2"

    strings:
        // Hashes (SHA-256) – reference only; add byte-strings/imphash conditions below
        // 9b93fde0cd1f8252a2abf2239ae56f9d
        // 0ebd28830251fc40845f4201396c683b0026828f3dc25873abdb6feac66820ad

    condition:
        // TODO: replace with byte-level strings, pe.imphash(), or hash.sha256() checks
        // Example: pe.imphash() == "aabbccdd..."
        false  // stub – analyst must complete this rule
}
