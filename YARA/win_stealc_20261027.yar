rule win_stealc_20261027
{
    meta:
        description = "Auto-generated stub for win.stealc based on 4 hashes"
        author      = "ti-pipeline (auto-generated)"
        date        = "2026-10-27"
        version     = "1.0"
        source      = "ThreatFox"
        family      = "win.stealc"
        hash_count  = "4"

    strings:
        // Hashes (SHA-256) – reference only; add byte-strings/imphash conditions below
        // baaadd859d1ab4142442003a80681dfa8ac306038de626f383e0110fd656c3b4
        // d2e3dcdcc038fff84849a359b18281d1
        // abc580ad3860919a5b2cdd8d9f48cbaa
        // f59012e49f2e8fd657a11cf2008fe74ca289d189552e29cdc3d1078956ad0d31

    condition:
        // TODO: replace with byte-level strings, pe.imphash(), or hash.sha256() checks
        // Example: pe.imphash() == "aabbccdd..."
        false  // stub – analyst must complete this rule
}
