rule win_dyepack
{
    meta:
        description = "Auto-generated stub for win.dyepack based on 2 hashes"
        author      = "ti-pipeline (auto-generated)"
        date        = "2026-06-26"
        version     = "1.0"
        source      = "ThreatFox"
        family      = "win.dyepack"
        hash_count  = "2"

    strings:
        // Hashes (SHA-256) – reference only; add byte-strings/imphash conditions below
        // 144a0a499e007931628c98f38929466f
        // 0dc0fa727f900ed5033f46f8ba6cf2d97d20ab95fd334cabc0f216da6e0622b0

    condition:
        // TODO: replace with byte-level strings, pe.imphash(), or hash.sha256() checks
        // Example: pe.imphash() == "aabbccdd..."
        false  // stub – analyst must complete this rule
}
