rule legion_loader
{
    meta:
        description = "Auto-generated stub for legion_loader based on 3 hashes"
        author      = "ti-pipeline (auto-generated)"
        date        = "2026-08-07"
        version     = "1.0"
        source      = "OTX"
        family      = "legion_loader"
        hash_count  = "3"

    strings:
        // Hashes (SHA-256) – reference only; add byte-strings/imphash conditions below
        // f40c47b9d68ea251957b705c851a6ee9
        // 67ef6e09000a5ae837faecd579deb331035d6717
        // 87b8b76762eac941c562c6c8eefb8402f48fc70fcfe360a274b12e75dd5726e2

    condition:
        // TODO: replace with byte-level strings, pe.imphash(), or hash.sha256() checks
        // Example: pe.imphash() == "aabbccdd..."
        false  // stub – analyst must complete this rule
}
