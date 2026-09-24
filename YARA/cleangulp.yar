rule cleangulp
{
    meta:
        description = "Auto-generated stub for cleangulp based on 4 hashes"
        author      = "ti-pipeline (auto-generated)"
        date        = "2026-09-24"
        version     = "1.0"
        source      = "OTX"
        family      = "cleangulp"
        hash_count  = "4"

    strings:
        // Hashes (SHA-256) – reference only; add byte-strings/imphash conditions below
        // 177652713dad3c128bd9195abf2b7603
        // 668aa5551315ab26b67118fbb29f8e4560a1e1af
        // 8858ea412dc306b3558885af18006c5ca24689e8875733b5e13b3c2692e603cb
        // cbeeb7dd5e89261cde032825fd10bb80bad2e3fbf5b91fdc9137ad463ffa8f21

    condition:
        // TODO: replace with byte-level strings, pe.imphash(), or hash.sha256() checks
        // Example: pe.imphash() == "aabbccdd..."
        false  // stub – analyst must complete this rule
}
