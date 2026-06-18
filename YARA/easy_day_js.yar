rule easy_day_js
{
    meta:
        description = "Auto-generated stub for easy-day-js based on 5 hashes"
        author      = "ti-pipeline (auto-generated)"
        date        = "2026-06-18"
        version     = "1.0"
        source      = "OTX"
        family      = "easy-day-js"
        hash_count  = "5"

    strings:
        // Hashes (SHA-256) – reference only; add byte-strings/imphash conditions below
        // 221c45a790dec2a296af57969e1165a16f8f49733aeab64c0bbd768d9943badf
        // 9570f77a5e1511869f4e554e7166df9fde081f2583e293c2569621792ed7d9c9
        // b122a9873bedf145ae2a7fd024b5f309007dbb025149f4dc4ac3f7e4f32a36a4
        // c38954e85bf5433e61e7c8f4230336695624ae88b6953afabf7bf817aa91b638
        // cdec8b20338beb708b5be8d3d7a3041a35a8b0fb92f9186262f312d55ff82066

    condition:
        // TODO: replace with byte-level strings, pe.imphash(), or hash.sha256() checks
        // Example: pe.imphash() == "aabbccdd..."
        false  // stub – analyst must complete this rule
}
