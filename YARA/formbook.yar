rule formbook
{
    meta:
        description = "Auto-generated stub for formbook based on 1 hashes"
        author      = "ti-pipeline (auto-generated)"
        date        = "2026-09-21"
        version     = "1.0"
        source      = "MalwareBazaar"
        family      = "formbook"
        hash_count  = "1"

    strings:
        // Hashes (SHA-256) – reference only; add byte-strings/imphash conditions below
        // 30e5af4d627069f7c7cf541a309bdd30050cf6f21232e6ad2aeeb4210053b8a9

    condition:
        // TODO: replace with byte-level strings, pe.imphash(), or hash.sha256() checks
        // Example: pe.imphash() == "aabbccdd..."
        false  // stub – analyst must complete this rule
}
