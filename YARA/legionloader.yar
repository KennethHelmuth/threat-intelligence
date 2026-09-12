rule legionloader
{
    meta:
        description = "Auto-generated stub for legionloader based on 5 hashes"
        author      = "ti-pipeline (auto-generated)"
        date        = "2026-09-12"
        version     = "1.0"
        source      = "OTX"
        family      = "legionloader"
        hash_count  = "5"

    strings:
        // Hashes (SHA-256) – reference only; add byte-strings/imphash conditions below
        // 0128a4b78aab83796042118ecb3e46e0
        // 27745ec8bde201e771e3f4069e887cad
        // 685b6822b0c66f4f18496eb6ce24f984
        // 8467ca57bdf6e6e94ca4e1484628b1aa
        // c4debc1b25ab67f094676ddc3195fa41

    condition:
        // TODO: replace with byte-level strings, pe.imphash(), or hash.sha256() checks
        // Example: pe.imphash() == "aabbccdd..."
        false  // stub – analyst must complete this rule
}
