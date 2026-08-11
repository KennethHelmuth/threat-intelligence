rule win_formbook_20260811
{
    meta:
        description = "Auto-generated stub for win.formbook based on 6 hashes"
        author      = "ti-pipeline (auto-generated)"
        date        = "2026-08-11"
        version     = "1.0"
        source      = "ThreatFox"
        family      = "win.formbook"
        hash_count  = "6"

    strings:
        // Hashes (SHA-256) – reference only; add byte-strings/imphash conditions below
        // a02aa86b025c34615a99437e118128fe
        // bbb3837bc8706b87668877a86fcda6a69ace99739e19caa744bef624570a7c0a
        // 5d8353255bc5b09aaed218f2d6f016ceda78354cfb1a3f0d36d939d142f3a8f2
        // 59e90d4e4072484541636b873c35a4a6
        // 893cf55eb5c958896580854b7f5c44e1
        // a6a6674d13230442f10b0b6663a5e659f9d3a072b8e575fd332baa5ff685a1d6

    condition:
        // TODO: replace with byte-level strings, pe.imphash(), or hash.sha256() checks
        // Example: pe.imphash() == "aabbccdd..."
        false  // stub – analyst must complete this rule
}
