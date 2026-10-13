rule netscaler
{
    meta:
        description = "Auto-generated stub for netscaler based on 4 hashes"
        author      = "ti-pipeline (auto-generated)"
        date        = "2026-10-13"
        version     = "1.0"
        source      = "OTX"
        family      = "netscaler"
        hash_count  = "4"

    strings:
        // Hashes (SHA-256) – reference only; add byte-strings/imphash conditions below
        // ae22ef2517b5c0fb47f78745b9cb5260acee0e751b89bcd354640ff8bc8d29ec
        // 79c65fa04541032e251fa4796b97800374b63c7982593dd1a2e0db605d429186
        // 1bd314b661396c7086f6367fbbb48025e03ca2de69c073d53a8b0a38aa5fbb7d
        // 7489a0f93c67fa5cdaeb4b921d90594d

    condition:
        // TODO: replace with byte-level strings, pe.imphash(), or hash.sha256() checks
        // Example: pe.imphash() == "aabbccdd..."
        false  // stub – analyst must complete this rule
}
