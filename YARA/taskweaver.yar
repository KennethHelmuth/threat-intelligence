rule taskweaver
{
    meta:
        description = "Auto-generated stub for taskweaver based on 2 hashes"
        author      = "ti-pipeline (auto-generated)"
        date        = "2026-07-01"
        version     = "1.0"
        source      = "OTX"
        family      = "taskweaver"
        hash_count  = "2"

    strings:
        // Hashes (SHA-256) – reference only; add byte-strings/imphash conditions below
        // 00cc86d1144020c24c8fbb3a8dc6b908926497ebd23be3bf854360f93d1c8f4c
        // f4a72600a3735c2a4d843875ea61bbb6f935a1af51a81f2fbc992ce11ba94afc

    condition:
        // TODO: replace with byte-level strings, pe.imphash(), or hash.sha256() checks
        // Example: pe.imphash() == "aabbccdd..."
        false  // stub – analyst must complete this rule
}
