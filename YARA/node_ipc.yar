rule node_ipc
{
    meta:
        description = "Auto-generated stub for node-ipc based on 5 hashes"
        author      = "ti-pipeline (auto-generated)"
        date        = "2026-06-20"
        version     = "1.0"
        source      = "OTX"
        family      = "node-ipc"
        hash_count  = "5"

    strings:
        // Hashes (SHA-256) – reference only; add byte-strings/imphash conditions below
        // 96097e0612d9575cb133021017fb1a5c68a03b60f9f3d24ebdc0e628d9034144
        // 78a82d93b4f580835f5823b85a3d9ee1f03a15ee6f0e01b4eac86252a7002981
        // c2f4dc64aec4631540a568e88932b61daebbfb7e8281b812fa01b7215f9be9ea
        // 449e4265979b5fdb2d3446c021af437e815debd66de7da2fe54f1ad93cbcc75e
        // bf9d8c0c3ed3ceaa831a13de27f1b1c7c7b7f01d2db4103bfdba4191940b0301

    condition:
        // TODO: replace with byte-level strings, pe.imphash(), or hash.sha256() checks
        // Example: pe.imphash() == "aabbccdd..."
        false  // stub – analyst must complete this rule
}
