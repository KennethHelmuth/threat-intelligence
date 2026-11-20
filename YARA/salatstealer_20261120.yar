rule salatstealer_20261120
{
    meta:
        description = "Auto-generated stub for salatstealer based on 2 hashes"
        author      = "ti-pipeline (auto-generated)"
        date        = "2026-11-20"
        version     = "1.0"
        source      = "MalwareBazaar"
        family      = "salatstealer"
        hash_count  = "2"

    strings:
        // Hashes (SHA-256) – reference only; add byte-strings/imphash conditions below
        // 8c206b4b74a93d26a037cd9020c81d6bb2f04e27bc477a5c36ca4861535fda8f
        // 0ebf9eb07266aada0469ba738447f8243f3aa53278488b19e3737a2e548f2539

    condition:
        // TODO: replace with byte-level strings, pe.imphash(), or hash.sha256() checks
        // Example: pe.imphash() == "aabbccdd..."
        false  // stub – analyst must complete this rule
}
