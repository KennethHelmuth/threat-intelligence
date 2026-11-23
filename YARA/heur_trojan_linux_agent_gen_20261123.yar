rule heur_trojan_linux_agent_gen_20261123
{
    meta:
        description = "Auto-generated stub for heur:trojan_linux_agent_gen based on 3 hashes"
        author      = "ti-pipeline (auto-generated)"
        date        = "2026-11-23"
        version     = "1.0"
        source      = "MalwareBazaar"
        family      = "heur:trojan_linux_agent_gen"
        hash_count  = "3"

    strings:
        // Hashes (SHA-256) – reference only; add byte-strings/imphash conditions below
        // 791b169be1f2e5dadf8a2b5b0a86c973a1fa6318959ac9d3824c654411ee1adc
        // dd66ee61c603e8500b9dd94f6ea05e9a9cc92c5f19f12775ff0449d4d38fa267
        // b457bcec64d9ce0a66c5fe2bd4e09a7109a0e01eccd37bc91b3c4b9da5fd78da

    condition:
        // TODO: replace with byte-level strings, pe.imphash(), or hash.sha256() checks
        // Example: pe.imphash() == "aabbccdd..."
        false  // stub – analyst must complete this rule
}
