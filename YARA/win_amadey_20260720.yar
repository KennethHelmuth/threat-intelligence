rule win_amadey_20260720
{
    meta:
        description = "Auto-generated stub for win.amadey based on 4 hashes"
        author      = "ti-pipeline (auto-generated)"
        date        = "2026-07-20"
        version     = "1.0"
        source      = "ThreatFox"
        family      = "win.amadey"
        hash_count  = "4"

    strings:
        // Hashes (SHA-256) – reference only; add byte-strings/imphash conditions below
        // e85149704da6ee8f9bc1c55304c560d1a792180489d4859a64cf0a4e056ccf52
        // f8e68cddf13a94d821a4b265172a0e32
        // 5d11d7b9b175695c197014bc6aa2fbdb
        // a86c023a02f1454738b39f753f50777c238b4ea296ffc76cd41c3059f216be10

    condition:
        // TODO: replace with byte-level strings, pe.imphash(), or hash.sha256() checks
        // Example: pe.imphash() == "aabbccdd..."
        false  // stub – analyst must complete this rule
}
