rule elf_gobrat
{
    meta:
        description = "Auto-generated stub for elf.gobrat based on 2 hashes"
        author      = "ti-pipeline (auto-generated)"
        date        = "2026-08-16"
        version     = "1.0"
        source      = "ThreatFox"
        family      = "elf.gobrat"
        hash_count  = "2"

    strings:
        // Hashes (SHA-256) – reference only; add byte-strings/imphash conditions below
        // 1182e436076f313fb9f22b4cf27918570c50d0ec90fc10d6383a1e86448d68d5
        // 78cfe8bfbdad19f3afb54cd12d949db4

    condition:
        // TODO: replace with byte-level strings, pe.imphash(), or hash.sha256() checks
        // Example: pe.imphash() == "aabbccdd..."
        false  // stub – analyst must complete this rule
}
