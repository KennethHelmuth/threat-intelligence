rule elf_sshdoor_20261113
{
    meta:
        description = "Auto-generated stub for elf.sshdoor based on 1 hashes"
        author      = "ti-pipeline (auto-generated)"
        date        = "2026-11-13"
        version     = "1.0"
        source      = "ThreatFox"
        family      = "elf.sshdoor"
        hash_count  = "1"

    strings:
        // Hashes (SHA-256) – reference only; add byte-strings/imphash conditions below
        // 6e6c1919fe960ccc265806de831006a68713ced68b4dd6ea3f59cdbe4dfa79fd

    condition:
        // TODO: replace with byte-level strings, pe.imphash(), or hash.sha256() checks
        // Example: pe.imphash() == "aabbccdd..."
        false  // stub – analyst must complete this rule
}
