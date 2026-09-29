rule elf_sshdoor
{
    meta:
        description = "Auto-generated stub for elf.sshdoor based on 1 hashes"
        author      = "ti-pipeline (auto-generated)"
        date        = "2026-09-29"
        version     = "1.0"
        source      = "ThreatFox"
        family      = "elf.sshdoor"
        hash_count  = "1"

    strings:
        // Hashes (SHA-256) – reference only; add byte-strings/imphash conditions below
        // ab69ef32017a5365ee0e7faca03e1352382865c5672e989d99d2d77ec91c33ef

    condition:
        // TODO: replace with byte-level strings, pe.imphash(), or hash.sha256() checks
        // Example: pe.imphash() == "aabbccdd..."
        false  // stub – analyst must complete this rule
}
