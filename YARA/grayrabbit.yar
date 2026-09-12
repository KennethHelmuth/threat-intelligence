rule grayrabbit
{
    meta:
        description = "Auto-generated stub for grayrabbit based on 3 hashes"
        author      = "ti-pipeline (auto-generated)"
        date        = "2026-09-12"
        version     = "1.0"
        source      = "OTX"
        family      = "grayrabbit"
        hash_count  = "3"

    strings:
        // Hashes (SHA-256) – reference only; add byte-strings/imphash conditions below
        // 29c7ee41d0cc9e07d981e451df56d0c3d37c41ac4ec10c7b516cc033ee397a63
        // 749160a2f20f82744026719cf72e483595c6aad718efa74d675a98662e02422e
        // d7a3c7eb94edc0e020f74c678743d71d61e944634aade4a67a96c3589e828b3a

    condition:
        // TODO: replace with byte-level strings, pe.imphash(), or hash.sha256() checks
        // Example: pe.imphash() == "aabbccdd..."
        false  // stub – analyst must complete this rule
}
