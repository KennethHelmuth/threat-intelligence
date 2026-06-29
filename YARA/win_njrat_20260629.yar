rule win_njrat_20260629
{
    meta:
        description = "Auto-generated stub for win.njrat based on 4 hashes"
        author      = "ti-pipeline (auto-generated)"
        date        = "2026-06-29"
        version     = "1.0"
        source      = "ThreatFox"
        family      = "win.njrat"
        hash_count  = "4"

    strings:
        // Hashes (SHA-256) – reference only; add byte-strings/imphash conditions below
        // 390929763242f8f854188b405ac7f5ba
        // 39cbd2d2299ebbc1eba6bb1ffab7d87f0016715fb237d0a1a253262b4b9cea13
        // 193177af43f8f24851b76d2866a11e1f
        // cd1ab1369c5b2090a046e27574158e038fabdabc695623b3e85810246990e351

    condition:
        // TODO: replace with byte-level strings, pe.imphash(), or hash.sha256() checks
        // Example: pe.imphash() == "aabbccdd..."
        false  // stub – analyst must complete this rule
}
