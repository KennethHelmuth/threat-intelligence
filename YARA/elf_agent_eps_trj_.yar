rule elf_agent_eps_trj_
{
    meta:
        description = "Auto-generated stub for elf:agent-eps_[trj] based on 7 hashes"
        author      = "ti-pipeline (auto-generated)"
        date        = "2026-08-11"
        version     = "1.0"
        source      = "MalwareBazaar"
        family      = "elf:agent-eps_[trj]"
        hash_count  = "7"

    strings:
        // Hashes (SHA-256) – reference only; add byte-strings/imphash conditions below
        // 0c411bf6df62ee8383027f24000510220b4fff2a806a36296bf7cda699540b95
        // cc589f2eea34d1a4d17b141d63d3bdeb215232823d6a4f3a379e34c27fce4140
        // 60c2382b1db5293458a0a40089926a0c8d1fb715703a294085ce3a7cb555ab7f
        // 388f63f0eb52acdcf3bba77ec0c470139b5a24b17ba22be2510d3166d739be56
        // 0e3a78094c70edeaa6c07fcc4c874f4d1a42ff8e9f1a3870e9fad4ead8ecc46a
        // c23fff87e5ab3227d638073b8624c258e91849f11dbb8d8edb35c01a2c4711f1
        // b38e430116c0c1a0763055bcdc6e2aa84b96523c9854ca62b46394e8666c7927

    condition:
        // TODO: replace with byte-level strings, pe.imphash(), or hash.sha256() checks
        // Example: pe.imphash() == "aabbccdd..."
        false  // stub – analyst must complete this rule
}
