rule xloader
{
    meta:
        description = "Auto-generated stub for xloader based on 23 hashes"
        author      = "ti-pipeline (auto-generated)"
        date        = "2026-11-05"
        version     = "1.0"
        source      = "OTX"
        family      = "xloader"
        hash_count  = "23"

    strings:
        // Hashes (SHA-256) – reference only; add byte-strings/imphash conditions below
        // d447a06cba8d3dbe80e09d73dd64576836b258961ee0d3ba56cf26cea7962b49
        // c2ef25f1a7c739805c7f01e54e20ab89
        // 79cd5ac780df8c96e67b42749ceb750b2d54f9bd
        // 08aadfcffb61f90b0d3b34758048e0f699f241216d164c82919a6934488a52e9
        // 46e8d2bd454926641176ea67b2e357089ff411c89e524def0158a04b6103d7d4
        // 33dbb7d0c78bfa2e124b78409ecc7152a80016bbcccf39e960a2790d1efb8a22
        // 7675b38aabebc8427171447edd484b5b
        // 145c72f8acdcd366869f955dffd000d3bc146b6e
        // 93d2a83d9b1440fd27d7722fe6aeafc2
        // a302e6d2cb4e97fcdd352ac51606583b748d4f82
        // 14a1a43ccad9a37fcc91d886cc3651a5
        // 8e8c94ad10d201b7d3085d4dbcf7a309b1c3f93a
        // 6d7aaf1e563032ba46d8e0f1c8eab2b91d383fb2e5d00a1d4fff891f78a3572b
        // 78f08bdefb127c96a64229b591de7b3f984a451796ad132cb26ff54c76d073d4
        // e834ea9cd3025f8070778cf7ef8219976568cc28085feaf974912b64e5b77bc8
        // 685c989f4d89b2402c167075d5d6d6e1f4573c0450adc1de3d8c08c65ed8ee9f
        // d87299e4a6457caccb6960c351003cb109748be9ab378cf31611461fce30ac28
        // 05ecf6621bc2f2303db6bab33cdc231cb1cd08895b4d089f7410b98b21c38c24
        // 78cb203de34c4a4c1961fe0e3700e6c76ab9b8b71dae9e2de408197fbc82733e
        // 896a4ddd93ab1d6fda5d57e71c5b2cf5db32970093350a1111396b2e80dc6686
        // be40d790d265afba64626b4e10fa2ff06e80119eb0056974407cf7d8e834745e
        // 21eb09400f387066649bec4c7fa63e4d4fd2171fb21a2b2ba182941325d76205
        // 38a498b126f8fc799a4f36f37b6d955fba6410d7eb02a9922eb21767897a8769

    condition:
        // TODO: replace with byte-level strings, pe.imphash(), or hash.sha256() checks
        // Example: pe.imphash() == "aabbccdd..."
        false  // stub – analyst must complete this rule
}
