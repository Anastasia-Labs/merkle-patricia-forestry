use aiken/cbor
use aiken/collection/list
use aiken/fuzz
use aiken/merkle_patricia_forestry.{
  Branch, Fork, Leaf, MerklePatriciaForestry, Neighbor, Proof, ProofStep,
} as mpf

// -----------------------------------------------------------------------------
// ------------------------------------------------------------------ Regression
// -----------------------------------------------------------------------------

test phil() {
  let proof =
    [
      Branch {
        skip: 0,
        neighbors: #"d0feb802cc999c500ec58b8e78bdb1b11bcb8e217d404c2cfb416669a6b2c240cd0c58152bf064f0c7834dd72f69d12651739b32caaa3c986a87937f125b500f1426fccf2a456bce3c25b43206d9b429d56515580d086a959ca730325411b3aada6ac4d7221f787b97e1ce677fdadc412e824a9816281b1259b91addeb37bb2c",
      },
      Branch {
        skip: 0,
        neighbors: #"098745f495c99b7627f559ac8ed8165e2392e2261ef8990291f13705adf78fcf3dcca881d4b45aabe746e7041f743baaa831029e7890df9587858d8be5dce648e02f31fe2936417a393df8def15d7d0c021a66cdb33c3fdda941ae70614913cb116fd5e6c499b71e229b88f5106975cbe83a8c44d3619541d7ddd7eae0a355bc",
      },
      Branch {
        skip: 0,
        neighbors: #"9732c3266e468dd27c4bd16af5a6e60c1f556bf91700f51554cfa33aa26b8d30f33c27ab7c5c85ef006c78f56ecd7e8c77c5fadd7910e9b178801d554f244977026104fc4aede0864d405db792691c4e4534b06ae7f58366b640f13ecfa549afa046a157d2e9b6c0793a506942eb8ff50dfeb7c5e7a2a51814c4b3a4d6af6fa0",
      },
      Branch {
        skip: 0,
        neighbors: #"5f3065e998b5fa89bb33d9204546c5dba2b075adc542688dcc1773a490fa739ac69ff52c5f575e9f1912664c1ebef2f9498775350b0077a6b59fe012861c3715657146a239aaea12b3091054e5846771bba6f721b1835d025fa08d1fc5c9b1c40000000000000000000000000000000000000000000000000000000000000000",
      },
      Leaf {
        skip: 1,
        key: #"2b5b0ba7a99e17d9fde58f14dee61cccda9e3e9627b2ba2732ebed551ea9eaa4",
        value: #"3657998959985b7b75c734eb5b49d18cae9b353d00d811cb2c24ed6ed17b23d9",
      },
      Leaf {
        skip: 0,
        key: #"2b5b063719f4b7644c71adef1439c9aa78d34e684677dd61db0adffcc21797ec",
        value: #"4e397303e05277d98701446ee62f6f02bc013721fc12efba7300fb51ea935f9f",
      },
    ]

  let new_root =
    mpf.insert(
      mpf.from_root(
        #"409bc367bec001f8c8af45fb86239d1f69763cb86e8e134c66bba15426cf176e",
      ),
      #"198d70e41146654a69e08c6682310a8c35816c8584431915a0eee4a62d39eda0",
      #"9e36f867a374be",
      proof,
    )

  new_root == mpf.from_root(
    #"1adf5b1386283988008cddb9126063d9c7e25851b73157cc10f71545083cc8ab",
  )
}

const edge_case_proof8: Proof =
  [
    Branch {
      skip: 0,
      neighbors: #"dd79d1a4980ff4ab374d6ed011b6a9b963fe5fd141a669fb20ef0f08250c9d928bdce2239643c187358c1abf47ae78136d7d8dce94b9c2bd22f4f3b1427c90b4aed17c11bddfc6d68b809b2de8f5129c43804516b4e6d67625c5780032dc0dad97b4d37f1699995fb7572eef017468819b948c8a16ec9732479d1d70c80996cd",
    },
    Branch {
      skip: 0,
      neighbors: #"63e2bed77aaf8034c17f5becd9d9e92c1820bd0609a0c92cf5746249270ad35ee6f92b945bbfa738a4d97409aaca86d9d44671b3da48a36dfb464501d9d147e4bffffd78b82dcef21e5d140e97318b8dfd1808014f2a02cf6057f460b203968e48554ea8b75d879edd62b154628ae8c30600b9e50434f0695ba6dd67465c8153",
    },
    Branch {
      skip: 0,
      neighbors: #"054c6807d1047ebe0b79cd7fec4b341037400ef79a30e50a81062f4a7b8df0ef7c423847528893fe54621016e0df78000987b3d47f0b43769035d3ca844ab93893146efd718347306d9c6699a27db53997c1a06d89ad7fc741a615cf6848c1eb2e83ea7273c04abfabca2cce83614304df0c68d0189764d9f6ba29e9091404f9",
    },
    Fork {
      skip: 1,
      neighbor: Neighbor {
        nibble: 12,
        prefix: #"",
        root: #"cbf9b55ffdf4dbc9964cb51a01e6d66fae05bfb1704c057b8b0affb9eb8f6d3b",
      },
    },
  ]

test insert_edge_case8() {
  let trie =
    mpf.from_root(
      #"d80496796601a1cdbad2912ba69af57185738594da390f36b65e237906808a89",
    )
  let key = #"541dddfaf11096844f045f162c0d3095597a16f711432a91e36cff007665efdc"
  let value = #"272f42edb4c1c334cb38ebbe0772dc3c10"
  mpf.insert(trie, key, value, edge_case_proof8) == mpf.from_root(
    #"7143c72548c502a02fe79ee13c3672bde847adb09b3749a5cc2a5ae94c5f7b8a",
  )
}

const edge_case_proof7: Proof =
  [
    Branch {
      skip: 0,
      neighbors: #"7391436705a8141e333c007c5ea3e046f9b6ce3200988f4323b337f1eb4e476e300fc77899d6c430dc56965b5171ed48ae947e00cf886ed36bd508f01ecdcfd0a61383bae3451edfa124b8b4a0d6a36f9634c9dcdb9684492bc1f1962a38247ba4ea8e58b84473436d6b6fc5fd47a3abef4959544f8e57bc62ba48131198e476",
    },
    Branch {
      skip: 0,
      neighbors: #"a8c0876243c8203192c45e572b91b84654915f3015e99fbf2a50d2d48bbdacf73a1077fa66a5e7159d0971ce3192d128158480293bd98923ea6614f444c91684b55f810f03a8a710183c7ffff4272817d630c6ffae2600accdedc9f656fa9283571838701edb01d0ec362c174d12243a426af448fb909d32ed51d8641c3a43b0",
    },
    Branch {
      skip: 0,
      neighbors: #"72302f4a439c2294ba4f6bef321f0f7bf497bb5c24335f2e1c8d0b49237410297674c4a5f9437696d4ed2145aad20cc0ef39bc139574941c9f24a4023706e7720d1a0c3d36e6748cabab8c24cb83a17b4a771f536a9fd361e1416f673ed43708b61ff685cecf3bd4a6118e3994e36e41e8dcaee8b47b2ea947968c0afca65b6e",
    },
    Branch {
      skip: 0,
      neighbors: #"f226865e02694067e1d0a17b3cb0f6c3d7e5186642a3ff1d8299573e3cac04673fced676fe9af960d3ed3d1e6138952993109b7ec62a3f38eae39fb89a06f04436b86983490a9c2488d8b690074fb3b6a487049f21b6de07dd27b8cfb6243fc3ab5d438a30e24aee9016ffb83a2c23ed7f316efac775c6c2eec64f41967e63c2",
    },
    Fork {
      skip: 1,
      neighbor: Neighbor {
        nibble: 11,
        prefix: #"0e",
        root: #"8ffc29f174b749ee61bc9048cb600b4b7b9379227cf690a9268ffa26c5973738",
      },
    },
  ]

test insert_edge_case7() {
  let trie =
    mpf.from_root(
      #"5032a544857633269c915dd4fb665d79a041d6d75ca795e24fc17a285cc1dece",
    )
  let key = #"daa708d4b3fcf81fdfb8fce2ec5ff61fa38ff02fb4f4d9a218c158b2de170b20"
  let value = #"9fb48cf6f576d74b1d7d8917"
  mpf.insert(trie, key, value, edge_case_proof7) == mpf.from_root(
    #"b4b1446e07f17da9643a597e5b3a805bc75307aec8a40edde1e41b22ffb90442",
  )
}

const edge_case_proof6: Proof =
  [
    Branch {
      skip: 0,
      neighbors: #"7e5c1b89d6ba9e8e5a012933aecd9e2e19f11294257e0e640e56c6845219261a4b1698ae92f74ac507f5680ca387481abd062fa046eb010b7b418153b9988fcf5bb476f0fc4b22846acdcf91c26b8405a09e21af7441dfe98e144b7e6f7475ce14a7917333baaf877fa3e6562e09e9e5539bb5731c89006ba3baf3317ea7cfd3",
    },
    Branch {
      skip: 0,
      neighbors: #"4945551523513a913b0c1748f0087865b5ef401247edca73d8ce823cedc62003ed7b7f4cfcedd277e93783a47475a8ec717761fbb2274bc09e00ea1a5fbcecb4b524a3388171fafdd68d4422401a634bbd85b7bab7260585112368ccb4dfcdc8470742a8dd6e058a84e82d5842ebfad6af4a0add6f167106e3c8bf8274e3f346",
    },
    Branch {
      skip: 0,
      neighbors: #"ccd2c106aeec88ac21a434fde3a80f6723bdaec66dbbf7b48798444176a66b313666175fd5c77515a487b92353e8b38975faa4fe8c781d20dbcf8e047dd4fb65ef96a189a702eba153af570fcd3fe5fcc246291520c8be76a28a513e0af3df2c1c0a21c307b69cc6de481a61fb485d0b6749347e2536c50f55ce95f4c8aeb9df",
    },
    Branch {
      skip: 0,
      neighbors: #"e6100e9747bf02da887ba2f15c77d151a6dafe424bfc2e4a575ce3be326d98938e810047967285276146d6cec58822f67af42393612eb7bf7f3419f20f7ddaab74699bfa72ad77a7e24e80960c3913a02dbc1300aedf4efef7448a1817eaaac0739f0ca36791ab54cb58545461e737e19eda3fddcbb16f771b28987206f90778",
    },
    Branch {
      skip: 0,
      neighbors: #"13e7ec23fb284cde60f0c5434f220256c0fcab29390bbb44be517239f63739e093b12de2213d6991bfed2f7a7a9204382975b655347e1b3c22fb35791a3ab6f60eb923b0cbd24df54401d998531feead35a47a99f4deed205de4af81120f9761807800df400ecd72d0f96b90289c6c9e30745c0f0f1b87dda505807bf113cd18",
    },
    Fork {
      skip: 1,
      neighbor: Neighbor {
        nibble: 9,
        prefix: #"0c",
        root: #"03be633c718bddfa31a6cc2988f933a12fe3d630ce46981090a673023c550a75",
      },
    },
  ]

test insert_edge_case6() {
  let trie =
    mpf.from_root(
      #"264bf8da18ca79f8da1b3907d7587a5933599c113e9fb6a43e4659dcaa7dfb14",
    )
  let key = #"5247268e194dad520a2ab88837e2c110fbe290fa3ee8e09b8fe10402b7f9e906"
  let value = #"4852f1a645b5c206f9b97f679af0e1629954f73d43080a5ebb9bf54f12131b"
  mpf.insert(trie, key, value, edge_case_proof6) == mpf.from_root(
    #"96149792c95b5da30a5c55447e652d7ca8669c8b2aec2093ceeaf0354808172e",
  )
}

const edge_case_proof5: Proof =
  [
    Branch {
      skip: 0,
      neighbors: #"83a353b3dfac1b00ec6333120a92996ce6e715029a72c9f224731b83d2d0da467dab0e24c4582fde651ef4f6fc292de9f674587c72439c2ebe10c5d8e0dd993cdb010bae8afbb2ef4563525f7f6df6250069efc4c6a7cfed090aa4de8a0b0943a9d4662d42439fdc9b0886bac8437ac6f870eb740c0aaac8900f0f07f6ca627c",
    },
    Branch {
      skip: 0,
      neighbors: #"fd83b02dec57c8d7c9c5709d216d7ece94aede0be367de0fba419efe0ea14fb5c183494e24e67b0ada22146e6c274ef2e615e31ef16a8d8e87001a3564597430615bb2668745780b8800fc1267f73736d76e804c292baf556edb21f6554b5277d6887507e528c0a75cbd0663e89ce6c1d58d425a5892588a1ad7d722c150ad35",
    },
    Branch {
      skip: 0,
      neighbors: #"fc880494853e132b1e5059ef097ac8052406e91c497a4b3220d461aebe24bc8011cb48bbb1fc48f83dcbdabacbadd5252b5a4aa9ce0cb11e469a487e5185e29a889fea6ad82b59c6b6545f1eb07ec79cef0b49996a0ed1f93b4d7e0fd19120bbced4fd32785b26b24acc48b334dc9cbb57d131811b209bd34e1c2eabdddd824b",
    },
    Branch {
      skip: 0,
      neighbors: #"2ac6a5bf86058b926969d57744a861c1ed0354e4a8597b30286da55ad65bc70888f678a79d87971609b0ebcb59957b2fb7a49b974988b622b609a172a22b07113c8d0c0385974874a96f9d2a8bf40b887f1a2770e10e2ad932452625dd092e32eeb0ecc037555a8be1b495c51f193e9e4a2b0394d508d985c368f76f41845c30",
    },
    Branch {
      skip: 0,
      neighbors: #"55b2b16593856d4f82e890477c446e0f6701065c0f8211d209e2c51ea140b4ef975439d6994d2a1320b64cd109fe3ba5f2e3cc6a1d901e18d4146c058294a0fd5199a4a23258ebe527b0f845549ae5b7c6abfb6a3ce51065788b24e0d3b6df590000000000000000000000000000000000000000000000000000000000000000",
    },
    Fork {
      skip: 1,
      neighbor: Neighbor {
        nibble: 2,
        prefix: #"06",
        root: #"afa03b4357df9c84cadd1dc8c488d01718a35f4dd467f4a9be010f09f1cfa5bc",
      },
    },
  ]

test insert_edge_case5() {
  let trie =
    mpf.from_root(
      #"7dc784628201add8ee3e19eef299af13d8be6b46189b5bfd95c8ab331e97bb00",
    )
  let key = #"e4a80cba017707ab102628bb4edd6f463ad3f5592c537c69b5d7f4f6dbae5c63"
  let value = #"61255c62f82fa03634e7f2be38b0589ed878c7293e41"
  mpf.insert(trie, key, value, edge_case_proof5) == mpf.from_root(
    #"62e1a31222df93f1e725cecea0d3429a9936a013fa9152aecdd44bc4f7a3d064",
  )
}

const edge_case_proof4: Proof =
  [
    Branch {
      skip: 0,
      neighbors: #"d072e11c4f761d09ebe0c1df54b08d398977aa4e98e85e5e231f52dc32fdf8053861a5ea164ac3eb460e27f96ba934832bfc7b240dbf7be24d3fb7ae16f3e44fa965498aa2e219f45428bafc4f646a8f2b4d863bf730f802f81f4f713a465246cd28ad53627981fd212ebec41068fa0f4b0ae5e0e77af0143e296373c6c8f753",
    },
    Branch {
      skip: 0,
      neighbors: #"6c2cf6703c1b121726899e4f1de29cf483227d9e75d5d7948b62b5904c7f1011165b8313abcd4f1c33b85a5dabf8c5096039b3aba1c1fedda2e247810090173998f6f58a03bc17874bff8ba7eda08d25623911dff348f57da60b8545044dcbb175d27abc4c3e1b9aa0a3161ea0f8067ef39885c30399c164395b181747ba4f51",
    },
    Branch {
      skip: 0,
      neighbors: #"c5b1eb4266a20e13961f0b7b8f909a217141eecab5bbe3116665e382f87477fcf9a8a6a9e1e1cb7af32d1ffdf5c70643434337c3874d417de45f83e48f7c00afaf7180e918199dde712083a3f512483e89d756f25ddafe8b14b246499fe44dd3bda1f1a580cf7af9dd35c6ddfffa2ec8af0d41b00d7ca5ed25af8e54d4bef1f9",
    },
    Fork {
      skip: 1,
      neighbor: Neighbor {
        nibble: 12,
        prefix: #"",
        root: #"136bca071d530710ba622dfd66fe1afb859d4f42d45f29ce252e862a92eb10c2",
      },
    },
  ]

test insert_edge_case4() {
  let trie =
    mpf.from_root(
      #"76ff3670f2b81017d50354ca4a78792de31adbd23f456eec41d7a8c13fcdc91b",
    )
  let key = #"04811fc306a2021340b15ce6f025db1dc3d402f0829c7ee2100ca8fdd6ed10cd"
  let value = #"0c43c3addce8b95e49eb0fb906"
  mpf.insert(trie, key, value, edge_case_proof4) == mpf.from_root(
    #"f45b9be75cbb9fa9143c249609304c246bf7d3b9457cf4af188d5de22c1a0827",
  )
}

const edge_case_proof3: Proof =
  [
    Branch {
      skip: 0,
      neighbors: #"9adb4faf00cb2666b1b18dd461cbedfeb51f2d95e4158c96c222ebe84d91391eec30cd78944a11d044682818143d22b96fc31932aa2c52e00b1888c65e56dab8a53c54b7d9170432cd45530cb4f23b20d073fceaf910c296d72446eb780b12175c057d3a7768e6460dc367abaeb396095594a6cde5068afbbbd1268c0fd36d27",
    },
    Branch {
      skip: 0,
      neighbors: #"d9701403f8a22c78d8ea0aa13580427d33a09ad207000f96d2c8cc3f9049792a17d5489236013aba204e657d142a4cc1f92b98e6d8ce31dba37eb355a98befe64a1ef3c786c8bdefff9c6ff870a6db9f86115b4760396b91abe622de3f29d85618da02ae1a2daa6ef05164669740c58d4af735eca7129a5e7b12490508eef65f",
    },
    Branch {
      skip: 0,
      neighbors: #"888502234def2d4ab5ce331577c00537350807cc6411f4a713db6e7c39da756de6665ece82216244b78d1ad2218775994977d8d8337f4d0d11d3f444b80d447373dac7d204349e68dd5d4303d169f22981d016b62d7f3295284c046b70bc87fc0000000000000000000000000000000000000000000000000000000000000000",
    },
    Fork {
      skip: 1,
      neighbor: Neighbor {
        nibble: 9,
        prefix: #"",
        root: #"34b8236af8370a93aa648a541efebae35dec9488f6160e324e656af0be5d374a",
      },
    },
  ]

test insert_edge_case3() {
  let trie =
    mpf.from_root(
      #"6544f125947f9b41d6e6ad0560f7174836d987fdb404df3f379985a2f661e4b9",
    )
  let key = #"497f99bb7565d7be2828f6580161cd27cdf8f56418adde5be871b6d0a447da15"
  let value = #"85ff67896b3cc0f2c866bef1c51e6c00055d059cd00067c10a49c74d24277c"
  mpf.insert(trie, key, value, edge_case_proof3) == mpf.from_root(
    #"5556e0ab2ba4be2ce33369cf3babb25fc3c1ce01e1c5426ef1ae409e43fc21a5",
  )
}

const edge_case_proof2: Proof =
  [
    Branch {
      skip: 0,
      neighbors: #"4c54bfc322fb7bc2e49ae21bf5fa560632e3ca42b5267eb115142e291e8ada4ecd0c58152bf064f0c7834dd72f69d12651739b32caaa3c986a87937f125b500f1426fccf2a456bce3c25b43206d9b429d56515580d086a959ca730325411b3aada6ac4d7221f787b97e1ce677fdadc412e824a9816281b1259b91addeb37bb2c",
    },
    Branch {
      skip: 0,
      neighbors: #"098745f495c99b7627f559ac8ed8165e2392e2261ef8990291f13705adf78fcf3dcca881d4b45aabe746e7041f743baaa831029e7890df9587858d8be5dce648e02f31fe2936417a393df8def15d7d0c021a66cdb33c3fdda941ae70614913cb116fd5e6c499b71e229b88f5106975cbe83a8c44d3619541d7ddd7eae0a355bc",
    },
    Branch {
      skip: 0,
      neighbors: #"9732c3266e468dd27c4bd16af5a6e60c1f556bf91700f51554cfa33aa26b8d30f33c27ab7c5c85ef006c78f56ecd7e8c77c5fadd7910e9b178801d554f244977026104fc4aede0864d405db792691c4e4534b06ae7f58366b640f13ecfa549afa046a157d2e9b6c0793a506942eb8ff50dfeb7c5e7a2a51814c4b3a4d6af6fa0",
    },
    Branch {
      skip: 0,
      neighbors: #"5f3065e998b5fa89bb33d9204546c5dba2b075adc542688dcc1773a490fa739ac69ff52c5f575e9f1912664c1ebef2f9498775350b0077a6b59fe012861c3715657146a239aaea12b3091054e5846771bba6f721b1835d025fa08d1fc5c9b1c40000000000000000000000000000000000000000000000000000000000000000",
    },
    Leaf {
      skip: 1,
      key: #"2b5b0ba7a99e17d9fde58f14dee61cccda9e3e9627b2ba2732ebed551ea9eaa4",
      value: #"3657998959985b7b75c734eb5b49d18cae9b353d00d811cb2c24ed6ed17b23d9",
    },
    Leaf {
      skip: 0,
      key: #"2b5b063719f4b7644c71adef1439c9aa78d34e684677dd61db0adffcc21797ec",
      value: #"4e397303e05277d98701446ee62f6f02bc013721fc12efba7300fb51ea935f9f",
    },
  ]

test insert_edge_case2() {
  let trie =
    mpf.from_root(
      #"00489b47aa866ff55da4f24fa4801a6948871258fab39f22354f35b7c4f94412",
    )
  let key = #"198d70e41146654a69e08c6682310a8c35816c8584431915a0eee4a62d39eda0"
  let value = #"9e36f867a374be"
  mpf.insert(trie, key, value, edge_case_proof2) == mpf.from_root(
    #"32d3876da6fa1482070142b0dad6be6e37ba9aa6131e9ba37e4aca3299829bbd",
  )
}

const edge_case_proof1: Proof =
  [
    Branch {
      skip: 0,
      neighbors: #"6da036230d1cdb614137b0d5a94bfe0350eae80a7a6228e1ada0025b3c4f7b7b5527cc2fa7d7d50e6059ef33bb9d71f4135265d016affaaebc48465275528b4cc47a765a2d0a90fa7efe6c4c2afb227f8fafa193d16b98afd8e0536d8f07beef9c989638ac0ebb91ce40562b449f66d80119354630bfbd3d1f51db2369a10c7b",
    },
    Branch {
      skip: 0,
      neighbors: #"d1672f79764d1e73c9784121bfcc4b77a043dd07d5769c9a041b04f421572cddb53b70e36b1ae1568c438bdd94eb7d209973e669639bf970b2356b98f4f23bbc66a5aeefc3e6796bd5559a1eba9e61a86eab048c18ec8f93a787c8ea7893c010828b7a5a3d83c8f64471a9a93a606591c3823f9b718870d1bb30f99e38cbac9b",
    },
    Branch {
      skip: 0,
      neighbors: #"dca400d830a111355a23e3c85ebccb507a7150bc26a259fce184ce63b0ec917ce2d43e656aafa0f3de6381d4c0ef65a76c263598eaf76156819bd2c321504d808b0dbee17ff39324bb913eecd66b8f49238000c1d0c22af719d51fe0f676d23e0000000000000000000000000000000000000000000000000000000000000000",
    },
    Leaf {
      skip: 1,
      key: #"5080c2f95315f3ef1f89304d94651f0f8ae2f80daa5cff26b9a7fd27813eae0b",
      value: #"0e5751c026e543b2e8ab2eb06099daa1d1e5df47778f7787faab45cdf12fe3a8",
    },
    Leaf {
      skip: 0,
      key: #"508010f4051f83d17de96eab544cd32a977e88fbe5a4b3b1274b11cce8aaf642",
      value: #"0e5751c026e543b2e8ab2eb06099daa1d1e5df47778f7787faab45cdf12fe3a8",
    },
  ]

test insert_edge_case1() {
  let trie =
    mpf.from_root(
      #"99286f8457f09a03965dd39ff8a9793cc049974aad98e3e97955b939bb9b2b9f",
    )
  let key = #"3fe6f46456b9c223116533d90f9b0bf7c5da095e0c1d68af297a2a3c9709bfa7"
  let value = #""
  mpf.insert(trie, key, value, edge_case_proof1) == mpf.from_root(
    #"d8363eaa94dc21254e63ae623649d38aa8feb0ee8cb5bb3978aa7820373624b7",
  )
}

// -----------------------------------------------------------------------------
// ---------------------------------------------------------------------- fruits
// -----------------------------------------------------------------------------

/// An example trie made from a list of fruits.
///
///   ╔═══════════════════════════════════════════════════════════════════╗
///   ║ #6e9e11c15686694fbec2e1e685e2aa3f2bb402ab955d02ebbc2a5ec1fc69093b ║
///   ╚═══════════════════════════════════════════════════════════════════╝
///    ┌─ 0 #520a7f805c5f
///    │  ├─ 389fd..[54 digits]..1abc #56408b9882f8 { mango[uid: 0] → 🥭 }
///    │  └─ 9d230..[54 digits]..9ecc #9ca49c0d73d5 { lemon[uid: 0] → 🍋 }
///    ├─ 16a4 #f8f1111fd89c
///    │  ├─ 3a30b..[51 digits]..a968 #ad0fd8a65153 { cherry[uid: 0] → 🍒 }
///    │  ├─ 8584c..[51 digits]..d4a5 #444019eac1ee { tomato[uid: 83468] → 🍅 }
///    │  └─ b7ce0..[51 digits]..f157 #edb44329c8b2 { plum[uid: 15492] → 🤷 }
///    ├─ 245 #c9431d708d20
///    │  ├─ 4c787..[52 digits]..c20e #e38b422bd7d9 { pineapple[uid: 12577] → 🍍 }
///    │  ├─ a4f81..[52 digits]..90a3 #3e2491668264 { pomegranate[uid: 0] → 🤷 }
///    │  └─ e3fc8..[52 digits]..e7c3 #eda213c9a1ca { strawberry[uid: 2532] → 🍓 }
///    ├─ 3e #5ecc582a6c21
///    │  ├─ d002d..[53 digits]..f3ac #f64ca98ded70 { lime[uid: 0] → 🤷 }
///    │  └─ e659e..[53 digits]..b3b9 #00ccb0145854 { banana[uid: 218] → 🍌 }
///    ├─ 4 #79519b8cdfbd
///    │  ├─ 07 #fdd60cf1b755
///    │  │  ├─ 6d8ab..[52 digits]..73ef #c538c893306a { guava[uid: 344] → 🤷 }
///    │  │  └─ c5847..[52 digits]..4a22 #785e20425cf9 { kiwi[uid: 0] → 🥝 }
///    │  └─ a522f..[54 digits]..20cd #e0b9d1f525e3 { kumquat[uid: 0] → 🤷 }
///    ├─ 5 #033c3ca05164
///    │  ├─ cddcd..[54 digits]..aa9e #8a1256a87426 { watermelon[uid: 0] → 🍉 }
///    │  └─ e #dd8486a799ef
///    │     ├─ 7ccfe..[53 digits]..4440 #57f7e5e1a73c { yuzu[uid: 0] → 🤷 }
///    │     └─ d71f9..[53 digits]..26d2 #a331cd3151b7 { apple[uid: 58] → 🍎 }
///    ├─ 78666..[55 digits]..7292 #4420b2d642ba { raspberry[uid: 0] → 🤷 }
///    ├─ 8af48..[55 digits]..04a8 #21e74ccebcea { tangerine[uid: 11] → 🍊 }
///    ├─ a #ccd5016507c7
///    │  ├─ 4b927..[54 digits]..3c69 #a6a35d200876 { peach[uid: 0] → 🍑 }
///    │  └─ f12 #9e53c7a37366
///    │     ├─ a1017..[51 digits]..50e7 #6441948643d0 { fig[uid: 68267] → 🤷 }
///    │     └─ ec412..[51 digits]..71fe #6cbd2ef58c2f { passionfruit[uid: 0] → 🤷 }
///    ├─ b #da0bdb30bf45
///    │  ├─ 67e71..[54 digits]..c48b #f39b1b5089f8 { grapefruit[uid: 0] → 🤷 }
///    │  └─ 88701..[54 digits]..949e #85acec96ac0f { blueberry[uid: 0] → 🫐 }
///    ├─ c #a22a7b4d767a
///    │  ├─ 5dc3c..[54 digits]..a3f3 #4c51531ac9d9 { cranberry[uid: 0] → 🤷 }
///    │  └─ 8cac1..[54 digits]..c3ca #8e27b4cf47de { orange[uid: 0] → 🍊 }
///    ├─ d #0a747d583e2e
///    │  ├─ b3047..[54 digits]..502a #54d9ea3b162d { coconut[uid: 0] → 🥥 }
///    │  └─ f779e..[54 digits]..678a #a82bdd8e07c2 { pear[uid: 0] → 🍐 }
///    ├─ e5993..[55 digits]..c9ec #a379ac6be6d5 { apricot[uid: 0] → 🤷 }
///    └─ f #117abf0e19fb
///       ├─ 63c88..[54 digits]..21ca #62bda6837164 { papaya[uid: 0] → 🤷 }
///       └─ b69c0..[54 digits]..2145 #c8e795f7b215 { grapes[uid: 0] → 🍇 }
///
const trie: MerklePatriciaForestry =
  mpf.from_root(
    #"6e9e11c15686694fbec2e1e685e2aa3f2bb402ab955d02ebbc2a5ec1fc69093b",
  )

test example_kumquat() {
  mpf.has(trie, kumquat, "🤷", proof_kumquat)
}

test example_has() {
  and {
    mpf.has(trie, apple, "🍎", proof_apple),
    mpf.has(trie, apricot, "🤷", proof_apricot),
    mpf.has(trie, banana, "🍌", proof_banana),
    mpf.has(trie, blueberry, "🫐", proof_blueberry),
    mpf.has(trie, cherry, "🍒", proof_cherry),
    mpf.has(trie, coconut, "🥥", proof_coconut),
    mpf.has(trie, cranberry, "🤷", proof_cranberry),
    mpf.has(trie, fig, "🤷", proof_fig),
    mpf.has(trie, grapefruit, "🤷", proof_grapefruit),
    mpf.has(trie, grapes, "🍇", proof_grapes),
    mpf.has(trie, guava, "🤷", proof_guava),
    mpf.has(trie, kiwi, "🥝", proof_kiwi),
    mpf.has(trie, kumquat, "🤷", proof_kumquat),
    mpf.has(trie, lemon, "🍋", proof_lemon),
    mpf.has(trie, lime, "🤷", proof_lime),
    mpf.has(trie, mango, "🥭", proof_mango),
    mpf.has(trie, orange, "🍊", proof_orange),
    mpf.has(trie, papaya, "🤷", proof_papaya),
    mpf.has(trie, passion, "🤷", proof_passion),
    mpf.has(trie, peach, "🍑", proof_peach),
    mpf.has(trie, pear, "🍐", proof_pear),
    mpf.has(trie, pineapple, "🍍", proof_pineapple),
    mpf.has(trie, plum, "🤷", proof_plum),
    mpf.has(trie, pomegranate, "🤷", proof_pomegranate),
    mpf.has(trie, raspberry, "🤷", proof_raspberry),
    mpf.has(trie, strawberry, "🍓", proof_strawberry),
    mpf.has(trie, tangerine, "🍊", proof_tangerine),
    mpf.has(trie, tomato, "🍅", proof_tomato),
    mpf.has(trie, watermelon, "🍉", proof_watermelon),
    mpf.has(trie, yuzu, "🤷", proof_yuzu),
  }
}

test example_insert() {
  and {
    mpf.insert(without_apple, apple, "🍎", proof_apple) == trie,
    mpf.insert(without_apricot, apricot, "🤷", proof_apricot) == trie,
    mpf.insert(without_banana, banana, "🍌", proof_banana) == trie,
    mpf.insert(without_blueberry, blueberry, "🫐", proof_blueberry) == trie,
    mpf.insert(without_cherry, cherry, "🍒", proof_cherry) == trie,
    mpf.insert(without_coconut, coconut, "🥥", proof_coconut) == trie,
    mpf.insert(without_cranberry, cranberry, "🤷", proof_cranberry) == trie,
    mpf.insert(without_fig, fig, "🤷", proof_fig) == trie,
    mpf.insert(without_grapefruit, grapefruit, "🤷", proof_grapefruit) == trie,
    mpf.insert(without_grapes, grapes, "🍇", proof_grapes) == trie,
    mpf.insert(without_guava, guava, "🤷", proof_guava) == trie,
    mpf.insert(without_kiwi, kiwi, "🥝", proof_kiwi) == trie,
    mpf.insert(without_kumquat, kumquat, "🤷", proof_kumquat) == trie,
    mpf.insert(without_lemon, lemon, "🍋", proof_lemon) == trie,
    mpf.insert(without_lime, lime, "🤷", proof_lime) == trie,
    mpf.insert(without_mango, mango, "🥭", proof_mango) == trie,
    mpf.insert(without_orange, orange, "🍊", proof_orange) == trie,
    mpf.insert(without_papaya, papaya, "🤷", proof_papaya) == trie,
    mpf.insert(without_passion, passion, "🤷", proof_passion) == trie,
    mpf.insert(without_peach, peach, "🍑", proof_peach) == trie,
    mpf.insert(without_pear, pear, "🍐", proof_pear) == trie,
    mpf.insert(without_pineapple, pineapple, "🍍", proof_pineapple) == trie,
    mpf.insert(without_plum, plum, "🤷", proof_plum) == trie,
    mpf.insert(without_pomegranate, pomegranate, "🤷", proof_pomegranate) == trie,
    mpf.insert(without_raspberry, raspberry, "🤷", proof_raspberry) == trie,
    mpf.insert(without_strawberry, strawberry, "🍓", proof_strawberry) == trie,
    mpf.insert(without_tangerine, tangerine, "🍊", proof_tangerine) == trie,
    mpf.insert(without_tomato, tomato, "🍅", proof_tomato) == trie,
    mpf.insert(without_watermelon, watermelon, "🍉", proof_watermelon) == trie,
    mpf.insert(without_yuzu, yuzu, "🤷", proof_yuzu) == trie,
  }
}

test example_delete() {
  and {
    mpf.delete(trie, apple, "🍎", proof_apple) == without_apple,
    mpf.delete(trie, apricot, "🤷", proof_apricot) == without_apricot,
    mpf.delete(trie, banana, "🍌", proof_banana) == without_banana,
    mpf.delete(trie, blueberry, "🫐", proof_blueberry) == without_blueberry,
    mpf.delete(trie, cherry, "🍒", proof_cherry) == without_cherry,
    mpf.delete(trie, coconut, "🥥", proof_coconut) == without_coconut,
    mpf.delete(trie, cranberry, "🤷", proof_cranberry) == without_cranberry,
    mpf.delete(trie, fig, "🤷", proof_fig) == without_fig,
    mpf.delete(trie, grapefruit, "🤷", proof_grapefruit) == without_grapefruit,
    mpf.delete(trie, grapes, "🍇", proof_grapes) == without_grapes,
    mpf.delete(trie, guava, "🤷", proof_guava) == without_guava,
    mpf.delete(trie, kiwi, "🥝", proof_kiwi) == without_kiwi,
    mpf.delete(trie, kumquat, "🤷", proof_kumquat) == without_kumquat,
    mpf.delete(trie, lemon, "🍋", proof_lemon) == without_lemon,
    mpf.delete(trie, lime, "🤷", proof_lime) == without_lime,
    mpf.delete(trie, mango, "🥭", proof_mango) == without_mango,
    mpf.delete(trie, orange, "🍊", proof_orange) == without_orange,
    mpf.delete(trie, papaya, "🤷", proof_papaya) == without_papaya,
    mpf.delete(trie, passion, "🤷", proof_passion) == without_passion,
    mpf.delete(trie, peach, "🍑", proof_peach) == without_peach,
    mpf.delete(trie, pear, "🍐", proof_pear) == without_pear,
    mpf.delete(trie, pineapple, "🍍", proof_pineapple) == without_pineapple,
    mpf.delete(trie, plum, "🤷", proof_plum) == without_plum,
    mpf.delete(trie, pomegranate, "🤷", proof_pomegranate) == without_pomegranate,
    mpf.delete(trie, raspberry, "🤷", proof_raspberry) == without_raspberry,
    mpf.delete(trie, strawberry, "🍓", proof_strawberry) == without_strawberry,
    mpf.delete(trie, tangerine, "🍊", proof_tangerine) == without_tangerine,
    mpf.delete(trie, tomato, "🍅", proof_tomato) == without_tomato,
    mpf.delete(trie, watermelon, "🍉", proof_watermelon) == without_watermelon,
    mpf.delete(trie, yuzu, "🤷", proof_yuzu) == without_yuzu,
  }
}

test example_update() {
  // https://media3.giphy.com/media/Bj5ILhCPm8EQ8/giphy.gif
  mpf.update(trie, banana, proof_banana, "🍌", "🍆") == updated_banana()
}

test example_idempotent_update() {
  and {
    mpf.update(trie, banana, proof_banana, "🍌", "🍌") == trie,
    mpf.update(updated_banana(), banana, proof_banana, "🍆", "🍆") == updated_banana(),
  }
}

test example_fake_update() fail {
  mpf.update(without_banana, banana, proof_banana, "🍌", "🍆") == updated_banana()
}

// -------------------- Some notable cases

test example_excluding_empty_proof(key via fuzz.bytearray_between(0, 32)) {
  mpf.miss(mpf.empty, key, [])
}

test example_including_empty_proof(
  (key, value) via fuzz.both(
    fuzz.bytearray_between(0, 32),
    fuzz.bytearray_between(0, 32),
  ),
) fail {
  mpf.has(mpf.empty, key, value, [])
}

test example_insert_whatever() {
  let root = mpf.insert(without_kiwi, kiwi, "foo", proof_kiwi)
  root != trie
}

test example_already_inserted() fail {
  let root = mpf.insert(trie, kiwi, "🥝", proof_kiwi)
  root == root
}

test example_delete_different_value() fail {
  let root = mpf.delete(trie, kiwi, "🤷", proof_kiwi)
  root == root
}

test example_already_inserted_different_value() fail {
  let root = mpf.insert(trie, kiwi, "foo", proof_kiwi)
  root == root
}

test example_insert_nearby_with_wrong_proof() fail {
  let root = mpf.insert(without_kiwi, guava, "🤷", proof_kiwi)
  root == root
}

test example_insert_higher_with_wrong_proof() fail {
  let root = mpf.insert(without_kiwi, kumquat, "🤷", proof_kiwi)
  root == root
}

test example_delete_nearby_with_wrong_proof() fail {
  let root = mpf.delete(trie, guava, "🤷", proof_kiwi)
  root == root
}

test example_delete_higher_with_wrong_proof() fail {
  let root = mpf.delete(trie, kumquat, "🤷", proof_kiwi)
  root == root
}

// -------------------- Mutations

type ProofMutation {
  RemoveStepAt(Int)
  InsertStepAt(Int, ProofStep)
  IncrementSkipAt(Int)
}

fn fuzz_proof_mutation(proof: Proof) -> Fuzzer<ProofMutation> {
  expect !list.is_empty(proof)

  let choice <- fuzz.and_then(fuzz.int_between(0, 1))

  when choice is {
    0 -> {
      let ix <- fuzz.map(fuzz.int_between(0, list.length(proof) - 1))
      RemoveStepAt(ix)
    }

    1 -> {
      let ix <- fuzz.and_then(fuzz.int_between(0, list.length(proof)))
      let key <- fuzz.and_then(fuzz.bytearray_between(32, 32))
      let value <- fuzz.map(fuzz.bytearray_between(32, 32))
      InsertStepAt(ix, Leaf { skip: 0, key, value })
    }

    2 -> {
      let ix <- fuzz.map(fuzz.int_between(0, list.length(proof) - 1))
      IncrementSkipAt(ix)
    }

    _ -> fail @"unexpected choice"
  }
}

fn mutate(proof: Proof, mutation: ProofMutation) -> Proof {
  when mutation is {
    RemoveStepAt(ix) ->
      list.concat(list.take(proof, ix - 1), list.drop(proof, ix + 1))

    InsertStepAt(ix, step) ->
      list.concat(list.take(proof, ix), [step, ..list.drop(proof, ix)])

    IncrementSkipAt(ix) -> {
      let step =
        when list.at(proof, ix) is {
          Some(Branch { skip, neighbors }) ->
            Branch { skip: skip + 1, neighbors }
          Some(Fork { skip, neighbor }) -> Fork { skip: skip + 1, neighbor }
          Some(Leaf { skip, key, value }) -> Leaf { skip: skip + 1, key, value }
          _ -> fail @"invalid 'IncrementSkipAt' mutation generated"
        }
      list.concat(list.take(proof, ix - 1), [step, ..list.drop(proof, ix + 1)])
    }
  }
}

test example_has_mutate_proof_apple(
  mutation via fuzz_proof_mutation(proof_apple),
) fail {
  let proof = proof_apple |> mutate(mutation)
  mpf.has(trie, apple, "🍎", proof)
}

test example_insert_mutate_proof_apple(
  mutation via fuzz_proof_mutation(proof_apple),
) fail {
  let proof = proof_apple |> mutate(mutation)
  let root = mpf.insert(without_apple, apple, "🍎", proof)
  root == root
}

// -------------------- Serialisation (comparing with off-chain)

test serialise_apricot() {
  let bytes = cbor.serialise(proof_apricot)
  bytes == #"9fd8799f005f58407c7fd40fe0f220322ad898cc9e5b4ea0485af584c84082ad64afcf71b1e4096759b3c3f838e5383f675cb27a7d0c4baca589be4c48ec74a8a088e5114a4f9e2d5840965c07fa815b86794e8703cee7e8f626c88d7da639258d2466aae67d5d041c5a117abf0e19fb78e0535891d82e5ece1310a1cf11674587dbba304c395769a988ffffff"
}

test serialise_peach() {
  let bytes = cbor.serialise(proof_peach)
  bytes == #"9fd8799f005f58407c7fd40fe0f220322ad898cc9e5b4ea0485af584c84082ad64afcf71b1e4096786bcf4305e2bb0425ebb921890279da144b50e516a440ff16b78417d4108afe95840e9625c510c5779331df65bd0a86085136d6696a6bfac0d752e6d31d5dd72da96da0bdb30bf45c76153418a634f1bcecba8c601ca985fbca14b57582920d82acbffffd87a9f00d8799f0f420102582023cd32d3d66f3b93c8bdf2214b14379ca5d4f61cfd4583fe5aad1a5ef7bf124dffffff"
}

test serialise_fig() {
  let bytes = cbor.serialise(proof_fig)
  bytes == #"9fd8799f005f58407c7fd40fe0f220322ad898cc9e5b4ea0485af584c84082ad64afcf71b1e4096786bcf4305e2bb0425ebb921890279da144b50e516a440ff16b78417d4108afe95840e9625c510c5779331df65bd0a86085136d6696a6bfac0d752e6d31d5dd72da96da0bdb30bf45c76153418a634f1bcecba8c601ca985fbca14b57582920d82acbffffd87b9f005820a4b927e3735c7dbf9f1846844aad53e82362e47e32223d559333f4d154483c6958205ee6f548bba6d9da3313a23b395efb48b440063a592d8592e73d87b79d1d887affd87b9f025820af12ec41241cb0a5cae2a4a1232a64f3ca68f65342cf2a2f98cd6a00cf7971fe58207c3715aba2db74d565a6ce6cc72f20d9cb4652ddb29efe6268be15b105e40911ffff"
}

// -------------------- Fruits

// ---------- apricot

const apricot = "apricot[uid: 0]"

const proof_apricot =
  [
    Branch {
      skip: 0,
      neighbors: #"7c7fd40fe0f220322ad898cc9e5b4ea0485af584c84082ad64afcf71b1e4096759b3c3f838e5383f675cb27a7d0c4baca589be4c48ec74a8a088e5114a4f9e2d965c07fa815b86794e8703cee7e8f626c88d7da639258d2466aae67d5d041c5a117abf0e19fb78e0535891d82e5ece1310a1cf11674587dbba304c395769a988",
    },
  ]

const without_apricot =
  mpf.from_root(
    #"c2bd5ca7b34d2a18520dcec8960e4031c9f607b7ddd04691f9837ca59c03fe09",
  )

// ---------- raspberry

const raspberry = "raspberry[uid: 0]"

const proof_raspberry =
  [
    Branch {
      skip: 0,
      neighbors: #"670cd8fe3049bf2f9c5cbcd01f747da8ac8feafac5c531858ec6bae229170e32f69f145e31d2dc69b65adb5fc2c9d9e87c48210d874d2a2d613793ca90ed906e5cafc4dadc7b95ffa056e19a6c33656d0683de9bcf3228e5aed88aeccda164de0000000000000000000000000000000000000000000000000000000000000000",
    },
  ]

const without_raspberry =
  mpf.from_root(
    #"35c0f70599a90b72c42981f9a951af9105a037a68941e89b8cd815ee5cc907e9",
  )

// ---------- tangerine

const tangerine = "tangerine[uid: 11]"

const proof_tangerine =
  [
    Branch {
      skip: 0,
      neighbors: #"7c7fd40fe0f220322ad898cc9e5b4ea0485af584c84082ad64afcf71b1e4096786bcf4305e2bb0425ebb921890279da144b50e516a440ff16b78417d4108afe9a5f09755c981a35e82a5c9da27cc58ed90e140d3ff3af6a3f669a2f21c631e9c0000000000000000000000000000000000000000000000000000000000000000",
    },
  ]

const without_tangerine =
  mpf.from_root(
    #"8997592195845afb892af2ba50325c2a6fee76b52cdc38450afb405dc820b7d2",
  )

// ---------- banana

const banana = "banana[uid: 218]"

const proof_banana =
  [
    Branch {
      skip: 0,
      neighbors: #"670cd8fe3049bf2f9c5cbcd01f747da8ac8feafac5c531858ec6bae229170e32b7f63d93c9186c6dde0133855d374be101f11901412df025d240ddaa0b0ed12d8f48bf09e3016acc9cccd5c4c41f961dba3ec1b19b0ab6d04428a3cc89de09eec9431d708d20021f1fa3f4f03468b8de194398072a402e7877376d06f747575a",
    },
    Leaf {
      skip: 1,
      key: #"3ed002d6885ab5d92e1307fccd1d021c32ec429192aea10cb2fd688b92aef3ac",
      value: #"7c3715aba2db74d565a6ce6cc72f20d9cb4652ddb29efe6268be15b105e40911",
    },
  ]

const without_banana =
  mpf.from_root(
    #"4cc9c7ae094d6cce8520f0cac6ea3f2b72ff994023be566932c8ab1cbc4ac3ce",
  )

// The root hash we get with `banana` mapped to 🍆 instead
fn updated_banana() {
  mpf.from_root(
    #"b2bb18caca1fa4cbc407272bf5315eb79d649bf3300ad55305347413d652fa96",
  )
}

// ---------- blueberry

const blueberry = "blueberry[uid: 0]"

const proof_blueberry =
  [
    Branch {
      skip: 0,
      neighbors: #"7c7fd40fe0f220322ad898cc9e5b4ea0485af584c84082ad64afcf71b1e4096786bcf4305e2bb0425ebb921890279da144b50e516a440ff16b78417d4108afe9e9625c510c5779331df65bd0a86085136d6696a6bfac0d752e6d31d5dd72da96ccd5016507c773bb56e91e830eebefe294feeb740778058d0c1238a94ad7e48c",
    },
    Leaf {
      skip: 0,
      key: #"b67e71b092e6a54576fa23b0eb48c5e5794a3fb5480983e48b40e453596cc48b",
      value: #"7c3715aba2db74d565a6ce6cc72f20d9cb4652ddb29efe6268be15b105e40911",
    },
  ]

const without_blueberry =
  mpf.from_root(
    #"cbc9d28f8ff48a7ef74630cd41aad7b3113796f37f60d822c5f1b24891747f38",
  )

// ---------- cherry

const cherry = "cherry[uid: 0]"

const proof_cherry =
  [
    Branch {
      skip: 0,
      neighbors: #"670cd8fe3049bf2f9c5cbcd01f747da8ac8feafac5c531858ec6bae229170e32b7f63d93c9186c6dde0133855d374be101f11901412df025d240ddaa0b0ed12da5f3162b8c722b67892153a7f737ae9944ccaa3b792c7d4dda7fe6898e6d8e00520a7f805c5f674e2deca5230b6942bbc71586dc94a783eebe1ed58c9a864e53",
    },
    Branch {
      skip: 3,
      neighbors: #"a297cd1371df7342817ebac221ffd3e0748b043d8f88182e64fa2918d4466b6c85c09af929492a871e4fae32d9d5c36e352471cd659bcdb61de08f1722acc3b10eb923b0cbd24df54401d998531feead35a47a99f4deed205de4af81120f97610000000000000000000000000000000000000000000000000000000000000000",
    },
  ]

const without_cherry =
  mpf.from_root(
    #"d000a6e2ebd7b35d1baaf1a734963c64120547ce8fa984608d0675cb4b893894",
  )

// ---------- coconut

const coconut = "coconut[uid: 0]"

const proof_coconut =
  [
    Branch {
      skip: 0,
      neighbors: #"7c7fd40fe0f220322ad898cc9e5b4ea0485af584c84082ad64afcf71b1e4096759b3c3f838e5383f675cb27a7d0c4baca589be4c48ec74a8a088e5114a4f9e2da8b9a944bba97c79651c4914dc1d5928bead43a0de29f723cd59cb046d8ab04ba22a7b4d767ada48673a4a9313a02a35ff47d2f55bcf10ae294127f590a4327c",
    },
    Leaf {
      skip: 0,
      key: #"df779e7f171b7299c2cede28bb898c1ee3456d98657b95e8082cd375704b678a",
      value: #"9e3d695f13a7292b8859d2ba0113e305825a8af8ba886d2ae73e73f2d35c6afe",
    },
  ]

const without_coconut =
  mpf.from_root(
    #"ed3b6da0125d9cf282b4384f5536bf4879e6d78afc9ab9299914d4b9b0a2363b",
  )

// ---------- cranberry

const cranberry = "cranberry[uid: 0]"

const proof_cranberry =
  [
    Branch {
      skip: 0,
      neighbors: #"7c7fd40fe0f220322ad898cc9e5b4ea0485af584c84082ad64afcf71b1e4096759b3c3f838e5383f675cb27a7d0c4baca589be4c48ec74a8a088e5114a4f9e2da8b9a944bba97c79651c4914dc1d5928bead43a0de29f723cd59cb046d8ab04b0a747d583e2e3db49524add1eea3063421fc04547e19c4e807810a537a63b379",
    },
    Leaf {
      skip: 0,
      key: #"c8cac1a325376bbc49936988b4c720d7806e99c878bc645ad90cebb98302c3ca",
      value: #"ccfd71674a4dca5f252690588b24bebffa36068206414b1575c0f7f7f8103839",
    },
  ]

const without_cranberry =
  mpf.from_root(
    #"7fc739ec024cfba6029622ee77df30df109f71055c0d2d611b0b698cb84f1b98",
  )

// ---------- grapefruit

const grapefruit = "grapefruit[uid: 0]"

const proof_grapefruit =
  [
    Branch {
      skip: 0,
      neighbors: #"7c7fd40fe0f220322ad898cc9e5b4ea0485af584c84082ad64afcf71b1e4096786bcf4305e2bb0425ebb921890279da144b50e516a440ff16b78417d4108afe9e9625c510c5779331df65bd0a86085136d6696a6bfac0d752e6d31d5dd72da96ccd5016507c773bb56e91e830eebefe294feeb740778058d0c1238a94ad7e48c",
    },
    Leaf {
      skip: 0,
      key: #"b88701c48c6abd03dfc5f4538bb585102ddc2e4640c55c8c3c9bb7e0093d949e",
      value: #"6d96ccb103b14005c17b3c17d45e0df0bab5dd1fb2276197a89ed1aeedaad7a0",
    },
  ]

const without_grapefruit =
  mpf.from_root(
    #"ac9e894e5d62b62fe3dfd27e04c9ebefd3739190691689b5c61cff9bedf436ed",
  )

// ---------- grapes

const grapes = "grapes[uid: 0]"

const proof_grapes =
  [
    Branch {
      skip: 0,
      neighbors: #"7c7fd40fe0f220322ad898cc9e5b4ea0485af584c84082ad64afcf71b1e4096759b3c3f838e5383f675cb27a7d0c4baca589be4c48ec74a8a088e5114a4f9e2d965c07fa815b86794e8703cee7e8f626c88d7da639258d2466aae67d5d041c5aa379ac6be6d51d610fcb4f7f8d7ea3ebccd364935ea87f82fabccc861abfdfe3",
    },
    Leaf {
      skip: 0,
      key: #"f63c88d1bc9695dfc39eaf90a11248964311383a95345e5b04d6d8f25d5121ca",
      value: #"7c3715aba2db74d565a6ce6cc72f20d9cb4652ddb29efe6268be15b105e40911",
    },
  ]

const without_grapes =
  mpf.from_root(
    #"92338619b28e0572c9cd662f08ae28c424fd5c72c8ab3740d6203bda6b5fa90e",
  )

// ---------- kumquat

const kumquat = "kumquat[uid: 0]"

const proof_kumquat =
  [
    Branch {
      skip: 0,
      neighbors: #"670cd8fe3049bf2f9c5cbcd01f747da8ac8feafac5c531858ec6bae229170e32f69f145e31d2dc69b65adb5fc2c9d9e87c48210d874d2a2d613793ca90ed906e25069a7a1fd46757d09286b9ee4f67753a06fc706f938d01b200791fd9518f42033c3ca051645e502f48523070a0d379c37f037762d501202e9cfb19f4f16220",
    },
    Fork {
      skip: 0,
      neighbor: Neighbor {
        nibble: 0,
        prefix: #"07",
        root: #"a1ffbc0e72342b41129e2d01d289809079b002e54b123860077d2d66added281",
      },
    },
  ]

const without_kumquat =
  mpf.from_root(
    #"9c31f3581dafc25ce927478baa4095735bcb21ddce9728697d7c23e6c02614a1",
  )

// ---------- lemon

const lemon = "lemon[uid: 0]"

const proof_lemon =
  [
    Branch {
      skip: 0,
      neighbors: #"670cd8fe3049bf2f9c5cbcd01f747da8ac8feafac5c531858ec6bae229170e32b7f63d93c9186c6dde0133855d374be101f11901412df025d240ddaa0b0ed12da5f3162b8c722b67892153a7f737ae9944ccaa3b792c7d4dda7fe6898e6d8e00f8f1111fd89c373c6cecb0bd43b6c932ae760f31d88c5fa71431ec39475b9e18",
    },
    Leaf {
      skip: 0,
      key: #"0389fd2d655e31dac50b00f3113aa327e36680e9df509d48eb255446d4891abc",
      value: #"001fb475e73fee4611a4350ae793d7dca387bcc1e199eabf498002a173378cc5",
    },
  ]

const without_lemon =
  mpf.from_root(
    #"98858de84b7c3a118c728bbe688cc94fb4ae116cb50a796394f44b222cd4d524",
  )

// ---------- lime

const lime = "lime[uid: 0]"

const proof_lime =
  [
    Branch {
      skip: 0,
      neighbors: #"670cd8fe3049bf2f9c5cbcd01f747da8ac8feafac5c531858ec6bae229170e32b7f63d93c9186c6dde0133855d374be101f11901412df025d240ddaa0b0ed12d8f48bf09e3016acc9cccd5c4c41f961dba3ec1b19b0ab6d04428a3cc89de09eec9431d708d20021f1fa3f4f03468b8de194398072a402e7877376d06f747575a",
    },
    Leaf {
      skip: 1,
      key: #"3ee659e1fddc70f61cc65eb61478cd92a09fd7787ea4f913047469339f26b3b9",
      value: #"356a8eb7e12e71400ef0f2e305a89c643ec8cad60506ca9057201a5e36fb01ab",
    },
  ]

const without_lime =
  mpf.from_root(
    #"444c63a311c2fd8237d832303eb77b901d7cbc39016e66195073fdfa29e0fc28",
  )

// ---------- mango

const mango = "mango[uid: 0]"

const proof_mango =
  [
    Branch {
      skip: 0,
      neighbors: #"670cd8fe3049bf2f9c5cbcd01f747da8ac8feafac5c531858ec6bae229170e32b7f63d93c9186c6dde0133855d374be101f11901412df025d240ddaa0b0ed12da5f3162b8c722b67892153a7f737ae9944ccaa3b792c7d4dda7fe6898e6d8e00f8f1111fd89c373c6cecb0bd43b6c932ae760f31d88c5fa71431ec39475b9e18",
    },
    Leaf {
      skip: 0,
      key: #"09d23032e6edc0522c00bc9b74edd3af226d1204a079640a367da94c84b69ecc",
      value: #"c29c35ad67a5a55558084e634ab0d98f7dd1f60070b9ce2a53f9f305fd9d9795",
    },
  ]

const without_mango =
  mpf.from_root(
    #"bb2de0446a1abb50255ba800198b3d0954e0fc3e23e0903e75b8039da1ac1fab",
  )

// ---------- orange

const orange = "orange[uid: 0]"

const proof_orange =
  [
    Branch {
      skip: 0,
      neighbors: #"7c7fd40fe0f220322ad898cc9e5b4ea0485af584c84082ad64afcf71b1e4096759b3c3f838e5383f675cb27a7d0c4baca589be4c48ec74a8a088e5114a4f9e2da8b9a944bba97c79651c4914dc1d5928bead43a0de29f723cd59cb046d8ab04b0a747d583e2e3db49524add1eea3063421fc04547e19c4e807810a537a63b379",
    },
    Leaf {
      skip: 0,
      key: #"c5dc3c068b45ce9dbf42d07fd86fc2dac165fd1b81ce73267b2aee242afba3f3",
      value: #"7c3715aba2db74d565a6ce6cc72f20d9cb4652ddb29efe6268be15b105e40911",
    },
  ]

const without_orange =
  mpf.from_root(
    #"2f6c73bd44f9f2084937cc3f3956a37076346d9bf65d50242891c973396247f0",
  )

// ---------- papaya

const papaya = "papaya[uid: 0]"

const proof_papaya =
  [
    Branch {
      skip: 0,
      neighbors: #"7c7fd40fe0f220322ad898cc9e5b4ea0485af584c84082ad64afcf71b1e4096759b3c3f838e5383f675cb27a7d0c4baca589be4c48ec74a8a088e5114a4f9e2d965c07fa815b86794e8703cee7e8f626c88d7da639258d2466aae67d5d041c5aa379ac6be6d51d610fcb4f7f8d7ea3ebccd364935ea87f82fabccc861abfdfe3",
    },
    Leaf {
      skip: 0,
      key: #"fb69c0d60ec9bfb6cafa5cf54675edfbb0017b873ee92a5dbb6bdabcfb352145",
      value: #"b5898c51c32083e91b8c18c735d0ba74e08f964a20b1639c189d1e8704b78a09",
    },
  ]

const without_papaya =
  mpf.from_root(
    #"02f7cab677d9706135157a99cc84aee3509dd114e9324ff2aacf2ed657b3cf80",
  )

// ---------- peach

const peach = "peach[uid: 0]"

const proof_peach =
  [
    Branch {
      skip: 0,
      neighbors: #"7c7fd40fe0f220322ad898cc9e5b4ea0485af584c84082ad64afcf71b1e4096786bcf4305e2bb0425ebb921890279da144b50e516a440ff16b78417d4108afe9e9625c510c5779331df65bd0a86085136d6696a6bfac0d752e6d31d5dd72da96da0bdb30bf45c76153418a634f1bcecba8c601ca985fbca14b57582920d82acb",
    },
    Fork {
      skip: 0,
      neighbor: Neighbor {
        nibble: 15,
        prefix: #"0102",
        root: #"23cd32d3d66f3b93c8bdf2214b14379ca5d4f61cfd4583fe5aad1a5ef7bf124d",
      },
    },
  ]

const without_peach =
  mpf.from_root(
    #"cd79bbe88a5b583287314cc0af4b71ab9992aabc10eef28bb9b8555a7a62dd23",
  )

// ---------- pear

const pear = "pear[uid: 0]"

const proof_pear =
  [
    Branch {
      skip: 0,
      neighbors: #"7c7fd40fe0f220322ad898cc9e5b4ea0485af584c84082ad64afcf71b1e4096759b3c3f838e5383f675cb27a7d0c4baca589be4c48ec74a8a088e5114a4f9e2da8b9a944bba97c79651c4914dc1d5928bead43a0de29f723cd59cb046d8ab04ba22a7b4d767ada48673a4a9313a02a35ff47d2f55bcf10ae294127f590a4327c",
    },
    Leaf {
      skip: 0,
      key: #"db30478ecc78451d06c1dfe24a35233a6d448fafa17af644fac693a4ca3f502a",
      value: #"1c8ca3866d1b2ab614bf085c95381adbf7be2c6e8fa628034932fe4a4f54e1c3",
    },
  ]

const without_pear =
  mpf.from_root(
    #"65d748810b3889cc812a4ec0a3116f19d90db53ae6cac4c398d16a0a2024b715",
  )

// ---------- pineapple

const pineapple = "pineapple[uid: 12577]"

const proof_pineapple =
  [
    Branch {
      skip: 0,
      neighbors: #"670cd8fe3049bf2f9c5cbcd01f747da8ac8feafac5c531858ec6bae229170e32b7f63d93c9186c6dde0133855d374be101f11901412df025d240ddaa0b0ed12d8f48bf09e3016acc9cccd5c4c41f961dba3ec1b19b0ab6d04428a3cc89de09ee5ecc582a6c2134fefd58e819f37a09f41c6114176dca17fc874a60cbed1e0c4a",
    },
    Branch {
      skip: 2,
      neighbors: #"4e1fa8ba9cc8e18bbf0194b41e5fac140d0e58758706545f2354f2e42f7b4b0685c09af929492a871e4fae32d9d5c36e352471cd659bcdb61de08f1722acc3b10eb923b0cbd24df54401d998531feead35a47a99f4deed205de4af81120f97610000000000000000000000000000000000000000000000000000000000000000",
    },
  ]

const without_pineapple =
  mpf.from_root(
    #"34466eb77d7c42f19d227ef46432876f694a8fd890ceb53be78f830f1c454630",
  )

// ---------- plum

const plum = "plum[uid: 15492]"

const proof_plum =
  [
    Branch {
      skip: 0,
      neighbors: #"670cd8fe3049bf2f9c5cbcd01f747da8ac8feafac5c531858ec6bae229170e32b7f63d93c9186c6dde0133855d374be101f11901412df025d240ddaa0b0ed12da5f3162b8c722b67892153a7f737ae9944ccaa3b792c7d4dda7fe6898e6d8e00520a7f805c5f674e2deca5230b6942bbc71586dc94a783eebe1ed58c9a864e53",
    },
    Branch {
      skip: 3,
      neighbors: #"fa4ecb581bdfa822fedf91a47f87d1f09bcd268360531011e63ecdc138b2dce785c09af929492a871e4fae32d9d5c36e352471cd659bcdb61de08f1722acc3b1d2415338d7f1f66d3eef7e69502c9bc41913ef43e854c34e1779e2bcc41444ca0000000000000000000000000000000000000000000000000000000000000000",
    },
  ]

const without_plum =
  mpf.from_root(
    #"8002fa4abc232642f42c8c7f4abd4385aad80234f5b4991494033b29c972f201",
  )

// ---------- pomegranate

const pomegranate = "pomegranate[uid: 0]"

const proof_pomegranate =
  [
    Branch {
      skip: 0,
      neighbors: #"670cd8fe3049bf2f9c5cbcd01f747da8ac8feafac5c531858ec6bae229170e32b7f63d93c9186c6dde0133855d374be101f11901412df025d240ddaa0b0ed12d8f48bf09e3016acc9cccd5c4c41f961dba3ec1b19b0ab6d04428a3cc89de09ee5ecc582a6c2134fefd58e819f37a09f41c6114176dca17fc874a60cbed1e0c4a",
    },
    Branch {
      skip: 2,
      neighbors: #"03c59510714326934442799b6960ed35c11bb26ea47746839d9ab0635887aa13b60d6d31fb16509758290f509e419f55abb79ba2ca63c9b329f97f69f9e5b4f90eb923b0cbd24df54401d998531feead35a47a99f4deed205de4af81120f97610000000000000000000000000000000000000000000000000000000000000000",
    },
  ]

const without_pomegranate =
  mpf.from_root(
    #"50a04c6a99f875659706e98600d92e413edf2702373ebe72eaace7eac24bcaeb",
  )

// ---------- strawberry

const strawberry = "strawberry[uid: 2532]"

const proof_strawberry =
  [
    Branch {
      skip: 0,
      neighbors: #"670cd8fe3049bf2f9c5cbcd01f747da8ac8feafac5c531858ec6bae229170e32b7f63d93c9186c6dde0133855d374be101f11901412df025d240ddaa0b0ed12d8f48bf09e3016acc9cccd5c4c41f961dba3ec1b19b0ab6d04428a3cc89de09ee5ecc582a6c2134fefd58e819f37a09f41c6114176dca17fc874a60cbed1e0c4a",
    },
    Branch {
      skip: 2,
      neighbors: #"03c59510714326934442799b6960ed35c11bb26ea47746839d9ab0635887aa13eaf6d47da35b10a0585256dfdb4e5a8456e02d276a6c554842bf3e4148160ba70eb923b0cbd24df54401d998531feead35a47a99f4deed205de4af81120f97610000000000000000000000000000000000000000000000000000000000000000",
    },
  ]

const without_strawberry =
  mpf.from_root(
    #"3efc4c103b0610bc5f76979f65edac35b10f7c965637386e7e665c6b982b70fb",
  )

// ---------- tomato

const tomato = "tomato[uid: 83468]"

const proof_tomato =
  [
    Branch {
      skip: 0,
      neighbors: #"670cd8fe3049bf2f9c5cbcd01f747da8ac8feafac5c531858ec6bae229170e32b7f63d93c9186c6dde0133855d374be101f11901412df025d240ddaa0b0ed12da5f3162b8c722b67892153a7f737ae9944ccaa3b792c7d4dda7fe6898e6d8e00520a7f805c5f674e2deca5230b6942bbc71586dc94a783eebe1ed58c9a864e53",
    },
    Branch {
      skip: 3,
      neighbors: #"fa4ecb581bdfa822fedf91a47f87d1f09bcd268360531011e63ecdc138b2dce785c09af929492a871e4fae32d9d5c36e352471cd659bcdb61de08f1722acc3b1b09356b9dd9ecff3b1435c6045466627e399eea3e28d831a16c9360d21efa53c0000000000000000000000000000000000000000000000000000000000000000",
    },
  ]

const without_tomato =
  mpf.from_root(
    #"1d338badd3802833db4149bdf03cbd3f98b3854a58c80bb994b9a404e5016a65",
  )

// ---------- watermelon

const watermelon = "watermelon[uid: 0]"

const proof_watermelon =
  [
    Branch {
      skip: 0,
      neighbors: #"670cd8fe3049bf2f9c5cbcd01f747da8ac8feafac5c531858ec6bae229170e32f69f145e31d2dc69b65adb5fc2c9d9e87c48210d874d2a2d613793ca90ed906e25069a7a1fd46757d09286b9ee4f67753a06fc706f938d01b200791fd9518f4279519b8cdfbd053e5a86cf28a781debae71638cd77f85aad4b88869373d9dcfd",
    },
    Fork {
      skip: 0,
      neighbor: Neighbor {
        nibble: 14,
        prefix: #"",
        root: #"d4447e5c5d54654688c8601bab65412d2b8c0607ae038ad5651caa3a04bc6b54",
      },
    },
  ]

const without_watermelon =
  mpf.from_root(
    #"2e96067d040a2fea346d4f1be4e9ccfdf12d5b8b27f7e2bc03a0f0abaef53501",
  )

// ---------- apple

const apple = "apple[uid: 58]"

const proof_apple =
  [
    Branch {
      skip: 0,
      neighbors: #"670cd8fe3049bf2f9c5cbcd01f747da8ac8feafac5c531858ec6bae229170e32f69f145e31d2dc69b65adb5fc2c9d9e87c48210d874d2a2d613793ca90ed906e25069a7a1fd46757d09286b9ee4f67753a06fc706f938d01b200791fd9518f4279519b8cdfbd053e5a86cf28a781debae71638cd77f85aad4b88869373d9dcfd",
    },
    Leaf {
      skip: 0,
      key: #"5cddcd30a0a388cf6feb3fd6e112c96e9daf23e3a9c8a334e7044650471aaa9e",
      value: #"f429821ddf89c9df3c7fbb5aa6fadb6c246d75ceede53173ce59d70dde375d14",
    },
    Leaf {
      skip: 0,
      key: #"5e7ccfedd44c90423b191ecca1eb21dfbac865d561bace8c0f3e94ae7edf4440",
      value: #"7c3715aba2db74d565a6ce6cc72f20d9cb4652ddb29efe6268be15b105e40911",
    },
  ]

const without_apple =
  mpf.from_root(
    #"657ba71331b58ff290847f747f81ab44e5f6716c9c0a1b7936ab3db9b3e5a425",
  )

// ---------- fig

const fig = "fig[uid: 68267]"

const proof_fig =
  [
    Branch {
      skip: 0,
      neighbors: #"7c7fd40fe0f220322ad898cc9e5b4ea0485af584c84082ad64afcf71b1e4096786bcf4305e2bb0425ebb921890279da144b50e516a440ff16b78417d4108afe9e9625c510c5779331df65bd0a86085136d6696a6bfac0d752e6d31d5dd72da96da0bdb30bf45c76153418a634f1bcecba8c601ca985fbca14b57582920d82acb",
    },
    Leaf {
      skip: 0,
      key: #"a4b927e3735c7dbf9f1846844aad53e82362e47e32223d559333f4d154483c69",
      value: #"5ee6f548bba6d9da3313a23b395efb48b440063a592d8592e73d87b79d1d887a",
    },
    Leaf {
      skip: 2,
      key: #"af12ec41241cb0a5cae2a4a1232a64f3ca68f65342cf2a2f98cd6a00cf7971fe",
      value: #"7c3715aba2db74d565a6ce6cc72f20d9cb4652ddb29efe6268be15b105e40911",
    },
  ]

const without_fig =
  mpf.from_root(
    #"c8552662e0234dd6ef4973cf416c9f5695820dc51a532b5d5654ee9212a4f772",
  )

// ---------- guava

const guava = "guava[uid: 344]"

const proof_guava =
  [
    Branch {
      skip: 0,
      neighbors: #"670cd8fe3049bf2f9c5cbcd01f747da8ac8feafac5c531858ec6bae229170e32f69f145e31d2dc69b65adb5fc2c9d9e87c48210d874d2a2d613793ca90ed906e25069a7a1fd46757d09286b9ee4f67753a06fc706f938d01b200791fd9518f42033c3ca051645e502f48523070a0d379c37f037762d501202e9cfb19f4f16220",
    },
    Leaf {
      skip: 0,
      key: #"4a522f84bcda4bebb725d5f2b92af615b57cc1777bb0d8b2c6c18c3e3e6520cd",
      value: #"7c3715aba2db74d565a6ce6cc72f20d9cb4652ddb29efe6268be15b105e40911",
    },
    Leaf {
      skip: 1,
      key: #"407c58473af4b3e5b24e65481294b0772ed6a7dd793937c6c90179960d154a22",
      value: #"05f6a1db018258657194e930ed49e86cbc3622aeae1c13e92110e28d3635fdca",
    },
  ]

const without_guava =
  mpf.from_root(
    #"dcde4d466622fa44311e3c0da8e9315538b1e7cc647eb0adb3c301b60056481e",
  )

// ---------- kiwi

const kiwi = "kiwi[uid: 0]"

const proof_kiwi =
  [
    Branch {
      skip: 0,
      neighbors: #"670cd8fe3049bf2f9c5cbcd01f747da8ac8feafac5c531858ec6bae229170e32f69f145e31d2dc69b65adb5fc2c9d9e87c48210d874d2a2d613793ca90ed906e25069a7a1fd46757d09286b9ee4f67753a06fc706f938d01b200791fd9518f42033c3ca051645e502f48523070a0d379c37f037762d501202e9cfb19f4f16220",
    },
    Leaf {
      skip: 0,
      key: #"4a522f84bcda4bebb725d5f2b92af615b57cc1777bb0d8b2c6c18c3e3e6520cd",
      value: #"7c3715aba2db74d565a6ce6cc72f20d9cb4652ddb29efe6268be15b105e40911",
    },
    Leaf {
      skip: 1,
      key: #"4076d8ab234597ab6a35c03c805381bbc016025b36ff1f7df9c5009e1a8b73ef",
      value: #"7c3715aba2db74d565a6ce6cc72f20d9cb4652ddb29efe6268be15b105e40911",
    },
  ]

const without_kiwi =
  mpf.from_root(
    #"f11a146be05a70d5e73d48b5fb23b8df4900602878af3a0f0c0883dd0bd05545",
  )

// ---------- passionfruit

const passion = "passionfruit[uid: 0]"

const proof_passion =
  [
    Branch {
      skip: 0,
      neighbors: #"7c7fd40fe0f220322ad898cc9e5b4ea0485af584c84082ad64afcf71b1e4096786bcf4305e2bb0425ebb921890279da144b50e516a440ff16b78417d4108afe9e9625c510c5779331df65bd0a86085136d6696a6bfac0d752e6d31d5dd72da96da0bdb30bf45c76153418a634f1bcecba8c601ca985fbca14b57582920d82acb",
    },
    Leaf {
      skip: 0,
      key: #"a4b927e3735c7dbf9f1846844aad53e82362e47e32223d559333f4d154483c69",
      value: #"5ee6f548bba6d9da3313a23b395efb48b440063a592d8592e73d87b79d1d887a",
    },
    Leaf {
      skip: 2,
      key: #"af12a10176ecbb08fc16658069ac132455796c5b62a5ef8985933c76652f50e7",
      value: #"7c3715aba2db74d565a6ce6cc72f20d9cb4652ddb29efe6268be15b105e40911",
    },
  ]

const without_passion =
  mpf.from_root(
    #"73f3008365a6a4b53b7660b10c44a23c40e4393818d929602d65d868eabb4a26",
  )

// ---------- yuzu

const yuzu = "yuzu[uid: 0]"

const proof_yuzu =
  [
    Branch {
      skip: 0,
      neighbors: #"670cd8fe3049bf2f9c5cbcd01f747da8ac8feafac5c531858ec6bae229170e32f69f145e31d2dc69b65adb5fc2c9d9e87c48210d874d2a2d613793ca90ed906e25069a7a1fd46757d09286b9ee4f67753a06fc706f938d01b200791fd9518f4279519b8cdfbd053e5a86cf28a781debae71638cd77f85aad4b88869373d9dcfd",
    },
    Leaf {
      skip: 0,
      key: #"5cddcd30a0a388cf6feb3fd6e112c96e9daf23e3a9c8a334e7044650471aaa9e",
      value: #"f429821ddf89c9df3c7fbb5aa6fadb6c246d75ceede53173ce59d70dde375d14",
    },
    Leaf {
      skip: 0,
      key: #"5ed71f91166242e8477758810ad103aff35313b175b1762b0efe800fa9a126d2",
      value: #"09d504e02c4e6fa7b66303a456bc8786da3f51e8bf2834eeb9c95ec479f3681a",
    },
  ]

const without_yuzu =
  mpf.from_root(
    #"ba9f06cd8e668234419be49452d304a8e641692ea68756c96d49ba5ea8f3c51f",
  )
