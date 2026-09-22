use mhfe::{MhfeEngine, NormalizedPassword};
use sha2::{Digest, Sha256};

struct PublishedVector {
    source: &'static str,
    password: &'static str,
    pim: u32,
    container: &'static str,
    encryption_sha256: &'static str,
    decryption_sha256: &'static str,
}

const VECTORS: &[PublishedVector] = &[
    PublishedVector {
        source: "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
        password: "public test password",
        pim: 0,
        container: "topple stock shiver enforce hire stumble unique trick mansion relief absent thought thunder price buzz crazy depart robust drastic bunker husband wagon salad book",
        encryption_sha256: "7563e583d8111753107963b6ed981e1d098cabcdb0d57efcbf1d585582e95a45",
        decryption_sha256: "876a6fedbebdef755db3e6841b88e3ff8a175caac9d28cd45d9892f094979829",
    },
    PublishedVector {
        source: "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
        password: "public test password",
        pim: 1,
        container: "still hole horn icon unveil plug there confirm achieve shoe pink mammal mean road kite region canoe trophy boat sport blind eager team energy",
        encryption_sha256: "f91c2d01efa681966b40e0d44655977196911049d21f1a7b004c11690ebb9556",
        decryption_sha256: "2931dabffd74e6df7b7097bf062d665b295668dad5dfd27682d46ea1a1090bd2",
    },
    PublishedVector {
        source: "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon address",
        password: "public test password",
        pim: 0,
        container: "normal salon faculty begin that custom suffer identify issue also pull filter omit culture swarm end sniff leisure super thank erupt satisfy park bunker",
        encryption_sha256: "16af013c51a8f0bb2957a17516419ab9a5f0721521218997f19ef0eabfb2c4c6",
        decryption_sha256: "d617df73d325d333fdcfe94f36faa0515aa107f7811996a4b276cd33586baf26",
    },
    PublishedVector {
        source: "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon agent",
        password: "public test password",
        pim: 0,
        container: "boost ladder dynamic decide erase tragic gravity cat fragile hole private damp brother deer forum clever cry verb worth little fiscal mobile hurt print",
        encryption_sha256: "e4565738fb4fbcce481710b023d0f114e8262b5185ed23ff4f9e6675407b0917",
        decryption_sha256: "54a759f529c95ab2301414ba57e89b03e115b461efe235dc0cd66fa16478c78f",
    },
    PublishedVector {
        source: "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon admit",
        password: "public test password",
        pim: 0,
        container: "correct train surge wear remember deliver hire undo lounge vicious leave token upset scrap ripple mango birth sword obscure lawn disorder video useless jar",
        encryption_sha256: "e1d0a9f85a1f3c03323888ffa6d8fb15ce65af3a3454b3965026c7df815d26c6",
        decryption_sha256: "742e8e5e922b20e7c063e252400b030409cfc025aed203713d38737adec59927",
    },
    PublishedVector {
        source: "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon art",
        password: "public test password",
        pim: 0,
        container: "negative rent lava dash crack tunnel strategy knock jeans poet network couple hello lumber loud west modify master shrug broccoli latin error decorate east",
        encryption_sha256: "79e61aed8173b4c0c3e360bcf3cea0ad3d92685b2f0c83246ffc80eb3db44654",
        decryption_sha256: "a4c5fddea6b06bbc15325ed5ccf3bbfb06db8655e12794cf8c09880bcbb02852",
    },
    PublishedVector {
        source: "legal winner thank year wave sausage worth useful legal winner thank yellow",
        password: "audit probe password 2026",
        pim: 0,
        container: "exact verb pair worth casino faint alpha expose zebra possible swift country cluster ride language farm sail churn original churn camera stage since finish",
        encryption_sha256: "ad323b058ead170afe0d10cc4605f2d0759a86e1d33187cb66c3102dad86fbd4",
        decryption_sha256: "61fe8f1a0c175f0d90e6e9f5555cf4d127675f4080f50c2ab33b89a684488c0d",
    },
    PublishedVector {
        source: "letter advice cage absurd amount doctor acoustic avoid letter advice cage absurd amount doctor acoustic avoid letter always",
        password: "audit probe password 2026",
        pim: 0,
        container: "cousin original loud solar nurse among equip loud tumble toddler trash siren coil easily ski siren defense certain plunge alley use fury memory reduce",
        encryption_sha256: "bfc85038d55c2be512f1db989097e42889549395678b9de60ae279bae34f50ab",
        decryption_sha256: "d8edf0a4346755fdbce54dce8d42476b9b160127c0e91a01d8be35d8021940ca",
    },
    PublishedVector {
        source: "legal winner thank year wave sausage worth useful legal winner thank year wave sausage worth useful legal winner thank year wave sausage worth title",
        password: "audit probe password 2026",
        pim: 0,
        container: "diesel decade erosion figure capable during enhance dumb miss zero can dress ice indoor street stamp bronze merge wise decorate burger gentle eternal forward",
        encryption_sha256: "2eaacee82372cdd28bf8868c012a2cc2bacae9ee33cef6931945bb68fd6f73bd",
        decryption_sha256: "3b2b3d8100df36e823d29880a3970a1b37124f34641ce414ef5384922f580d4b",
    },
];

#[test]
#[ignore = "expensive frozen-suite replay; run explicitly or in vector CI"]
fn published_vectors_encrypt_and_decrypt() {
    for vector in VECTORS {
        let password = NormalizedPassword::from_test_ascii(vector.password).unwrap();
        let mut engine = MhfeEngine::new(vector.pim).unwrap();
        let encrypted = engine.encrypt_vector(vector.source, &password).unwrap();
        assert_eq!(encrypted.encrypted_mnemonic, vector.container);
        assert_eq!(digest_json(&encrypted), vector.encryption_sha256);
        let recovered = engine
            .decrypt_vector(
                vector.container,
                vector.source.split_ascii_whitespace().count(),
                &password,
            )
            .unwrap();
        assert_eq!(recovered.recovered_mnemonic, vector.source);
        assert_eq!(recovered.recovery_verified, recovered.source_words < 24);
        assert_eq!(digest_json(&recovered), vector.decryption_sha256);
    }
}

fn digest_json(value: &impl serde::Serialize) -> String {
    hex::encode(Sha256::digest(serde_json::to_vec(value).unwrap()))
}
