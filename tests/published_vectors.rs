use mhfe::{MhfeEngine, NormalizedPassword};
use sha2::{Digest, Sha256};

struct PublishedVector {
    source: &'static str,
    pim: u32,
    container: &'static str,
    encryption_sha256: &'static str,
    decryption_sha256: &'static str,
}

const VECTORS: &[PublishedVector] = &[
    PublishedVector {
        source: "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
        pim: 0,
        container: "topple stock shiver enforce hire stumble unique trick mansion relief absent thought thunder price buzz crazy depart robust drastic bunker husband wagon salad book",
        encryption_sha256: "7563e583d8111753107963b6ed981e1d098cabcdb0d57efcbf1d585582e95a45",
        decryption_sha256: "876a6fedbebdef755db3e6841b88e3ff8a175caac9d28cd45d9892f094979829",
    },
    PublishedVector {
        source: "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
        pim: 1,
        container: "still hole horn icon unveil plug there confirm achieve shoe pink mammal mean road kite region canoe trophy boat sport blind eager team energy",
        encryption_sha256: "f91c2d01efa681966b40e0d44655977196911049d21f1a7b004c11690ebb9556",
        decryption_sha256: "2931dabffd74e6df7b7097bf062d665b295668dad5dfd27682d46ea1a1090bd2",
    },
    PublishedVector {
        source: "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon address",
        pim: 0,
        container: "normal salon faculty begin that custom suffer identify issue also pull filter omit culture swarm end sniff leisure super thank erupt satisfy park bunker",
        encryption_sha256: "16af013c51a8f0bb2957a17516419ab9a5f0721521218997f19ef0eabfb2c4c6",
        decryption_sha256: "d617df73d325d333fdcfe94f36faa0515aa107f7811996a4b276cd33586baf26",
    },
    PublishedVector {
        source: "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon agent",
        pim: 0,
        container: "boost ladder dynamic decide erase tragic gravity cat fragile hole private damp brother deer forum clever cry verb worth little fiscal mobile hurt print",
        encryption_sha256: "e4565738fb4fbcce481710b023d0f114e8262b5185ed23ff4f9e6675407b0917",
        decryption_sha256: "54a759f529c95ab2301414ba57e89b03e115b461efe235dc0cd66fa16478c78f",
    },
    PublishedVector {
        source: "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon admit",
        pim: 0,
        container: "correct train surge wear remember deliver hire undo lounge vicious leave token upset scrap ripple mango birth sword obscure lawn disorder video useless jar",
        encryption_sha256: "e1d0a9f85a1f3c03323888ffa6d8fb15ce65af3a3454b3965026c7df815d26c6",
        decryption_sha256: "742e8e5e922b20e7c063e252400b030409cfc025aed203713d38737adec59927",
    },
    PublishedVector {
        source: "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon art",
        pim: 0,
        container: "negative rent lava dash crack tunnel strategy knock jeans poet network couple hello lumber loud west modify master shrug broccoli latin error decorate east",
        encryption_sha256: "79e61aed8173b4c0c3e360bcf3cea0ad3d92685b2f0c83246ffc80eb3db44654",
        decryption_sha256: "a4c5fddea6b06bbc15325ed5ccf3bbfb06db8655e12794cf8c09880bcbb02852",
    },
];

#[test]
#[ignore = "expensive frozen-suite replay; run explicitly or in vector CI"]
fn published_vectors_encrypt_and_decrypt() {
    let password = NormalizedPassword::from_test_ascii("public test password").unwrap();
    for vector in VECTORS {
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
