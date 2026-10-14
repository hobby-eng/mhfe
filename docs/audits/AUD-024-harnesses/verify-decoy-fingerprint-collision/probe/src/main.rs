//! AUD-024 verification of the two-word decoy fingerprint collision. Public data only: the
//! phrases are "abandon" x 10 followed by two words. Reports whether the two given phrases are
//! valid BIP39 phrases with the same master key fingerprint, and what search_decoy returns for
//! "abandon" x 10 "? ?" with that fingerprint, also with the later phrase's words typed as ?.
use mhfe::search::{ContainerSearch, DECOY_SCAN_GAP};
use mhfe::wallet::master_fingerprint;
use mhfe::Reference;

fn hex(f: &[u8; 4]) -> String {
    f.iter().map(|b| format!("{b:02x}")).collect()
}

fn main() {
    let prefix = "abandon ".repeat(10);
    let pairs = [("able ghost", "best student"), ("amused buzz", "employ giraffe")];
    let mut wrong = 0;
    for (earlier, later) in pairs {
        let a = format!("{prefix}{earlier}");
        let b = format!("{prefix}{later}");
        let fa = master_fingerprint(&a, "").expect("valid phrase");
        let fb = master_fingerprint(&b, "").expect("valid phrase");
        println!("[{earlier}] fingerprint {} ; [{later}] fingerprint {} ; equal: {}", hex(&fa), hex(&fb), fa == fb);
        let search = ContainerSearch::new(&format!("{prefix}? ?")).expect("two marked words");
        let reference = Reference::Fingerprint { fingerprint: fb, passphrase: "" };
        let mut last = (0, 0);
        let started = std::time::Instant::now();
        let result = search.search_decoy(&reference, DECOY_SCAN_GAP, &mut |done, count| {
            last = (done, count);
            Ok(())
        });
        match result {
            // Since the fix of AUD-024-FUN001 the search compares every candidate and refuses a
            // fingerprint that more than one matches: the defect is gone.
            Err(error) if error.code() == "SEVERAL_CANDIDATES_MATCH" => println!(
                "  search_decoy for the fingerprint of [{later}] over {} candidates: refused, {error}; last progress {:?}; {:.1} s",
                search.count(),
                last,
                started.elapsed().as_secs_f64()
            ),
            Err(error) => panic!("the search runs: {error:?}"),
            Ok(found) => {
                let found = found.expect("a match");
                println!(
                    "  search_decoy for the fingerprint of [{later}] over {} candidates: returned {:?}, container is [{later}]: {}; last progress {:?}; {:.1} s",
                    search.count(),
                    found.words,
                    found.container.as_str() == b,
                    last,
                    started.elapsed().as_secs_f64()
                );
                if found.container.as_str() != b {
                    wrong += 1;
                }
            }
        }
    }
    println!("RESULT: {wrong} of {} searches returned the earlier candidate, not the container whose fingerprint was given", pairs.len());
    std::process::exit(if wrong > 0 { 1 } else { 0 });
}
