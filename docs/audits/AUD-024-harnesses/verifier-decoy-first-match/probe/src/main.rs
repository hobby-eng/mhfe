//! AUD-024 verifier probe: one two-word decoy search of "abandon" x10 "? ?" with the master key
//! fingerprint 02ba9d7a, which both "... amused buzz" and "... employ giraffe" have. The owner's
//! container is taken to be "... employ giraffe". Prints what search_decoy returns and how many
//! candidates it compared, and, as a control, the fingerprints of both containers through the
//! library. Exits 1 when the search returns the other container with no sign of a second match.
use mhfe::search::{ContainerSearch, DECOY_SCAN_GAP};
use mhfe::wallet::master_fingerprint;
use mhfe::Reference;

fn main() {
    let prefix = "abandon ".repeat(10);
    let owner = format!("{prefix}employ giraffe");
    let other = format!("{prefix}amused buzz");
    let hex = |f: [u8; 4]| f.iter().map(|b| format!("{b:02x}")).collect::<String>();
    let owner_fp = master_fingerprint(&owner, "").expect("valid phrase");
    let other_fp = master_fingerprint(&other, "").expect("valid phrase");
    println!("library fingerprint of abandon x10 employ giraffe: {}", hex(owner_fp));
    println!("library fingerprint of abandon x10 amused buzz:    {}", hex(other_fp));
    let written = format!("{prefix}? ?");
    let search = ContainerSearch::new(&written).expect("two marked words");
    println!("candidates: {}", search.count());
    let reference = Reference::Fingerprint { fingerprint: owner_fp, passphrase: "" };
    let mut last = (0, 0);
    let found = search
        .search_decoy(&reference, DECOY_SCAN_GAP, &mut |done, count| {
            last = (done, count);
            Ok(())
        })
        .expect("the search runs")
        .expect("a candidate matches");
    println!("last progress report: {} of {}", last.0, last.1);
    println!("search_decoy returned words {:?}", found.words);
    let is_owner = *found.container == owner;
    println!(
        "returned container is {}",
        if is_owner { "the owner's (employ giraffe)" } else { "NOT the owner's: amused buzz" }
    );
    println!("Found has fields container, words, path only: nothing says whether another candidate matched");
    std::process::exit(if is_owner { 0 } else { 1 });
}
