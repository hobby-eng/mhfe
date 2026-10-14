//! AUD-024 verification probe: mhfe::search::ContainerSearch::search_decoy (compare_candidates,
//! src/search.rs:279-367) and PhraseDraw::draw_on_every_core (src/wallet_check/threads.rs) when
//! the system refuses new threads. Public test data only: the "abandon" x23 "art" phrase.
use mhfe::random::RandomSource;
use mhfe::search::ContainerSearch;
use mhfe::wallet::master_fingerprint;
use mhfe::wallet_check::PhraseDraw;
use mhfe::{MhfeError, Reference};

struct Counting(u64);
impl RandomSource for Counting {
    fn fill(&mut self, bytes: &mut [u8]) -> Result<(), MhfeError> {
        self.0 += 1;
        bytes.fill(0);
        let n = bytes.len();
        bytes[n - 8..].copy_from_slice(&self.0.to_be_bytes());
        Ok(())
    }
}

fn main() {
    let which = std::env::args().nth(1).unwrap_or_default();
    eprintln!(
        "available_parallelism: {:?}",
        std::thread::available_parallelism().map(|n| n.get())
    );
    if which == "draw" {
        let draw = PhraseDraw::with_check("TREZOR").unwrap();
        let found = draw.draw_on_every_core(|| Counting(76_559), &mut |_| Ok(()));
        println!(
            "draw on every core: {:?}",
            found.map(|p| p.phrase().split(' ').last().map(str::to_owned))
        );
        return;
    }
    // "twelve": the 12-word "abandon" x11 "about", whose last word leaves 128 candidates.
    let (container, last) = if which == "twelve" {
        ("abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about", " about")
    } else {
        ("abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon art", " art")
    };
    let fingerprint = master_fingerprint(container, "").unwrap();
    let typed = container.replace(last, " ?");
    let search = ContainerSearch::new(&typed).unwrap();
    eprintln!("candidates: {}", search.count());
    let reference = Reference::Fingerprint { fingerprint, passphrase: "" };
    let found = search.search_decoy(&reference, 20, &mut |_, _| Ok(()));
    println!("decoy search: {:?}", found.map(|f| f.map(|f| f.words)));
}
