//! The decoy search for one missing word, natively shared among the processor's cores
//! (mhfe::search::compare_candidates), and the checked draw of a new phrase on every core
//! (mhfe::wallet_check::threads), run as they are; under `prlimit --nproc=1` the system refuses
//! every new thread of this process.
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
    if which == "draw" {
        // The published wallet-check vector: counter 76,562 passes with "TREZOR"; every source
        // starts three before it, as the two probes of the source take two counters.
        let draw = PhraseDraw::with_check("TREZOR").unwrap();
        let found = draw.draw_on_every_core(|| Counting(76_559), &mut |_| Ok(()));
        println!("draw on every core: {:?}", found.map(|p| p.phrase().split(' ').last().map(str::to_owned)));
        return;
    }
    let container = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon art";
    let fingerprint = master_fingerprint(container, "").unwrap();
    let typed = container.replace(" art", " ?");
    let search = ContainerSearch::new(&typed).unwrap();
    let reference = Reference::Fingerprint { fingerprint, passphrase: "" };
    let found = search.search_decoy(&reference, 20, &mut |_, _| Ok(()));
    println!("decoy search: {:?}", found.map(|f| f.map(|f| f.words)));
}
