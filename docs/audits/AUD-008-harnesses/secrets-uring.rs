//! AUD-008: challenge the exact production isolation module with a two-entry io_uring probe.
#[path = "../../../src/bin/mhfe/protect.rs"]
mod protect;
use std::net::UdpSocket;
use std::time::Duration;
unsafe extern "C" {
    fn probe_uring_socket(port: u16) -> i32;
}
fn main() {
    let receiver = UdpSocket::bind("127.0.0.1:0").expect("synthetic loopback receiver");
    receiver
        .set_read_timeout(Some(Duration::from_secs(1)))
        .unwrap();
    let port = receiver.local_addr().unwrap().port();
    protect::harden_process();
    let isolation = protect::isolate(protect::Needs::NOTHING);
    println!("production_isolation={isolation:?}");
    let normal = UdpSocket::bind("127.0.0.1:0");
    println!(
        "ordinary_socket_error={:?}",
        normal.as_ref().err().and_then(|error| error.raw_os_error())
    );
    assert!(
        isolation.no_network && normal.is_err(),
        "control isolation failed"
    );
    let result = unsafe { probe_uring_socket(port) };
    if result == 1 {
        let mut bytes = [0u8; 64];
        let read = receiver
            .recv(&mut bytes)
            .expect("public marker should reach loopback");
        assert_eq!(&bytes[..read], b"AUD008 public loopback probe\0");
        println!("FAIL: a newly created io_uring UDP socket sent the synthetic marker under production isolation");
    } else if result == 2 {
        println!("BLOCKED: host policy or unsupported ring operation prevented this diagnostic");
    }
    std::process::exit(result);
}
