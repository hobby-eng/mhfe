//! Hash adapters for known-answer tables; the hash type is the only varying parameter.

use hmac::{KeyInit, Mac, SimpleHmac};
use sha2::digest::block_api::BlockSizeUser;
use sha2::Digest;

pub(crate) fn digest<D: Digest>(_: &[u8], message: &[u8]) -> Vec<u8> {
    D::digest(message).to_vec()
}

#[expect(clippy::expect_used, reason = "HMAC accepts a key of any length")]
pub(crate) fn hmac<D: Digest + BlockSizeUser>(key: &[u8], message: &[u8]) -> Vec<u8> {
    let mut mac =
        <SimpleHmac<D> as KeyInit>::new_from_slice(key).expect("HMAC takes a key of any length");
    mac.update(message);
    mac.finalize().into_bytes().to_vec()
}
