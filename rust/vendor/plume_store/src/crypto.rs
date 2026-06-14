//! Transparent at-rest encryption for the account store. The key is derived from this Mac's
//! host UUID (so an encrypted file is useless if copied to another machine or restored from a
//! backup) mixed with the app bundle id and a salt. AES-256-GCM, fresh random nonce per write.

use aes_gcm::aead::{Aead, KeyInit};
use aes_gcm::{Aes256Gcm, Key, Nonce};
use rand::RngCore;
use sha2::{Digest, Sha256};

const BUNDLE_ID: &str = "ro.randusoft.signr";
const SALT: &str = "signr-data-v1";
const MAGIC: &[u8] = b"SGNRENC1";

#[repr(C)]
struct Timespec {
    tv_sec: i64,
    tv_nsec: i64,
}

unsafe extern "C" {
    fn gethostuuid(id: *mut u8, wait: *const Timespec) -> i32;
}

fn host_uuid() -> [u8; 16] {
    let mut id = [0u8; 16];
    let wait = Timespec { tv_sec: 5, tv_nsec: 0 };
    unsafe {
        gethostuuid(id.as_mut_ptr(), &wait);
    }
    id
}

fn key() -> Key<Aes256Gcm> {
    let mut h = Sha256::new();
    h.update(host_uuid());
    h.update(BUNDLE_ID.as_bytes());
    h.update(SALT.as_bytes());
    *Key::<Aes256Gcm>::from_slice(&h.finalize())
}

/// Encrypt as `MAGIC || nonce(12) || ciphertext+tag`.
pub fn encrypt(plaintext: &[u8]) -> Vec<u8> {
    let cipher = Aes256Gcm::new(&key());
    let mut nonce = [0u8; 12];
    rand::thread_rng().fill_bytes(&mut nonce);
    let ct = cipher
        .encrypt(Nonce::from_slice(&nonce), plaintext)
        .expect("aes-gcm encryption never fails");
    let mut out = Vec::with_capacity(MAGIC.len() + nonce.len() + ct.len());
    out.extend_from_slice(MAGIC);
    out.extend_from_slice(&nonce);
    out.extend_from_slice(&ct);
    out
}

/// Decrypt our format. Returns `None` when the data is not our blob (e.g. a legacy plaintext
/// file), so callers can fall back to reading it directly and re-save it encrypted.
pub fn decrypt(data: &[u8]) -> Option<Vec<u8>> {
    let head = MAGIC.len() + 12;
    if data.len() < head || &data[..MAGIC.len()] != MAGIC {
        return None;
    }
    let cipher = Aes256Gcm::new(&key());
    let nonce = Nonce::from_slice(&data[MAGIC.len()..head]);
    cipher.decrypt(nonce, &data[head..]).ok()
}
