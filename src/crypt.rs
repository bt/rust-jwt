extern crate openssl;

use crypto::digest::Digest;
use crypto::hmac::Hmac;
use crypto::mac::{Mac, MacResult};
use crypto::sha2::Sha256;
use rustc_serialize::base64::{FromBase64, ToBase64, Config, CharacterSet, Newline};
use self::openssl::crypto::rsa;
use self::openssl::crypto::hash;
use super::header::Algorithm;
use BASE_CONFIG;

pub fn sign<D: Digest>(data: &str, key: &[u8], digest: D) -> String {
    let mut hmac = Hmac::new(digest, key);
    hmac.input(data.as_bytes());

    let mac = hmac.result();
    let code = mac.code();
    (*code).to_base64(BASE_CONFIG)
}

pub fn sign_rsa(data: &str, key: &[u8], alg: &Algorithm) -> String {
    let private_key = rsa::RSA::private_key_from_pem(key).unwrap();
    let mut hasher = match alg {
        &Algorithm::RS256 => Sha256::new(),
        _ => unimplemented!(),
    };
    let hash_type = match alg {
        &Algorithm::RS256 => hash::Type::SHA256,
        _ => unimplemented!(),
    };

    hasher.input_str(data);
    let data_bytes = hasher.output_bytes();
    let mut data = vec![0u8; data_bytes];
    let mut data = &mut data[..];
    hasher.result(&mut data);

    (private_key.sign(hash_type, data).unwrap()).to_base64(Config {
        char_set: CharacterSet::UrlSafe,
        newline: Newline::LF,
        pad: true,
        line_length: None,
    })
}

pub fn verify<D: Digest>(target: &str, data: &str, key: &[u8], digest: D) -> bool {
    let target_bytes = match target.from_base64() {
        Ok(x) => x,
        Err(_) => return false,
    };
    let target_mac = MacResult::new_from_owned(target_bytes);

    let mut hmac = Hmac::new(digest, key);
    hmac.input(data.as_bytes());

    hmac.result() == target_mac
}
