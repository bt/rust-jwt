extern crate openssl;

use crypto::digest::Digest;
use crypto::hmac::Hmac;
use crypto::mac::{Mac, MacResult};
use crypto::sha2::Sha256;
use rustc_serialize::base64::{FromBase64, ToBase64, Config, CharacterSet, Newline};
use self::openssl::crypto::rsa;
use self::openssl::crypto::hash;
use std::io::Write;
use super::header::Algorithm;
use BASE_CONFIG;

pub fn sign<D: Digest>(data: &str, key: &[u8], digest: D) -> String {
    let mut hmac = Hmac::new(digest, key);
    hmac.input(data.as_bytes());

    let mac = hmac.result();
    let code = mac.code();
    (*code).to_base64(BASE_CONFIG)
}

fn get_sha_algorithm(alg: &Algorithm) -> hash::Type {
    match alg {
        &Algorithm::RS256 => hash::Type::SHA256,
        &Algorithm::RS384 => hash::Type::SHA384,
        &Algorithm::RS512 => hash::Type::SHA512,
        _ => panic!("Invalid RSA algorithm"),
    }
}

pub fn sign_rsa(data: &str, key: &[u8], alg: &Algorithm) -> String {
    let private_key = rsa::RSA::private_key_from_pem(key).unwrap();
    let sha_alg = get_sha_algorithm(alg);

    let mut hasher = hash::Hasher::new(sha_alg).unwrap();
    hasher.write_all(data.as_bytes()).unwrap();

    let digest = hasher.finish().unwrap();

    (private_key.sign(sha_alg, &digest).unwrap()).to_base64(Config {
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
