//! Challenge-HMAC authentication helpers.

use crate::base64;
use crate::sha256;
use crate::util;

pub fn new_challenge() -> String {
    util::random_hex(16)
}

pub fn message(nonce: &str, challenge: &str) -> String {
    format!("inkblade-probe/v1|{nonce}|{challenge}")
}

pub fn expected_mac(token: &str, nonce: &str, challenge: &str) -> String {
    base64::hex(&sha256::hmac_sha256(
        token.as_bytes(),
        message(nonce, challenge).as_bytes(),
    ))
}

pub fn verify(token: &str, nonce: &str, challenge: &str, mac_hex: &str) -> bool {
    match base64::unhex(mac_hex) {
        Ok(provided) => {
            let expected = sha256::hmac_sha256(
                token.as_bytes(),
                message(nonce, challenge).as_bytes(),
            );
            sha256::constant_time_eq(&provided, &expected)
        }
        Err(_) => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_only_the_correct_mac() {
        let token = "unit-token";
        let nonce = "0011223344556677";
        let challenge = "aabbccdd";
        let mac = expected_mac(token, nonce, challenge);
        assert!(verify(token, nonce, challenge, &mac));
        assert!(!verify("other", nonce, challenge, &mac));
        assert!(!verify(token, "other", challenge, &mac));
        assert!(!verify(token, nonce, "other", &mac));
        assert!(!verify(token, nonce, challenge, "zz"));
    }

    #[test]
    fn message_is_stable() {
        assert_eq!(message("n", "c"), "inkblade-probe/v1|n|c");
    }
}
