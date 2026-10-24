mod login;
mod token;
mod two_factor_auth;

use aes::cipher::BlockModeDecrypt;
use cbc::cipher::{KeyIvInit, block_padding::Pkcs7};
use hmac::{Hmac, KeyInit, Mac};
use plist::{Dictionary, Value};
use reqwest::Response;
use reqwest::header::HeaderMap;
use sha2::Sha256;
use srp::ClientVerifier;

use crate::Error;
use crate::auth::{Account, GSA_ENDPOINT};

pub async fn parse_response(res: Result<Response, reqwest::Error>) -> Result<Dictionary, Error> {
    let res = res?;
    let url = res.url().to_string();
    let status = res.status().as_u16();
    let body = res.bytes().await?;
    parse_gsa_body(&url, status, &body)
}

/// Apple answers rejected clients with HTML error pages, which used to surface as plist parse
/// errors, and a non-2xx that still carries a GrandSlam status keeps its error code
pub fn parse_gsa_body(url: &str, status: u16, body: &[u8]) -> Result<Dictionary, Error> {
    let response = plist::from_bytes::<Dictionary>(body)
        .ok()
        .and_then(|mut d| d.remove("Response"))
        .and_then(Value::into_dictionary);
    let http_error = || Error::GsaHttp {
        url: url.to_string(),
        status,
    };
    match response {
        Some(dict) if (200..300).contains(&status) => Ok(dict),
        Some(dict) => {
            check_error(&dict)?;
            Err(http_error())
        }
        None if (200..300).contains(&status) => Err(Error::Parse),
        None => Err(http_error()),
    }
}

fn status_dict(res: &Dictionary) -> &Dictionary {
    match res.get("Status") {
        Some(Value::Dictionary(d)) => d,
        _ => res,
    }
}

pub fn check_error(res: &Dictionary) -> Result<(), Error> {
    let status = status_dict(res);
    let ec = status
        .get("ec")
        .and_then(|v| v.as_signed_integer())
        .unwrap_or(0);
    if ec != 0 {
        let em = status
            .get("em")
            .and_then(|v| v.as_string())
            .unwrap_or_default();
        return Err(Error::AuthSrpWithMessage(ec, em.to_owned()));
    }

    Ok(())
}

/// GrandSlam's own status code, 409 means Apple already pushed a 2FA code and 434 asks for
/// an anisette resync
pub fn gsa_hsc(res: &Dictionary) -> Option<i64> {
    status_dict(res).get("hsc").and_then(|v| v.as_signed_integer())
}

pub fn decrypt_cbc(usr: &ClientVerifier<Sha256>, data: &[u8]) -> Result<Vec<u8>, Error> {
    let extra_data_key = create_session_key(usr, "extra data key:");
    let extra_data_iv = create_session_key(usr, "extra data iv:");
    let extra_data_iv = &extra_data_iv[..16];

    cbc::Decryptor::<aes::Aes256>::new_from_slices(&extra_data_key, extra_data_iv)
        .map_err(|_| Error::Parse)?
        .decrypt_padded_vec::<Pkcs7>(data)
        .map_err(|_| Error::Parse)
}

pub fn create_session_key(usr: &ClientVerifier<Sha256>, name: &str) -> Vec<u8> {
    Hmac::<Sha256>::new_from_slice(&usr.key())
        .unwrap()
        .chain_update(name.as_bytes())
        .finalize()
        .into_bytes()
        .to_vec()
}

impl Account {
    async fn gsa_post<T: serde::Serialize>(
        &self,
        headers: HeaderMap,
        packet: &T,
    ) -> Result<Dictionary, Error> {
        let mut buffer = Vec::new();
        plist::to_writer_xml(&mut buffer, packet)?;
        let res = self
            .client
            .post(GSA_ENDPOINT)
            .headers(headers)
            .body(buffer)
            .send()
            .await;
        parse_response(res).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn response(status: &[(&str, Value)]) -> Vec<u8> {
        let mut st = Dictionary::new();
        for (k, v) in status {
            st.insert(k.to_string(), v.clone());
        }
        let mut inner = Dictionary::new();
        inner.insert("Status".into(), Value::Dictionary(st));
        let mut outer = Dictionary::new();
        outer.insert("Response".into(), Value::Dictionary(inner));
        let mut buf = Vec::new();
        plist::to_writer_xml(&mut buf, &outer).unwrap();
        buf
    }

    #[test]
    fn html_error_pages_become_http_errors() {
        let err = parse_gsa_body("u", 503, b"<html>Service Unavailable</html>").unwrap_err();
        assert!(matches!(err, Error::GsaHttp { status: 503, .. }));
    }

    #[test]
    fn non_2xx_keeps_the_grandslam_code() {
        let body = response(&[("ec", Value::Integer((-20209).into())), ("em", "locked".into())]);
        let err = parse_gsa_body("u", 403, &body).unwrap_err();
        assert!(matches!(err, Error::AuthSrpWithMessage(-20209, _)));
    }

    #[test]
    fn success_without_a_plist_is_a_parse_error() {
        assert!(matches!(parse_gsa_body("u", 200, b"nope"), Err(Error::Parse)));
    }

    #[test]
    fn status_codes_are_read() {
        let body = response(&[("ec", Value::Integer(0.into())), ("hsc", Value::Integer(434.into()))]);
        let dict = parse_gsa_body("u", 200, &body).unwrap();
        assert_eq!(gsa_hsc(&dict), Some(434));
        assert!(check_error(&dict).is_ok());
    }

    #[test]
    fn missing_status_fields_do_not_panic() {
        let dict = Dictionary::new();
        assert!(check_error(&dict).is_ok());
        assert_eq!(gsa_hsc(&dict), None);
        let mut only_ec = Dictionary::new();
        only_ec.insert("ec".into(), Value::Integer((-80046).into()));
        assert!(matches!(check_error(&only_ec), Err(Error::AuthSrpWithMessage(-80046, _))));
    }
}
