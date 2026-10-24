use aes::cipher::consts::U16;
use aes_gcm::AesGcm;
use aes_gcm::aes::Aes256;
use aes_gcm::{AeadInOut, Nonce};
use hmac::digest::KeyInit;
use hmac::{Hmac, Mac};

use crate::Error;
use sha2::Sha256;

use crate::auth::account::check_error;
use crate::auth::{Account, AppToken, AuthTokenRequest, AuthTokenRequestBody, RequestHeader};

impl Account {
    pub async fn get_app_token(&self, app_name: &str) -> Result<AppToken, Error> {
        let spd = self.spd.as_ref().ok_or(Error::Parse)?;
        let dsid = spd.get("adsid").and_then(|v| v.as_string()).ok_or(Error::Parse)?;
        let auth_token = spd
            .get("GsIdmsToken")
            .and_then(|v| v.as_string())
            .ok_or(Error::Parse)?;

        // apptokens is where Apple answers -80046 for anisette that doesn't match the device
        let valid_anisette = self.fresh_anisette().await?;

        let sk = spd.get("sk").and_then(|v| v.as_data()).ok_or(Error::Parse)?;
        let c = spd.get("c").and_then(|v| v.as_data()).ok_or(Error::Parse)?;

        let checksum = Self::create_checksum(&sk.to_vec(), dsid, app_name);

        let header = RequestHeader {
            version: "1.0.1".to_string(),
        };
        let body = AuthTokenRequestBody {
            cpd: valid_anisette.cpd(),
            app: vec![app_name.to_string()],
            c: plist::Value::Data(c.to_vec()),
            operation: "apptokens".to_owned(),
            t: auth_token.to_string(),
            u: dsid.to_string(),
            checksum: plist::Value::Data(checksum),
        };

        let packet = AuthTokenRequest {
            header: header.clone(),
            request: body,
        };

        let res = self.gsa_post(valid_anisette.gsa_headers()?, &packet).await?;
        check_error(&res)?;

        let encrypted_token = res
            .get("et")
            .ok_or(Error::Parse)?
            .as_data()
            .ok_or(Error::Parse)?;

        if encrypted_token.len() < 3 + 16 + 16 {
            return Err(Error::Parse);
        }
        let header = &encrypted_token[0..3];
        if header != b"XYZ" {
            return Err(Error::AuthSrpWithMessage(
                0,
                "Encrypted token is in an unknown format.".to_string(),
            ));
        }
        let iv = &encrypted_token[3..19];
        let ciphertext_and_tag = &encrypted_token[19..];

        if sk.len() != 32 {
            return Err(Error::Parse);
        }
        if iv.len() != 16 {
            return Err(Error::Parse);
        }

        let key = aes_gcm::Key::<AesGcm<Aes256, U16>>::try_from(sk)?;
        let cipher = AesGcm::<Aes256, U16>::new(&key);
        let nonce = Nonce::<U16>::try_from(iv)?;

        let mut buf = ciphertext_and_tag.to_vec();

        cipher.decrypt_in_place(&nonce, header, &mut buf)?;

        let decrypted_token: plist::Dictionary =
            plist::from_bytes(&buf).map_err(|_| Error::Parse)?;

        let t_val = decrypted_token.get("t").ok_or(Error::Parse)?;
        let app_tokens = t_val.as_dictionary().ok_or(Error::Parse)?;
        let app_token_dict = app_tokens.get(app_name).ok_or(Error::Parse)?;
        let app_token = app_token_dict.as_dictionary().ok_or(Error::Parse)?;
        let token = app_token
            .get("token")
            .and_then(|v| v.as_string())
            .ok_or(Error::Parse)?;

        Ok(AppToken {
            app_tokens: app_tokens.clone(),
            auth_token: token.to_string(),
            app: app_name.to_string(),
        })
    }

    fn create_checksum(session_key: &Vec<u8>, dsid: &str, app_name: &str) -> Vec<u8> {
        Hmac::<Sha256>::new_from_slice(&session_key)
            .unwrap()
            .chain_update("apptokens".as_bytes())
            .chain_update(dsid.as_bytes())
            .chain_update(app_name.as_bytes())
            .finalize()
            .into_bytes()
            .to_vec()
    }
}
