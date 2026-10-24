use std::str::FromStr;

use crate::Error;
use base64::{Engine, engine::general_purpose};
use reqwest::Response;
use reqwest::header::{HeaderMap, HeaderName, HeaderValue};

use crate::auth::account::check_error;
use crate::auth::{Account, AuthenticationExtras, LoginState, PhoneNumber, VerifyBody, VerifyCode};

fn http_error(res: &Response) -> Error {
    Error::GsaHttp {
        url: res.url().to_string(),
        status: res.status().as_u16(),
    }
}

impl Account {
    pub async fn send_2fa_to_devices(&self) -> Result<LoginState, Error> {
        let headers = self.build_2fa_headers(false).await?;

        let res = self
            .client
            .get("https://gsa.apple.com/auth/verify/trusteddevice")
            .headers(headers)
            .send()
            .await?;

        if !res.status().is_success() {
            return Err(http_error(&res));
        }

        return Ok(LoginState::Needs2FAVerification);
    }

    pub async fn send_sms_2fa_to_devices(&self, phone_id: u32) -> Result<LoginState, Error> {
        let headers = self.build_2fa_headers(true).await?;

        let body = VerifyBody {
            phone_number: PhoneNumber { id: phone_id },
            mode: "sms".to_string(),
            security_code: None,
        };

        let res = self
            .client
            .put("https://gsa.apple.com/auth/verify/phone")
            .headers(headers)
            .json(&body)
            .send()
            .await?;

        if !res.status().is_success() {
            return Err(http_error(&res));
        }

        return Ok(LoginState::NeedsSMS2FAVerification(body));
    }

    pub async fn get_auth_extras(&self) -> Result<AuthenticationExtras, Error> {
        let headers = self.build_2fa_headers(true).await?;

        let req = self
            .client
            .get("https://gsa.apple.com/auth")
            .headers(headers)
            .header("Accept", "application/json")
            .send()
            .await?;
        let status = req.status().as_u16();
        let mut new_state = req.json::<AuthenticationExtras>().await?;
        if status == 201 {
            if let Some(phone) = new_state.trusted_phone_numbers.first() {
                new_state.new_state = Some(LoginState::NeedsSMS2FAVerification(VerifyBody {
                    phone_number: PhoneNumber { id: phone.id },
                    mode: "sms".to_string(),
                    security_code: None,
                }));
            }
        }

        Ok(new_state)
    }

    pub async fn verify_2fa(&self, code: String) -> Result<LoginState, Error> {
        self.fresh_anisette().await?;
        let headers = self.build_2fa_headers(false).await?;
        let res = self
            .client
            .get("https://gsa.apple.com/grandslam/GsService2/validate")
            .headers(headers)
            .header(
                HeaderName::from_str("security-code").unwrap(),
                HeaderValue::from_str(&code).map_err(|_| Error::Bad2faCode)?,
            )
            .send()
            .await?;

        let url = res.url().to_string();
        let status = res.status();
        let body = res.bytes().await?;
        match plist::from_bytes::<plist::Dictionary>(&body) {
            Ok(dict) => {
                check_error(&dict)?;
                if !status.is_success() {
                    return Err(Error::GsaHttp { url, status: status.as_u16() });
                }
            }
            Err(_) if status.is_success() => return Err(Error::Parse),
            Err(_) => return Err(Error::GsaHttp { url, status: status.as_u16() }),
        }

        Ok(LoginState::NeedsLogin)
    }

    pub async fn verify_sms_2fa(
        &self,
        code: String,
        mut body: VerifyBody,
    ) -> Result<LoginState, Error> {
        let headers = self.build_2fa_headers(true).await?;
        body.security_code = Some(VerifyCode { code });
        let res = self
            .client
            .post("https://gsa.apple.com/auth/verify/phone/securitycode")
            .headers(headers)
            .json(&body)
            .send()
            .await?;

        let status_code = res.status();

        // TODO: 423 http code may occur, in this case we to ask for sending
        // last code sent (unlikely it would even work), or try again later
        if status_code.is_server_error() || status_code.as_u16() == 429 {
            return Err(http_error(&res));
        }
        if !status_code.is_success() {
            return Err(Error::Bad2faCode);
        }

        Ok(LoginState::NeedsLogin)
    }

    async fn build_2fa_headers(&self, sms: bool) -> Result<HeaderMap, Error> {
        let spd = self.spd.as_ref().ok_or(Error::Parse)?;
        let dsid = spd.get("adsid").and_then(|v| v.as_string()).ok_or(Error::Parse)?;
        let token = spd
            .get("GsIdmsToken")
            .and_then(|v| v.as_string())
            .ok_or(Error::Parse)?;

        let identity_token = general_purpose::STANDARD.encode(format!("{}:{}", dsid, token));

        let mut headers = self.get_anisette().await.two_factor_headers(sms)?;
        headers.append(
            "X-Apple-Identity-Token",
            HeaderValue::from_str(&identity_token)
                .map_err(|_| Error::InvalidHeader("X-Apple-Identity-Token".into()))?,
        );

        Ok(headers)
    }
}
