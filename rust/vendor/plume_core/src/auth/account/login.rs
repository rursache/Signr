use plist::{Dictionary, Value};
use reqwest::header::{HeaderMap, HeaderValue};
use sha2::{Digest, Sha256};
use srp::groups::G2048;

use crate::Error;

use crate::auth::account::{check_error, parse_response};
use crate::auth::anisette_data::AnisetteData;
use crate::auth::{
    Account, ChallengeRequest, ChallengeRequestBody, GSA_ENDPOINT, InitRequest, InitRequestBody,
    LoginState, RequestHeader, TrustedPhoneNumber, TwoFactorAction, TwoFactorMethod,
    TwoFactorRequest,
};

#[macro_export]
macro_rules! plist_get_string {
    ($base:expr, $( $path:literal )+, $final_key:literal) => {{
        let mut current_val = $base;
        $(
            current_val = current_val
                .get($path)
                .expect(concat!("Missing dictionary key: ", $path))
                .as_dictionary()
                .expect(concat!("Key value is not a dictionary: ", $path));
        )+
        current_val
            .get($final_key)
            .expect(concat!("Missing string key: ", $final_key))
            .as_string()
            .expect(concat!("Value is not a string: ", $final_key))
            .to_string()
    }};

    ($base:expr, $key:literal) => {{
        $base
            .get($key)
            .expect(concat!("Missing key: ", $key))
            .as_string()
            .expect(concat!("Value is not a string: ", $key))
            .to_string()
    }};
}

impl Account {
    pub async fn login(
        appleid_closure: impl Fn() -> Result<(String, String), String>,
        tfa_closure: impl Fn(TwoFactorRequest) -> Result<TwoFactorAction, String>,
    ) -> Result<Account, Error> {
        let anisette = AnisetteData::new().await?;
        Account::login_with_anisette(appleid_closure, tfa_closure, anisette).await
    }

    pub async fn login_with_anisette<
        F: Fn() -> Result<(String, String), String>,
        G: Fn(TwoFactorRequest) -> Result<TwoFactorAction, String>,
    >(
        appleid_closure: F,
        tfa_closure: G,
        anisette: AnisetteData,
    ) -> Result<Account, Error> {
        let mut _self = Account::new_with_anisette(anisette)?;
        let (username, password) = appleid_closure().map_err(|e| {
            Error::AuthSrpWithMessage(0, format!("Failed to get Apple ID credentials: {}", e))
        })?;

        let mut response = _self.login_email_pass(&username, &password).await?;
        // Cached so the caller can be offered an SMS fallback even when a trusted
        // device handled the push. Fetched lazily the first time 2FA is needed.
        let mut trusted_phone_numbers: Vec<TrustedPhoneNumber> = Vec::new();

        loop {
            match response {
                LoginState::NeedsDevice2FA => {
                    response = _self.send_2fa_to_devices().await?;
                    if trusted_phone_numbers.is_empty() {
                        if let Ok(extras) = _self.get_auth_extras().await {
                            trusted_phone_numbers = extras.trusted_phone_numbers;
                        }
                    }
                }
                LoginState::Needs2FAVerification => {
                    let request = TwoFactorRequest {
                        method: TwoFactorMethod::Device,
                        trusted_phone_numbers: trusted_phone_numbers.clone(),
                    };
                    match tfa_closure(request).map_err(|e| {
                        Error::AuthSrpWithMessage(0, format!("Failed to get 2FA code: {}", e))
                    })? {
                        TwoFactorAction::SubmitCode(code) => {
                            response = _self.verify_2fa(code).await?
                        }
                        TwoFactorAction::SendSms(id) => {
                            response = _self.send_sms_2fa_to_devices(id).await?
                        }
                    }
                }
                LoginState::NeedsSMS2FA => {
                    if trusted_phone_numbers.is_empty() {
                        if let Ok(extras) = _self.get_auth_extras().await {
                            trusted_phone_numbers = extras.trusted_phone_numbers;
                        }
                    }
                    let id = trusted_phone_numbers.first().map(|p| p.id).unwrap_or(1);
                    response = _self.send_sms_2fa_to_devices(id).await?;
                }
                LoginState::NeedsSMS2FAVerification(body) => {
                    let request = TwoFactorRequest {
                        method: TwoFactorMethod::Sms,
                        trusted_phone_numbers: trusted_phone_numbers.clone(),
                    };
                    match tfa_closure(request).map_err(|e| {
                        Error::AuthSrpWithMessage(
                            0,
                            format!("Failed to get SMS 2FA code: {}", e),
                        )
                    })? {
                        TwoFactorAction::SubmitCode(code) => {
                            response = _self.verify_sms_2fa(code, body).await?
                        }
                        TwoFactorAction::SendSms(id) => {
                            response = _self.send_sms_2fa_to_devices(id).await?
                        }
                    }
                }
                LoginState::NeedsLogin => {
                    response = _self.login_email_pass(&username, &password).await?
                }
                LoginState::LoggedIn => return Ok(_self),
                LoginState::NeedsExtraStep(step) => {
                    if _self.get_pet().is_some() {
                        return Ok(_self);
                    } else {
                        return Err(Error::ExtraStep(step));
                    }
                }
            }
        }
    }

    pub async fn login_email_pass(
        &mut self,
        username: &str,
        password: &str,
    ) -> Result<LoginState, Error> {
        let username_for_spd = username.to_string().to_lowercase();
        let srp_client = srp::Client::<G2048, Sha256>::new_with_options(false);
        let a: Vec<u8> = (0..32).map(|_| rand::random::<u8>()).collect();
        let a_pub = srp_client.compute_public_ephemeral(&a);

        let anisette = self.get_anisette().await;

        let mut gsa_headers = HeaderMap::new();
        gsa_headers.insert(
            "Content-Type",
            HeaderValue::from_str("text/x-xml-plist").unwrap(),
        );
        gsa_headers.insert("Accept", HeaderValue::from_str("*/*").unwrap());
        gsa_headers.insert(
            "User-Agent",
            HeaderValue::from_str("akd/1.0 CFNetwork/978.0.7 Darwin/18.7.0").unwrap(),
        );
        gsa_headers.insert(
            "X-MMe-Client-Info",
            HeaderValue::from_str(&anisette.get_header("x-mme-client-info")?).unwrap(),
        );

        let header = RequestHeader {
            version: "1.0.1".to_string(),
        };
        let init_body = InitRequestBody {
            a_pub: plist::Value::Data(a_pub),
            cpd: anisette.to_plist(true, false, false),
            operation: "init".to_string(),
            ps: vec!["s2k".to_string(), "s2k_fo".to_string()],
            username: username_for_spd.clone(),
        };

        let init_packet = InitRequest {
            header: header.clone(),
            request: init_body,
        };

        let mut buffer = Vec::new();
        plist::to_writer_xml(&mut buffer, &init_packet)?;

        let res = self
            .client
            .post(GSA_ENDPOINT)
            .headers(gsa_headers.clone())
            .body(buffer)
            .send()
            .await;

        let res = parse_response(res).await?;
        check_error(&res)?;

        let salt = res.get("s").unwrap().as_data().unwrap();
        let b_pub = res.get("B").unwrap().as_data().unwrap();
        let iters = res.get("i").unwrap().as_signed_integer().unwrap();
        let c = res.get("c").unwrap().as_string().unwrap();

        let hashed_password = Sha256::digest(password.as_bytes());

        let mut password_buf = [0u8; 32];
        pbkdf2::pbkdf2::<hmac::Hmac<Sha256>>(
            &hashed_password,
            salt,
            iters as u32,
            &mut password_buf,
        )?;

        let verifier = srp_client
            .process_reply(&a, username_for_spd.as_bytes(), &password_buf, salt, b_pub)
            .unwrap();

        let challenge_body = ChallengeRequestBody {
            m: plist::Value::Data(verifier.proof().to_vec()),
            c: c.to_string(),
            cpd: anisette.to_plist(true, false, false),
            operation: "complete".to_string(),
            username: username_for_spd.clone(),
        };

        let challenge_packet = ChallengeRequest {
            header,
            request: challenge_body,
        };

        let mut buffer = Vec::new();
        plist::to_writer_xml(&mut buffer, &challenge_packet)?;

        gsa_headers.insert("Connection", HeaderValue::from_static("close"));

        let res = self
            .client
            .post(GSA_ENDPOINT)
            .headers(gsa_headers)
            .body(buffer)
            .send()
            .await;

        let res = parse_response(res).await?;
        check_error(&res)?;

        let m2 = res.get("M2").unwrap().as_data().unwrap();
        verifier.verify_server(m2).unwrap();

        let spd_encrypted = res.get("spd").unwrap().as_data().unwrap();
        let spd_decrypted = super::decrypt_cbc(&verifier, spd_encrypted);
        let mut spd: Dictionary = plist::from_bytes(&spd_decrypted).unwrap();

        if !spd.contains_key("appleId") {
            spd.insert(
                "appleId".to_string(),
                plist::Value::String(username_for_spd),
            );
        }

        self.spd = Some(spd);

        let status = res.get("Status").unwrap().as_dictionary().unwrap();
        if let Some(Value::String(auth_type)) = status.get("au") {
            return match auth_type.as_str() {
                "trustedDeviceSecondaryAuth" => Ok(LoginState::NeedsDevice2FA),
                "secondaryAuth" => Ok(LoginState::NeedsSMS2FA),
                other => Ok(LoginState::NeedsExtraStep(other.to_string())),
            };
        }

        Ok(LoginState::LoggedIn)
    }

    pub fn get_pet(&self) -> Option<String> {
        let base = self.spd.as_ref().unwrap();
        let token = base.get("t")?.as_dictionary()?;

        Some(plist_get_string!(token, "com.apple.gs.idms.pet", "token"))
    }

    pub fn get_name(&self) -> (String, String) {
        let base = self.spd.as_ref().unwrap();
        (plist_get_string!(base, "fn"), plist_get_string!(base, "ln"))
    }

    pub async fn get_anisette(&self) -> AnisetteData {
        let mut locked = self.anisette.lock().await;
        if locked.needs_refresh() {
            // Refresh can hit the network now that anisette may come from a remote provider,
            // so a transient failure must not panic. The current data stays valid past the
            // refresh point, so reuse it and try again on the next call.
            match locked.refresh().await {
                Ok(fresh) => *locked = fresh,
                Err(e) => log::warn!("anisette refresh failed, reusing current data: {e}"),
            }
        }
        locked.clone()
    }
}

#[cfg(test)]
mod srp_protocol_probe {
    use super::*;

    /// RS-263 follow-up: find out which key-stretching protocol Apple selects for an account.
    ///
    /// The SRP `init` step needs only a username, never a password, so this is safe to run with
    /// a real Apple ID. `login_email_pass` always stretches the password the `s2k` way; if Apple
    /// answers with `sp = s2k_fo` the proof we send is wrong and Apple reports it as error
    /// -22406 "Enter the correct password", which is indistinguishable from a real typo.
    ///
    ///   SIGNR_PROBE_APPLE_ID=you@example.com \
    ///     cargo test -p plume_core --features tweaks --lib srp_protocol_probe -- --ignored --nocapture
    #[tokio::test]
    #[ignore]
    async fn reports_selected_srp_protocol() {
        let _ = rustls::crypto::ring::default_provider().install_default();

        let username = std::env::var("SIGNR_PROBE_APPLE_ID")
            .expect("set SIGNR_PROBE_APPLE_ID to the Apple ID to probe");
        let username = username.to_lowercase();

        let anisette = AnisetteData::new().await.expect("no anisette tier succeeded");
        println!("anisette source: {:?}", anisette.source);

        let srp_client = srp::Client::<G2048, Sha256>::new_with_options(false);
        let a: Vec<u8> = (0..32).map(|_| rand::random::<u8>()).collect();
        let a_pub = srp_client.compute_public_ephemeral(&a);

        let mut gsa_headers = HeaderMap::new();
        gsa_headers.insert(
            "Content-Type",
            HeaderValue::from_str("text/x-xml-plist").unwrap(),
        );
        gsa_headers.insert("Accept", HeaderValue::from_str("*/*").unwrap());
        gsa_headers.insert(
            "User-Agent",
            HeaderValue::from_str("akd/1.0 CFNetwork/978.0.7 Darwin/18.7.0").unwrap(),
        );
        gsa_headers.insert(
            "X-MMe-Client-Info",
            HeaderValue::from_str(&anisette.get_header("x-mme-client-info").unwrap()).unwrap(),
        );

        let init_packet = InitRequest {
            header: RequestHeader {
                version: "1.0.1".to_string(),
            },
            request: InitRequestBody {
                a_pub: plist::Value::Data(a_pub),
                cpd: anisette.to_plist(true, false, false),
                operation: "init".to_string(),
                ps: vec!["s2k".to_string(), "s2k_fo".to_string()],
                username: username.clone(),
            },
        };

        let mut buffer = Vec::new();
        plist::to_writer_xml(&mut buffer, &init_packet).unwrap();

        let client = crate::client().unwrap();
        let res = client
            .post(GSA_ENDPOINT)
            .headers(gsa_headers)
            .body(buffer)
            .send()
            .await;

        let res = parse_response(res).await.expect("no response from GSA");
        println!("--- GSA init response ---");
        for (k, v) in res.iter() {
            let shown = match k.as_str() {
                "s" | "B" | "c" => "<redacted>".to_string(),
                _ => format!("{v:?}"),
            };
            println!("  {k} = {shown}");
        }

        if let Err(e) = check_error(&res) {
            println!("init reported an error: {e}");
            return;
        }

        let sp = res.get("sp").and_then(|v| v.as_string()).unwrap_or("<absent>");
        println!("\nselected protocol sp = {sp}");
        println!(
            "login_email_pass assumes s2k, so this account is {}",
            if sp == "s2k_fo" { "MISHANDLED" } else { "handled correctly" }
        );
    }
}

#[cfg(test)]
mod login_e2e {
    use super::*;

    /// RS-263 verification: prove a real password is accepted by Apple, without completing 2FA.
    ///
    /// The password is read from stdin so it never appears in an argument, an environment
    /// variable, or the shell history. Getting back a 2FA state IS the success signal: Apple only
    /// asks for a second factor once the SRP proof has been accepted.
    ///
    ///   read -rs "pw?Apple ID password: " && printf '%s' "$pw" | \
    ///     SIGNR_PROBE_APPLE_ID=you@example.com \
    ///     cargo test -p plume_core --features tweaks --lib login_e2e -- --ignored --nocapture
    ///   unset pw
    #[tokio::test]
    #[ignore]
    async fn password_is_accepted_by_apple() {
        use std::io::Read;

        let _ = rustls::crypto::ring::default_provider().install_default();

        let username = std::env::var("SIGNR_PROBE_APPLE_ID")
            .expect("set SIGNR_PROBE_APPLE_ID to the Apple ID to test");

        let mut password = String::new();
        std::io::stdin()
            .read_to_string(&mut password)
            .expect("pipe the password into stdin");
        let password = password.trim_end_matches(['\n', '\r']);
        assert!(!password.is_empty(), "no password on stdin");

        let anisette = AnisetteData::new().await.expect("no anisette tier succeeded");
        println!("anisette source: {:?}", anisette.source);

        let mut account = Account::new_with_anisette(anisette).expect("could not build account");

        match account.login_email_pass(&username, password).await {
            Ok(state) => {
                // Any of these means the SRP proof was accepted.
                println!("\nPASSWORD ACCEPTED -> {state:?}");
                println!("RS-263 verified: anisette + SRP auth work end to end.");
            }
            Err(e) => {
                println!("\nlogin failed: {e}");
                panic!("password not accepted: {e}");
            }
        }
    }
}
