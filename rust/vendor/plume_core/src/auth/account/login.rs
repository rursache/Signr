use base64::{Engine, engine::general_purpose};
use plist::{Dictionary, Value};
use reqwest::header::HeaderValue;
use sha2::{Digest, Sha256};
use srp::groups::G2048;

use crate::Error;

use crate::auth::account::{check_error, gsa_hsc};
use crate::auth::anisette_data::{AnisetteData, AnisetteSource};
use crate::auth::{
    Account, ChallengeRequest, ChallengeRequestBody, InitRequest, InitRequestBody, LoginState,
    RequestHeader, TrustedPhoneNumber, TwoFactorAction, TwoFactorMethod, TwoFactorRequest,
};

/// The first login plus two after 2FA, more than that means Apple keeps sending us around
const MAX_LOGIN_ATTEMPTS: u32 = 3;

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
        let mut logins = 1;
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
                    _self.fresh_anisette().await?;
                    response = _self.login_email_pass(&username, &password).await?;
                    logins += 1;
                    // Stop before pushing or prompting for a code that could never be used
                    if logins >= MAX_LOGIN_ATTEMPTS && asks_for_two_factor(&response) {
                        return Err(Error::TooMany2faRounds);
                    }
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

        let mut anisette = self.get_anisette().await;

        let header = RequestHeader {
            version: "1.0.1".to_string(),
        };

        // Apple answers hsc 434 when it wants the remote anisette resynced, AltSign then
        // resends init with the same SRP A, once per login
        let mut resynced = false;
        let res = loop {
            let init_packet = InitRequest {
                header: header.clone(),
                request: InitRequestBody {
                    a_pub: plist::Value::Data(a_pub.clone()),
                    cpd: anisette.cpd(),
                    operation: "init".to_string(),
                    ps: vec!["s2k".to_string(), "s2k_fo".to_string()],
                    username: username_for_spd.clone(),
                },
            };
            let res = self.gsa_post(anisette.gsa_headers()?, &init_packet).await?;
            if gsa_hsc(&res) != Some(434) || anisette.source != AnisetteSource::RemoteV3 {
                break res;
            }
            if resynced {
                return Err(Error::AnisetteResync("Apple asked for a second resync".into()));
            }
            let sim = resync_data(&res).ok_or_else(|| {
                Error::AnisetteResync("Apple sent no X-Apple-I-MD-DATA".into())
            })?;
            anisette = anisette.resync(&sim).await?;
            *self.anisette.lock().await = anisette.clone();
            resynced = true;
        };
        check_error(&res)?;

        let salt = res.get("s").and_then(|v| v.as_data()).ok_or(Error::Parse)?;
        let b_pub = res.get("B").and_then(|v| v.as_data()).ok_or(Error::Parse)?;
        let iters = res
            .get("i")
            .and_then(|v| v.as_signed_integer())
            .ok_or(Error::Parse)?;
        let c = res.get("c").and_then(|v| v.as_string()).ok_or(Error::Parse)?;
        let protocol = res.get("sp").and_then(|v| v.as_string()).unwrap_or("s2k");

        let password_buf = derive_password(password, protocol, salt, iters as u32)?;

        let verifier = srp_client
            .process_reply(&a, username_for_spd.as_bytes(), &password_buf, salt, b_pub)
            .map_err(|_| Error::Parse)?;

        let challenge_body = ChallengeRequestBody {
            m: plist::Value::Data(verifier.proof().to_vec()),
            c: c.to_string(),
            cpd: anisette.cpd(),
            operation: "complete".to_string(),
            username: username_for_spd.clone(),
        };

        let challenge_packet = ChallengeRequest {
            header,
            request: challenge_body,
        };

        let mut gsa_headers = anisette.gsa_headers()?;
        gsa_headers.insert("Connection", HeaderValue::from_static("close"));

        let res = self.gsa_post(gsa_headers, &challenge_packet).await?;
        check_error(&res)?;

        let m2 = res.get("M2").and_then(|v| v.as_data()).ok_or(Error::Parse)?;
        verifier.verify_server(m2).map_err(|_| {
            Error::AuthSrpWithMessage(0, "Apple's server proof didn't verify".to_string())
        })?;

        let spd_encrypted = res.get("spd").and_then(|v| v.as_data()).ok_or(Error::Parse)?;
        let spd_decrypted = super::decrypt_cbc(&verifier, spd_encrypted)?;
        let mut spd: Dictionary = plist::from_bytes(&spd_decrypted)?;

        if !spd.contains_key("appleId") {
            spd.insert(
                "appleId".to_string(),
                plist::Value::String(username_for_spd),
            );
        }

        self.spd = Some(spd);

        let status = res
            .get("Status")
            .and_then(|v| v.as_dictionary())
            .ok_or(Error::Parse)?;
        match status.get("au") {
            Some(Value::String(auth_type)) if !auth_type.is_empty() => {
                return match auth_type.as_str() {
                    "trustedDeviceSecondaryAuth" => Ok(LoginState::NeedsDevice2FA),
                    "secondaryAuth" => Ok(LoginState::NeedsSMS2FA),
                    other => Ok(LoginState::NeedsExtraStep(other.to_string())),
                };
            }
            // Apple already pushed a code to the trusted devices, asking again would be a
            // second request AltSign deliberately avoids
            _ if gsa_hsc(&res) == Some(409) => return Ok(LoginState::Needs2FAVerification),
            _ => {}
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

    /// Anisette right before the requests where AltSign refreshes it (GsService2/validate, the
    /// login after 2FA and apptokens), same identity with a new one-time password
    pub async fn fresh_anisette(&self) -> Result<AnisetteData, Error> {
        let mut locked = self.anisette.lock().await;
        match locked.refresh().await {
            Ok(fresh) => *locked = fresh,
            Err(e) if locked.is_valid() => {
                log::warn!("anisette refresh failed, reusing current data: {e}")
            }
            Err(e) => return Err(e),
        }
        Ok(locked.clone())
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

fn resync_data(res: &Dictionary) -> Option<String> {
    let status = res.get("Status").and_then(|v| v.as_dictionary())?;
    match status.get("X-Apple-I-MD-DATA")? {
        Value::String(s) if !s.is_empty() => Some(s.clone()),
        Value::Data(d) if !d.is_empty() => Some(general_purpose::STANDARD.encode(d)),
        _ => None,
    }
}

fn asks_for_two_factor(state: &LoginState) -> bool {
    matches!(
        state,
        LoginState::NeedsDevice2FA
            | LoginState::NeedsSMS2FA
            | LoginState::Needs2FAVerification
            | LoginState::NeedsSMS2FAVerification(_)
    )
}

/// `s2k_fo` stretches the lowercase hex form of the SHA-256 digest instead of its raw bytes
fn derive_password(
    password: &str,
    protocol: &str,
    salt: &[u8],
    iterations: u32,
) -> Result<[u8; 32], Error> {
    let digest = Sha256::digest(password.as_bytes());
    let hex: String;
    let input: &[u8] = if protocol == "s2k_fo" {
        hex = digest.iter().map(|b| format!("{b:02x}")).collect();
        hex.as_bytes()
    } else {
        &digest
    };
    let mut out = [0u8; 32];
    pbkdf2::pbkdf2::<hmac::Hmac<Sha256>>(input, salt, iterations, &mut out)?;
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn s2k_fo_stretches_the_hex_digest() {
        let salt = b"saltsaltsaltsalt";
        let s2k = derive_password("hunter2", "s2k", salt, 1000).unwrap();
        let fo = derive_password("hunter2", "s2k_fo", salt, 1000).unwrap();
        assert_ne!(s2k, fo);

        let hex: String = Sha256::digest(b"hunter2").iter().map(|b| format!("{b:02x}")).collect();
        let mut expected = [0u8; 32];
        pbkdf2::pbkdf2::<hmac::Hmac<Sha256>>(hex.as_bytes(), salt, 1000, &mut expected).unwrap();
        assert_eq!(fo, expected);
    }

    #[test]
    fn resync_data_accepts_string_or_data() {
        let mut status = Dictionary::new();
        status.insert("X-Apple-I-MD-DATA".into(), Value::String("c2lt".into()));
        let mut res = Dictionary::new();
        res.insert("Status".into(), Value::Dictionary(status.clone()));
        assert_eq!(resync_data(&res).as_deref(), Some("c2lt"));

        status.insert("X-Apple-I-MD-DATA".into(), Value::Data(b"sim".to_vec()));
        res.insert("Status".into(), Value::Dictionary(status));
        assert_eq!(resync_data(&res).as_deref(), Some("c2lt"));

        assert_eq!(resync_data(&Dictionary::new()), None);

        let mut status = Dictionary::new();
        status.insert("X-Apple-I-MD-DATA".into(), Value::String(String::new()));
        res.insert("Status".into(), Value::Dictionary(status));
        assert_eq!(resync_data(&res), None);
    }

    #[test]
    fn two_factor_states_are_recognized() {
        assert!(asks_for_two_factor(&LoginState::NeedsDevice2FA));
        assert!(asks_for_two_factor(&LoginState::Needs2FAVerification));
        assert!(!asks_for_two_factor(&LoginState::LoggedIn));
        assert!(!asks_for_two_factor(&LoginState::NeedsLogin));
    }
}

#[cfg(test)]
mod srp_protocol_probe {
    use super::*;

    /// RS-263 follow-up: find out which key-stretching protocol Apple selects for an account.
    ///
    /// The SRP `init` step needs only a username, never a password, so this is safe to run with
    /// a real Apple ID, and `login_email_pass` stretches the password the way `sp` asks for so
    /// both `s2k` and `s2k_fo` accounts are handled
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

        let gsa_headers = anisette.gsa_headers().unwrap();

        let init_packet = InitRequest {
            header: RequestHeader {
                version: "1.0.1".to_string(),
            },
            request: InitRequestBody {
                a_pub: plist::Value::Data(a_pub),
                cpd: anisette.cpd(),
                operation: "init".to_string(),
                ps: vec!["s2k".to_string(), "s2k_fo".to_string()],
                username: username.clone(),
            },
        };

        let mut buffer = Vec::new();
        plist::to_writer_xml(&mut buffer, &init_packet).unwrap();

        let client = crate::client().unwrap();
        let res = client
            .post(crate::auth::GSA_ENDPOINT)
            .headers(gsa_headers)
            .body(buffer)
            .send()
            .await;

        let res = crate::auth::account::parse_response(res)
            .await
            .expect("no response from GSA");
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
