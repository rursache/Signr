// Implementing the SideStore Anisette v3 protocol the way AltServer 1.8.2 uses it: the server's
// own client_info and user_agent go to Apple unchanged, and the provisioned identity is only
// reused while the server still reports the client_info it was provisioned under

use std::{
    collections::HashMap,
    fs,
    io::{Cursor, Write as _},
    path::{Path, PathBuf},
    time::Duration,
};

use async_trait::async_trait;
use base64::Engine;
use base64::engine::general_purpose;
use chrono::{DateTime, SubsecRound, Utc};
use futures_util::{SinkExt, stream::StreamExt};
use log::debug;
use plist::{Data, Dictionary};
use reqwest::{Client, ClientBuilder, RequestBuilder, Url, header::HeaderValue};
use serde::{Deserialize, Deserializer, Serialize, Serializer, de::Error as _};
use sha2::{Digest, Sha256};
use std::fmt::Write;
use tokio_tungstenite::{connect_async, tungstenite::Message};
use uuid::Uuid;

use crate::{AnisetteError, anisette_headers_provider::AnisetteHeadersProvider};

pub const XCODE_VERSION: &str = "27.0 (27A5218g)";
pub const APP_INFO: &str = "com.apple.gs.xcode.auth";
const LOOKUP_URL: &str = "https://gsa.apple.com/grandslam/GsService2/lookup";
const REQUEST_TIMEOUT: Duration = Duration::from_secs(30);
const PROVISIONING_TIMEOUT: Duration = Duration::from_secs(90);

/// Mac identities that Android CoreADI and Windows iTunes ADI servers present
const NON_MAC_ADI_IDENTITIES: [&str; 2] = [
    "<MacBookPro13,2> <macOS;13.1;22C65>",
    "<MacBookPro15,1> <Mac OS X;10.15.2;19C57>",
];
/// Implementation-Version prefixes of the Android CoreADI servers (Dadoum's anisette-v3-server
/// and omnisette-server). The Mac ADI servers report "anisette-v3-server (native-c ...)"
const NON_MAC_ADI_IMPLEMENTATIONS: [&str; 2] = ["anisette-v3-server v", "omnisette-server"];

fn plist_to_string<T: serde::Serialize>(value: &T) -> Result<String, AnisetteError> {
    let mut buf: Vec<u8> = Vec::new();
    plist::to_writer_xml(Cursor::new(&mut buf), &value)?;
    String::from_utf8(buf).map_err(|e| AnisetteError::InvalidArgument(e.to_string()))
}

fn bin_serialize<S>(x: &[u8], s: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    s.serialize_bytes(x)
}

fn bin_serialize_opt<S>(x: &Option<Vec<u8>>, s: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    x.clone().map(|i| Data::new(i)).serialize(s)
}

fn bin_deserialize_opt<'de, D>(d: D) -> Result<Option<Vec<u8>>, D::Error>
where
    D: Deserializer<'de>,
{
    let s: Option<Data> = Deserialize::deserialize(d)?;
    Ok(s.map(|i| i.into()))
}

fn bin_deserialize_16<'de, D>(d: D) -> Result<[u8; 16], D::Error>
where
    D: Deserializer<'de>,
{
    let s: Data = Deserialize::deserialize(d)?;
    let s: Vec<u8> = s.into();
    s.try_into()
        .map_err(|_| D::Error::custom("keychain identifier must be 16 bytes"))
}

fn encode_hex(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for &b in bytes {
        write!(&mut s, "{:02x}", b).unwrap();
    }
    s
}

fn base64_encode(data: &[u8]) -> String {
    general_purpose::STANDARD.encode(data)
}

fn base64_decode(data: &str) -> Result<Vec<u8>, AnisetteError> {
    general_purpose::STANDARD
        .decode(data.trim())
        .map_err(|e| AnisetteError::Provisioning(format!("invalid base64 from the server: {e}")))
}

fn client_time() -> String {
    let dt: DateTime<Utc> = Utc::now().round_subsecs(0);
    dt.format("%+").to_string().replace("+00:00", "Z")
}

/// Apple has rejected every non-Mac ADI identity since October 2026: Android data with -80045
/// at init, Android and Windows data with -80046 at apptokens after the password and 2FA code
/// were already spent, so refusing those servers up front keeps that from ever reaching Apple
pub fn check_server_identity(
    client_info: &str,
    user_agent: &str,
    implementation: Option<&str>,
) -> Result<(), AnisetteError> {
    for (name, value) in [("client_info", client_info), ("user_agent", user_agent)] {
        if value.trim().is_empty() || HeaderValue::from_str(value).is_err() {
            return Err(AnisetteError::InvalidClientInfo(format!("{name} {value:?}")));
        }
    }

    let os = client_info.split('<').nth(2).unwrap_or_default();
    let mac = os.starts_with("macOS;") || os.starts_with("Mac OS X;");
    let known_non_mac = NON_MAC_ADI_IDENTITIES.iter().any(|i| client_info.starts_with(i))
        || implementation.is_some_and(|v| {
            NON_MAC_ADI_IMPLEMENTATIONS.iter().any(|p| v.trim().starts_with(p))
        });
    // Apple answers anything naming com.apple.dt.Xcode with HTTP 503
    if !mac || known_non_mac || client_info.contains("com.apple.dt.Xcode") {
        return Err(AnisetteError::UnsupportedServerIdentity {
            client_info: client_info.to_string(),
        });
    }
    Ok(())
}

fn is_apple_provisioning_url(url: &str) -> bool {
    Url::parse(url).is_ok_and(|u| {
        u.scheme() == "https"
            && u.host_str() == Some("gsa.apple.com")
            && matches!(u.port(), None | Some(443))
            && u.username().is_empty()
            && u.password().is_none()
    })
}

fn provisioning_ws_url(server: &str) -> Result<String, AnisetteError> {
    let base = server.trim_end_matches('/');
    let ws = if let Some(rest) = base.strip_prefix("https://") {
        format!("wss://{rest}")
    } else if let Some(rest) = base.strip_prefix("http://") {
        format!("ws://{rest}")
    } else {
        return Err(AnisetteError::InvalidArgument(format!("anisette server URL {server}")));
    };
    Ok(format!("{ws}/v3/provisioning_session"))
}

/// The provisioned identity is a device credential, so keep it private to this user
fn write_private(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    let mut options = fs::OpenOptions::new();
    options.write(true).create(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options.open(path)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        file.set_permissions(fs::Permissions::from_mode(0o600))?;
    }
    file.write_all(bytes)
}

#[derive(Deserialize, Clone, Debug)]
struct AnisetteClientInfo {
    client_info: String,
    user_agent: String,
}

#[derive(Serialize, Deserialize)]
pub struct AnisetteState {
    #[serde(
        serialize_with = "bin_serialize",
        deserialize_with = "bin_deserialize_16"
    )]
    keychain_identifier: [u8; 16],
    #[serde(
        serialize_with = "bin_serialize_opt",
        deserialize_with = "bin_deserialize_opt"
    )]
    adi_pb: Option<Vec<u8>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    provisioned_client_info: Option<String>,
}

impl Default for AnisetteState {
    fn default() -> Self {
        AnisetteState {
            keychain_identifier: rand::random::<[u8; 16]>(),
            adi_pb: None,
            provisioned_client_info: None,
        }
    }
}

impl AnisetteState {
    pub fn new() -> AnisetteState {
        AnisetteState::default()
    }

    pub fn is_provisioned(&self) -> bool {
        self.adi_pb.is_some()
    }

    /// State from before this field existed, or from a server whose identity has changed since,
    /// has to be provisioned again, like AltServer does
    pub fn is_usable_for(&self, client_info: &str) -> bool {
        self.is_provisioned() && self.provisioned_client_info.as_deref() == Some(client_info)
    }

    fn load(path: &Path) -> Option<AnisetteState> {
        plist::from_file(path).ok()
    }

    fn save(&self, path: &Path) -> Result<(), AnisetteError> {
        let mut buf = Vec::new();
        plist::to_writer_xml(&mut buf, self)?;
        write_private(path, &buf)?;
        Ok(())
    }

    fn md_lu(&self) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(&self.keychain_identifier);
        hasher.finalize().into()
    }

    fn device_id(&self) -> String {
        Uuid::from_bytes(self.keychain_identifier).to_string()
    }
}

pub struct AnisetteClient {
    client_info: AnisetteClientInfo,
    url: String,
    http: Client,
}

#[derive(Serialize)]
#[serde(rename_all = "PascalCase")]
struct ProvisionBodyData {
    header: Dictionary,
    request: Dictionary,
}

#[derive(Debug)]
pub struct AnisetteData {
    machine_id: String,
    one_time_password: String,
    routing_info: String,
    device_description: String,
    user_agent: String,
    local_user_id: String,
    device_unique_identifier: String,
}

impl AnisetteData {
    /// No X-Apple-I-SRL-NO: AltSign never sends one, and the real serial of this Mac next to
    /// a remote server's Mac identity would be a mismatch of its own
    pub fn get_headers(&self) -> HashMap<String, String> {
        HashMap::from_iter(
            [
                ("X-Apple-I-Client-Time".to_string(), client_time()),
                ("X-Apple-I-TimeZone".to_string(), "UTC".to_string()),
                ("X-Apple-Locale".to_string(), "en_US".to_string()),
                ("X-Apple-I-MD-RINFO".to_string(), self.routing_info.clone()),
                ("X-Apple-I-MD-LU".to_string(), self.local_user_id.clone()),
                (
                    "X-Mme-Device-Id".to_string(),
                    self.device_unique_identifier.clone(),
                ),
                ("X-Apple-I-MD".to_string(), self.one_time_password.clone()),
                ("X-Apple-I-MD-M".to_string(), self.machine_id.clone()),
                (
                    "X-Mme-Client-Info".to_string(),
                    self.device_description.clone(),
                ),
                ("User-Agent".to_string(), self.user_agent.clone()),
            ]
            .into_iter(),
        )
    }
}

fn make_reqwest() -> Result<Client, AnisetteError> {
    const APPLE_ROOT: &[u8] = include_bytes!("./apple_root.der");
    Ok(ClientBuilder::new()
        .add_root_certificate(reqwest::Certificate::from_der(APPLE_ROOT)?)
        .http1_title_case_headers()
        .redirect(reqwest::redirect::Policy::none())
        .timeout(REQUEST_TIMEOUT)
        .build()?)
}

fn provisioning_error(what: &str) -> AnisetteError {
    AnisetteError::Provisioning(format!("unexpected response from Apple: {what}"))
}

fn response_dict(text: &str) -> Result<Dictionary, AnisetteError> {
    plist::Value::from_reader(Cursor::new(text))?
        .into_dictionary()
        .ok_or_else(|| provisioning_error("not a dictionary"))
}

fn string_in<'a>(dict: &'a Dictionary, key: &str) -> Result<&'a str, AnisetteError> {
    dict.get(key)
        .and_then(|v| v.as_string())
        .ok_or_else(|| provisioning_error(key))
}

impl AnisetteClient {
    pub async fn new(url: String) -> Result<AnisetteClient, AnisetteError> {
        let url = url.trim_end_matches('/').to_string();
        let http = make_reqwest()?;
        let response = http
            .get(format!("{url}/v3/client_info"))
            .send()
            .await?
            .error_for_status()?;
        let implementation = response
            .headers()
            .get("implementation-version")
            .and_then(|v| v.to_str().ok())
            .map(str::to_string);
        let client_info = response.json::<AnisetteClientInfo>().await?;
        check_server_identity(
            &client_info.client_info,
            &client_info.user_agent,
            implementation.as_deref(),
        )?;
        Ok(AnisetteClient {
            client_info,
            url,
            http,
        })
    }

    pub fn client_info(&self) -> &str {
        &self.client_info.client_info
    }

    fn build_apple_request(
        &self,
        state: &AnisetteState,
        builder: RequestBuilder,
    ) -> RequestBuilder {
        builder
            .header("X-Mme-Client-Info", &self.client_info.client_info)
            .header("User-Agent", &self.client_info.user_agent)
            .header("Content-Type", "text/x-xml-plist")
            .header("Accept", "text/x-xml-plist")
            .header("X-Xcode-Version", XCODE_VERSION)
            .header("X-Apple-App-Info", APP_INFO)
            .header("Connection", "close")
            .header("X-Apple-I-MD-LU", encode_hex(&state.md_lu()))
            .header("X-Mme-Device-Id", state.device_id())
            .header("X-Apple-I-Client-Time", client_time())
            .header("X-Apple-I-TimeZone", "UTC")
            .header("X-Apple-Locale", "en_US")
    }

    /// `sim` is the X-Apple-I-MD-DATA Apple sends with hsc 434 to ask for a resync
    pub async fn get_headers(
        &self,
        state: &AnisetteState,
        sim: Option<&str>,
    ) -> Result<AnisetteData, AnisetteError> {
        #[derive(Serialize)]
        struct GetHeadersBody {
            identifier: String,
            adi_pb: String,
            #[serde(skip_serializing_if = "Option::is_none")]
            sim: Option<String>,
            #[serde(skip_serializing_if = "Option::is_none")]
            device_id: Option<String>,
            #[serde(skip_serializing_if = "Option::is_none")]
            md_lu: Option<String>,
        }
        let body = GetHeadersBody {
            identifier: base64_encode(&state.keychain_identifier),
            adi_pb: base64_encode(
                state
                    .adi_pb
                    .as_ref()
                    .ok_or(AnisetteError::AnisetteNotProvisioned)?,
            ),
            sim: sim.map(str::to_string),
            device_id: sim.map(|_| state.device_id()),
            md_lu: sim.map(|_| encode_hex(&state.md_lu())),
        };

        #[derive(Deserialize)]
        #[serde(tag = "result")]
        enum AnisetteHeaders {
            GetHeadersError {
                message: String,
            },
            Headers {
                #[serde(rename = "X-Apple-I-MD-M")]
                machine_id: String,
                #[serde(rename = "X-Apple-I-MD")]
                one_time_password: String,
                #[serde(rename = "X-Apple-I-MD-RINFO")]
                routing_info: String,
            },
        }

        let headers = self
            .http
            .post(format!("{}/v3/get_headers", self.url))
            .json(&body)
            .send()
            .await?
            .json::<AnisetteHeaders>()
            .await?;
        match headers {
            AnisetteHeaders::GetHeadersError { message } if message.contains("-45061") => {
                Err(AnisetteError::AnisetteNotProvisioned)
            }
            AnisetteHeaders::GetHeadersError { message } => Err(AnisetteError::GetHeaders(message)),
            AnisetteHeaders::Headers {
                machine_id,
                one_time_password,
                routing_info,
            } => Ok(AnisetteData {
                machine_id,
                one_time_password,
                routing_info,
                device_description: self.client_info.client_info.clone(),
                user_agent: self.client_info.user_agent.clone(),
                local_user_id: encode_hex(&state.md_lu()),
                device_unique_identifier: state.device_id(),
            }),
        }
    }

    pub async fn provision(&self, state: &mut AnisetteState) -> Result<(), AnisetteError> {
        tokio::time::timeout(PROVISIONING_TIMEOUT, self.provision_session(state))
            .await
            .map_err(|_| AnisetteError::ProvisioningTimeout)?
    }

    async fn apple_request(
        &self,
        state: &AnisetteState,
        url: &str,
        request: Dictionary,
    ) -> Result<Dictionary, AnisetteError> {
        let body = ProvisionBodyData {
            header: Dictionary::new(),
            request,
        };
        let text = self
            .build_apple_request(state, self.http.post(url))
            .body(plist_to_string(&body)?)
            .send()
            .await?
            .error_for_status()?
            .text()
            .await?;
        response_dict(&text)?
            .remove("Response")
            .and_then(|v| v.into_dictionary())
            .ok_or_else(|| provisioning_error("Response"))
    }

    async fn provision_session(&self, state: &mut AnisetteState) -> Result<(), AnisetteError> {
        debug!("Provisioning Anisette");
        let text = self
            .build_apple_request(state, self.http.get(LOOKUP_URL))
            .send()
            .await?
            .error_for_status()?
            .text()
            .await?;
        let lookup = response_dict(&text)?;
        let urls = lookup
            .get("urls")
            .and_then(|v| v.as_dictionary())
            .ok_or_else(|| provisioning_error("urls"))?;
        let start_provisioning_url = string_in(urls, "midStartProvisioning")?.to_string();
        let end_provisioning_url = string_in(urls, "midFinishProvisioning")?.to_string();
        for url in [&start_provisioning_url, &end_provisioning_url] {
            if !is_apple_provisioning_url(url) {
                return Err(AnisetteError::Provisioning(format!(
                    "refusing a provisioning URL outside gsa.apple.com: {url}"
                )));
            }
        }
        debug!(
            "Got provisioning urls: {} and {}",
            start_provisioning_url, end_provisioning_url
        );

        let (mut connection, _) = connect_async(&provisioning_ws_url(&self.url)?).await?;

        #[derive(Deserialize)]
        #[serde(tag = "result")]
        enum ProvisionInput {
            GiveIdentifier,
            GiveStartProvisioningData,
            GiveEndProvisioningData { cpim: String },
            ProvisioningSuccess { adi_pb: String },
        }

        loop {
            let message = match connection.next().await {
                Some(Ok(message)) => message,
                Some(Err(e)) => return Err(e.into()),
                None => {
                    return Err(AnisetteError::Provisioning(
                        "the anisette server closed the provisioning session".into(),
                    ));
                }
            };
            if message.is_close() {
                return Err(AnisetteError::Provisioning(
                    "the anisette server ended provisioning before it finished".into(),
                ));
            }
            if !message.is_text() {
                continue;
            }

            let reply = match serde_json::from_str::<ProvisionInput>(message.to_text()?)? {
                ProvisionInput::GiveIdentifier => {
                    serde_json::json!({ "identifier": base64_encode(&state.keychain_identifier) })
                }
                ProvisionInput::GiveStartProvisioningData => {
                    debug!("GiveStartProvisioningData");
                    let response = self
                        .apple_request(state, &start_provisioning_url, Dictionary::new())
                        .await?;
                    serde_json::json!({ "spim": string_in(&response, "spim")? })
                }
                ProvisionInput::GiveEndProvisioningData { cpim } => {
                    debug!("GiveEndProvisioningData");
                    let request = Dictionary::from_iter([("cpim", cpim)]);
                    let response = self
                        .apple_request(state, &end_provisioning_url, request)
                        .await?;
                    serde_json::json!({
                        "ptm": string_in(&response, "ptm")?,
                        "tk": string_in(&response, "tk")?,
                    })
                }
                ProvisionInput::ProvisioningSuccess { adi_pb } => {
                    debug!("ProvisioningSuccess");
                    state.adi_pb = Some(base64_decode(&adi_pb)?);
                    let _ = connection.close(None).await;
                    return Ok(());
                }
            };
            connection.send(Message::Text(reply.to_string().into())).await?;
        }
    }
}

pub struct RemoteAnisetteProviderV3 {
    client_url: String,
    client: Option<AnisetteClient>,
    configuration_path: PathBuf,
}

impl RemoteAnisetteProviderV3 {
    pub fn new(url: String, configuration_path: PathBuf) -> RemoteAnisetteProviderV3 {
        RemoteAnisetteProviderV3 {
            client_url: url,
            client: None,
            configuration_path,
        }
    }

    fn state_path(&self) -> PathBuf {
        self.configuration_path.join("state.plist")
    }

    async fn take_client(&mut self) -> Result<AnisetteClient, AnisetteError> {
        match self.client.take() {
            Some(client) => Ok(client),
            None => AnisetteClient::new(self.client_url.clone()).await,
        }
    }

    async fn provision_new(
        client: &AnisetteClient,
        path: &Path,
    ) -> Result<AnisetteState, AnisetteError> {
        let mut state = AnisetteState::new();
        client.provision(&mut state).await?;
        state.provisioned_client_info = Some(client.client_info().to_string());
        state.save(path)?;
        Ok(state)
    }

    /// Without `allow_provisioning` nothing reaches Apple and a state that would need a new
    /// identity fails with NeedsProvisioning, so retries and mid-login refreshes can never mint
    /// a new device behind the user's back
    pub async fn headers(
        &mut self,
        allow_provisioning: bool,
    ) -> Result<HashMap<String, String>, AnisetteError> {
        let client = self.take_client().await?;
        fs::create_dir_all(&self.configuration_path)?;
        let path = self.state_path();

        let mut provisioned_now = false;
        let mut state = match AnisetteState::load(&path) {
            Some(state) if state.is_usable_for(client.client_info()) => state,
            _ if !allow_provisioning => return Err(AnisetteError::NeedsProvisioning),
            _ => {
                provisioned_now = true;
                Self::provision_new(&client, &path).await?
            }
        };

        let data = match client.get_headers(&state, None).await {
            Ok(data) => data,
            Err(AnisetteError::AnisetteNotProvisioned) if !allow_provisioning => {
                return Err(AnisetteError::NeedsProvisioning);
            }
            Err(AnisetteError::AnisetteNotProvisioned) if !provisioned_now => {
                state = Self::provision_new(&client, &path).await?;
                client.get_headers(&state, None).await?
            }
            Err(e) => return Err(e),
        };
        self.client = Some(client);
        Ok(data.get_headers())
    }

    /// Answer Apple's hsc 434 with the X-Apple-I-MD-DATA it sent
    pub async fn resync(&mut self, sim: &str) -> Result<HashMap<String, String>, AnisetteError> {
        let client = self.take_client().await?;
        let state = AnisetteState::load(&self.state_path())
            .filter(|s| s.is_usable_for(client.client_info()))
            .ok_or_else(|| {
                AnisetteError::ResyncUnavailable(
                    "the server's identity changed since provisioning".into(),
                )
            })?;
        let data = client.get_headers(&state, Some(sim)).await?;
        self.client = Some(client);
        Ok(data.get_headers())
    }
}

#[async_trait]
impl AnisetteHeadersProvider for RemoteAnisetteProviderV3 {
    async fn get_anisette_headers(
        &mut self,
        skip_provisioning: bool,
    ) -> Result<HashMap<String, String>, AnisetteError> {
        self.headers(!skip_provisioning).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const MAC: &str = "<MacBookPro13,3> <Mac OS X;10.12.6;16G29> <com.apple.AuthKit/1 (com.apple.akd/1.0)>";
    const MAC_UA: &str = "akd/1.0 CFNetwork/811.5.4 Darwin/16.7.0";
    const NATIVE_C: &str = "anisette-v3-server (native-c 0.2.0)";

    fn unsupported(r: Result<(), AnisetteError>) -> bool {
        matches!(r, Err(AnisetteError::UnsupportedServerIdentity { .. }))
    }

    #[test]
    fn mac_adi_server_is_accepted() {
        check_server_identity(MAC, MAC_UA, Some(NATIVE_C)).unwrap();
        check_server_identity(
            "<MacBookPro18,3> <macOS;26.6;25F84> <com.apple.AuthKit/1 (com.apple.akd/1.0)>",
            "akd/1.0 CFNetwork/1568 Darwin/25.6.0",
            None,
        )
        .unwrap();
    }

    #[test]
    fn android_adi_servers_are_refused() {
        let akd = "<MacBookPro13,2> <macOS;13.1;22C65> <com.apple.AuthKit/1 (com.apple.akd/1.0)>";
        assert!(unsupported(check_server_identity(akd, "akd/1.0 CFNetwork/808.1.4", None)));
        assert!(unsupported(check_server_identity(
            MAC,
            MAC_UA,
            Some("anisette-v3-server v2.2.2")
        )));
        assert!(unsupported(check_server_identity(
            MAC,
            MAC_UA,
            Some("omnisette-server 1.0.0-beta.1")
        )));
        assert!(unsupported(check_server_identity(
            "<Pixel 7> <Android;13;TQ3A> <com.google.android.gms/1>",
            "akd/1.0",
            None
        )));
    }

    #[test]
    fn windows_and_xcode_identities_are_refused() {
        assert!(unsupported(check_server_identity(
            "<PC> <Windows;6.2(0,0);9200> <com.apple.AuthKit/1 (com.apple.iTunes/12.12.4.1)>",
            "akd/1.0 CFNetwork/808.1.4",
            None
        )));
        assert!(unsupported(check_server_identity(
            "<MacBookPro15,1> <Mac OS X;10.15.2;19C57> <com.apple.AuthKit/1 (com.apple.dt.Xcode/3594.4.19)>",
            "akd/1.0 CFNetwork/978.0.7 Darwin/18.7.0",
            None
        )));
        assert!(unsupported(check_server_identity(
            "<MacBookPro13,3> <Mac OS X;10.12.6;16G29> <com.apple.AuthKit/1 (com.apple.dt.Xcode/3594.4.19)>",
            MAC_UA,
            Some(NATIVE_C)
        )));
    }

    #[test]
    fn unusable_header_values_are_refused() {
        for (info, ua) in [("", MAC_UA), (MAC, " "), (MAC, "akd\r\nX-Evil: 1"), ("<a>\n<b>", MAC_UA)] {
            assert!(matches!(
                check_server_identity(info, ua, None),
                Err(AnisetteError::InvalidClientInfo(_))
            ));
        }
    }

    #[test]
    fn provisioning_urls_must_point_at_apple() {
        assert!(is_apple_provisioning_url(
            "https://gsa.apple.com/grandslam/GsService2/midStartProvisioning"
        ));
        assert!(is_apple_provisioning_url("https://gsa.apple.com:443/x"));
        assert!(!is_apple_provisioning_url("http://gsa.apple.com/x"));
        assert!(!is_apple_provisioning_url("https://gsa.apple.com.evil.example/x"));
        assert!(!is_apple_provisioning_url("https://gsa.apple.com:8443/x"));
        assert!(!is_apple_provisioning_url("https://user@gsa.apple.com/x"));
        assert!(!is_apple_provisioning_url("not a url"));
    }

    #[test]
    fn provisioning_socket_follows_the_server_scheme() {
        assert_eq!(
            provisioning_ws_url("https://mac-ani.jkcoxson.com/").unwrap(),
            "wss://mac-ani.jkcoxson.com/v3/provisioning_session"
        );
        assert_eq!(
            provisioning_ws_url("http://10.0.0.2:6969").unwrap(),
            "ws://10.0.0.2:6969/v3/provisioning_session"
        );
        assert!(provisioning_ws_url("ftp://x").is_err());
    }

    #[test]
    fn state_is_keyed_by_the_provisioning_client_info() {
        let mut state = AnisetteState::new();
        assert!(!state.is_usable_for(MAC));
        state.adi_pb = Some(vec![1, 2, 3]);
        assert!(!state.is_usable_for(MAC), "state without a recorded identity is reprovisioned");
        state.provisioned_client_info = Some(MAC.to_string());
        assert!(state.is_usable_for(MAC));
        assert!(!state.is_usable_for(
            "<PC> <Windows;6.2(0,0);9200> <com.apple.AuthKit/1 (com.apple.iTunes/12.12.4.1)>"
        ));
    }

    #[test]
    fn state_round_trips_privately_and_reads_old_files() {
        let dir = std::env::temp_dir().join(format!("signr-anisette-{}", Uuid::new_v4()));
        fs::create_dir_all(&dir).unwrap();
        let path = dir.join("state.plist");

        let mut state = AnisetteState::new();
        state.adi_pb = Some(vec![9; 8]);
        state.provisioned_client_info = Some(MAC.to_string());
        state.save(&path).unwrap();
        let loaded = AnisetteState::load(&path).unwrap();
        assert!(loaded.is_usable_for(MAC));
        assert_eq!(loaded.device_id(), state.device_id());
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(fs::metadata(&path).unwrap().permissions().mode() & 0o777, 0o600);
        }

        let mut old = Dictionary::new();
        old.insert("keychain_identifier".into(), plist::Value::Data(vec![7; 16]));
        old.insert("adi_pb".into(), plist::Value::Data(vec![1; 4]));
        plist::to_file_xml(&path, &old).unwrap();
        let loaded = AnisetteState::load(&path).unwrap();
        assert!(loaded.is_provisioned());
        assert!(!loaded.is_usable_for(MAC));

        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn headers_carry_the_server_identity_and_no_serial() {
        let data = AnisetteData {
            machine_id: "mid".into(),
            one_time_password: "otp".into(),
            routing_info: "17106176".into(),
            device_description: MAC.into(),
            user_agent: MAC_UA.into(),
            local_user_id: "lu".into(),
            device_unique_identifier: "id".into(),
        };
        let headers = data.get_headers();
        assert_eq!(headers["X-Mme-Client-Info"], MAC);
        assert_eq!(headers["User-Agent"], MAC_UA);
        assert!(headers["X-Apple-I-Client-Time"].ends_with('Z'));
        assert!(!headers.contains_key("X-Apple-I-SRL-NO"));
    }

    #[tokio::test]
    #[ignore]
    async fn android_server_is_refused_before_apple() {
        let _ = rustls::crypto::ring::default_provider().install_default();
        let err = AnisetteClient::new("https://ani.sidestore.app".into()).await.err();
        assert!(
            matches!(err, Some(AnisetteError::UnsupportedServerIdentity { .. })),
            "{err:?}"
        );
    }

    // Provisions a new identity against Apple through the default server, no Apple ID involved
    #[tokio::test]
    #[ignore]
    async fn fetch_anisette_remote_v3() -> Result<(), AnisetteError> {
        let _ = rustls::crypto::ring::default_provider().install_default();
        let dir = std::env::temp_dir().join(format!("signr-anisette-{}", Uuid::new_v4()));
        let mut provider =
            RemoteAnisetteProviderV3::new(crate::DEFAULT_ANISETTE_URL_V3.to_string(), dir.clone());
        let first = provider.headers(true).await?;
        let second = provider.headers(false).await?;
        assert_eq!(first["X-Mme-Device-Id"], second["X-Mme-Device-Id"]);
        println!("{:?}", second.keys().collect::<Vec<_>>());
        fs::remove_dir_all(&dir)?;
        Ok(())
    }
}
