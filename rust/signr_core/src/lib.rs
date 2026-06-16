//! signr_core — facade over PlumeImpactor's Rust crates, exposed to SwiftUI via UniFFI.
//!
//! SwiftUI stays a thin UI client: it calls the async methods on [`SignrEngine`] and
//! implements two foreign traits — [`TwoFactorProvider`] (Rust asks Swift for a 2FA code
//! mid-login) and [`ProgressObserver`] (Rust streams stage/percent updates).
//!
//! The orchestration mirrors `apps/plumesign`'s verified login -> sign -> install flow.

use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use async_trait::async_trait;

use plume_core::auth::{Account as PlumeAccount, TwoFactorAction};
use plume_core::developer::DeveloperSession;
use plume_core::CertificateIdentity;
use plume_store::{AccountStore, GsaAccount};
use plume_utils::{
    Bundle, InstallProgress, Package, PlistInfoTrait, Signer, SignerMode, SignerOptions,
    get_device_for_id,
};

uniffi::setup_scaffolding!();

// ============================================================================
// Errors
// ============================================================================

#[derive(Debug, thiserror::Error, uniffi::Error)]
pub enum SignrError {
    #[error("Not signed in")]
    NotAuthenticated,
    #[error("Authentication failed: {message}")]
    Auth { message: String },
    #[error("Two-factor authentication failed: {message}")]
    TwoFactor { message: String },
    #[error("Device error: {message}")]
    Device { message: String },
    #[error("Signing failed: {message}")]
    Sign { message: String },
    #[error("I/O error: {message}")]
    Io { message: String },
    #[error("Operation cancelled")]
    Cancelled,
    #[error("{message}")]
    Unexpected { message: String },
}

impl From<uniffi::UnexpectedUniFFICallbackError> for SignrError {
    fn from(e: uniffi::UnexpectedUniFFICallbackError) -> Self {
        SignrError::Unexpected { message: e.reason }
    }
}

/// Install the rustls ring CryptoProvider exactly once. Without this the first TLS
/// handshake panics ("Could not automatically determine the process-level CryptoProvider").
fn ensure_crypto_provider() {
    use std::sync::Once;
    static INIT: Once = Once::new();
    INIT.call_once(|| {
        let _ = rustls::crypto::ring::default_provider().install_default();
    });
}

/// Run a future on a fresh runtime, turning a panic into an error instead of killing
/// the worker thread silently.
fn block_on_caught<T>(
    fut: impl std::future::Future<Output = Result<T, SignrError>>,
) -> Result<T, SignrError> {
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(io_err)?;
    std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| rt.block_on(fut))).unwrap_or_else(
        |p| {
            let msg = p
                .downcast_ref::<&str>()
                .map(|s| s.to_string())
                .or_else(|| p.downcast_ref::<String>().cloned())
                .unwrap_or_else(|| "internal panic".to_string());
            Err(SignrError::Unexpected { message: msg })
        },
    )
}

fn auth_err<E: std::fmt::Display>(e: E) -> SignrError {
    SignrError::Auth { message: e.to_string() }
}
fn io_err<E: std::fmt::Display>(e: E) -> SignrError {
    SignrError::Io { message: e.to_string() }
}
fn dev_err<E: std::fmt::Display>(e: E) -> SignrError {
    SignrError::Device { message: e.to_string() }
}
fn sign_err<E: std::fmt::Display>(e: E) -> SignrError {
    SignrError::Sign { message: e.to_string() }
}

// ============================================================================
// Data transfer objects
// ============================================================================

#[derive(Debug, Clone, uniffi::Record)]
pub struct Account {
    pub apple_id: String,
    pub team_name: String,
    pub team_id: String,
    /// "Free" (no paid membership, 7-day), "Personal" (paid Individual), or "Paid"
    /// (Company / Organization). Empty when not yet resolved.
    pub tier: String,
}

#[derive(Debug, Clone, uniffi::Record)]
pub struct Team {
    pub id: String,
    pub name: String,
    /// "Free" / "Personal" / "Paid".
    pub tier: String,
}

/// Classify a team. `xcode_free_only` flags a no-membership 7-day team; otherwise the
/// Apple team `type` ("Individual" vs "Company"/"Organization") tells personal from paid.
fn team_tier(xcode_free_only: bool, kind: &str) -> String {
    if xcode_free_only {
        "Free".into()
    } else if kind.eq_ignore_ascii_case("Individual") {
        "Personal".into()
    } else {
        "Paid".into()
    }
}

/// Default to a Paid (Company) team, then any non-Free team, else the first.
fn default_team(teams: &[Team]) -> Team {
    teams
        .iter()
        .find(|t| t.tier == "Paid")
        .or_else(|| teams.iter().find(|t| t.tier != "Free"))
        .cloned()
        .unwrap_or_else(|| teams[0].clone())
}

/// Metadata read from an IPA's Info.plist, used to prefill + inform the UI.
#[derive(Debug, Clone, uniffi::Record)]
pub struct IpaInfo {
    pub bundle_id: Option<String>,
    pub name: Option<String>,
    pub version: Option<String>,
    pub build: Option<String>,
    /// MinimumOSVersion (e.g. "15.0").
    pub min_os: Option<String>,
    /// "iPhone" / "iPad" / "Universal".
    pub device_family: Option<String>,
    /// e.g. "iPhoneOS".
    pub platform: Option<String>,
    /// SDK the app was built against (DTPlatformVersion).
    pub sdk_version: Option<String>,
}

/// How a device reached usbmuxd, so the UI can show a USB vs WiFi indicator.
#[derive(Debug, Clone, uniffi::Enum)]
pub enum DeviceLink {
    Usb,
    Wifi,
    Unknown,
}

#[derive(Debug, Clone, uniffi::Record)]
pub struct DeviceInfo {
    pub name: String,
    pub udid: String,
    pub device_id: u64,
    pub product_type: Option<String>,
    pub os_version: Option<String>,
    pub is_mac: bool,
    pub link: DeviceLink,
}

#[derive(Debug, Clone, uniffi::Record)]
pub struct SignedApp {
    pub bundle_id: String,
    pub display_name: String,
    /// Set when exporting an .ipa instead of installing to a device.
    pub output_path: Option<String>,
}

#[derive(Debug, Clone, uniffi::Enum)]
pub enum SignStage {
    Preparing,
    Authenticating,
    RegisteringDevice,
    CreatingCertificate,
    RegisteringApp,
    Modifying,
    Signing,
    Installing,
    Done,
}

/// Mirrors `plume_utils::SignerOptions` — every Impactor-style knob.
#[derive(Debug, Clone, Default, uniffi::Record)]
pub struct SignOptions {
    pub custom_bundle_id: Option<String>,
    pub custom_name: Option<String>,
    pub custom_version: Option<String>,
    pub custom_icon_path: Option<String>,
    /// Paths to .dylib / .deb / .framework / .bundle / .appex to inject.
    pub tweaks: Vec<String>,
    /// Strip app extensions (the PlugIns folder) and any Watch app before signing, so only
    /// the main binary gets an App ID registered. Conserves the free-account App-ID quota
    /// and avoids extension provisioning mismatches that fail installs.
    pub main_binary_only: bool,
    pub enable_file_sharing: bool,
    pub enable_ipad_fullscreen: bool,
    pub enable_pro_motion: bool,
    pub enable_game_mode: bool,
    pub enable_liquid_glass: bool,
    /// Register the increased-memory-limit capability on the App ID so the profile authorizes
    /// `com.apple.developer.kernel.increased-memory-limit` (raises the per-app RAM cap on
    /// supported devices). Works on free accounts; silently ignored on unsupported hardware.
    pub increased_memory_limit: bool,
    pub enable_ellekit: bool,
    /// Inject the Sideload Spoofer dylib (bypasses sideload detection so apps like TikTok
    /// allow login). Pulls in the ElleKit runtime automatically, since it links Substrate.
    pub enable_sideload_bypass: bool,
    pub remove_url_schemes: bool,
    /// Strip the UISupportedDevices allowlist so the app installs on any device model
    /// (e.g. iOS apps on Apple Silicon Macs, or models the developer didn't list).
    pub remove_ui_supported_devices: bool,
    /// Lower the app's MinimumOSVersion so it installs on older iOS.
    pub lower_min_os: bool,
    /// Sign with a wildcard App ID (`*`) so the app keeps its original bundle id and no
    /// per-app App ID is registered (how Sideloadly signs apps it doesn't own). Paid teams
    /// only — ignored on free teams, which always get a team-id suffix + explicit App ID.
    pub wildcard_app_id: bool,
}

/// The Sideload Spoofer dylib, baked into the binary so it ships with the app. Written to
/// a temp file and injected like a tweak (which auto-pulls the ElleKit runtime it links).
const SIDELOAD_SPOOFER: &[u8] = include_bytes!("../assets/SideloadSpoofer.dylib");

fn stage_sideload_spoofer() -> Result<PathBuf, SignrError> {
    let path = std::env::temp_dir().join("signr_SideloadSpoofer.dylib");
    // The dylib is baked into the binary and never changes, so skip the write if a correctly
    // sized copy is already staged.
    let already_staged = std::fs::metadata(&path)
        .map(|m| m.len() == SIDELOAD_SPOOFER.len() as u64)
        .unwrap_or(false);
    if !already_staged {
        std::fs::write(&path, SIDELOAD_SPOOFER).map_err(io_err)?;
    }
    Ok(path)
}

/// Strip app extensions and the Watch app (PlugIns/Extensions/Watch) plus the now-stale SC_Info
/// manifest entries that reference them, so only the main app is registered and signed. Returns
/// the directory names that were actually removed (for logging). Leaving stale
/// SinfReplicationPaths entries pointing at removed dirs makes installd fail with
/// PackageInspectionFailed (same fix AltStore/SideStore apply).
pub fn strip_non_main_bundles(bundle: &Bundle) -> Result<Vec<String>, SignrError> {
    let mut removed = Vec::new();
    for sub in ["PlugIns", "Extensions", "Watch"] {
        let dir = bundle.bundle_dir().join(sub);
        if dir.exists() {
            std::fs::remove_dir_all(&dir).map_err(io_err)?;
            removed.push(sub.to_string());
        }
    }

    let manifest = bundle.bundle_dir().join("SC_Info").join("Manifest.plist");
    if manifest.exists() {
        if let Ok(mut value) = plist::Value::from_file(&manifest) {
            let mut changed = false;
            if let Some(paths) = value
                .as_dictionary_mut()
                .and_then(|d| d.get_mut("SinfReplicationPaths"))
                .and_then(|v| v.as_array_mut())
            {
                let before = paths.len();
                paths.retain(|v| {
                    v.as_string().is_none_or(|s| {
                        !(s.starts_with("PlugIns/")
                            || s.starts_with("Extensions/")
                            || s.starts_with("Watch/"))
                    })
                });
                changed = paths.len() != before;
            }
            if changed {
                let _ = value.to_file_xml(&manifest);
            }
        }
    }

    Ok(removed)
}

/// Resolve the bundle identifier to sign with. A non-empty custom id overrides the original.
/// Free teams get a ".<team_id>" suffix (free provisioning can't use a wildcard and must register
/// an explicit, owned App ID); paid teams keep the id verbatim.
pub fn resolve_signing_identifier(
    custom_bundle_id: Option<&str>,
    original_bundle_id: Option<&str>,
    team_id: &str,
    is_free: bool,
) -> Option<String> {
    let base = custom_bundle_id
        .filter(|s| !s.is_empty())
        .or(original_bundle_id)?;
    Some(if is_free {
        format!("{base}.{team_id}")
    } else {
        base.to_string()
    })
}

/// Wildcard signing (keep the original id, register a single `*` App ID, sign with its profile)
/// is paid-team only; free provisioning can't register a wildcard.
pub fn use_wildcard_app_id(wildcard_requested: bool, is_free: bool) -> bool {
    wildcard_requested && !is_free
}

pub fn build_signer_options(o: &SignOptions) -> SignerOptions {
    let mut s = SignerOptions {
        custom_identifier: o.custom_bundle_id.clone(),
        custom_name: o.custom_name.clone(),
        custom_version: o.custom_version.clone(),
        custom_icon: o.custom_icon_path.clone().map(PathBuf::from),
        tweaks: if o.tweaks.is_empty() {
            None
        } else {
            Some(o.tweaks.iter().map(PathBuf::from).collect())
        },
        ..Default::default()
    };
    s.mode = SignerMode::Pem;
    s.features.support_file_sharing = o.enable_file_sharing;
    s.features.support_ipad_fullscreen = o.enable_ipad_fullscreen;
    s.features.support_pro_motion = o.enable_pro_motion;
    s.features.support_game_mode = o.enable_game_mode;
    s.features.support_liquid_glass = o.enable_liquid_glass;
    s.features.support_increased_memory_limit = o.increased_memory_limit;
    s.features.support_ellekit = o.enable_ellekit;
    s.features.remove_url_schemes = o.remove_url_schemes;
    s.features.remove_ui_supported_devices = o.remove_ui_supported_devices;
    s.features.support_minimum_os_version = o.lower_min_os;
    s
}

// ============================================================================
// Foreign traits — implemented in Swift, called from Rust
// ============================================================================

/// How Apple is delivering the current 2FA code.
#[derive(Debug, Clone, uniffi::Enum)]
pub enum TwoFactorMethod {
    /// Pushed to the account's trusted devices.
    Device,
    /// Sent by SMS to a trusted phone number.
    Sms,
}

/// A trusted phone number that can receive an SMS code.
#[derive(Debug, Clone, uniffi::Record)]
pub struct TrustedPhone {
    pub id: u32,
    /// Last two digits, for display (e.g. "•• 42").
    pub last_two_digits: String,
}

/// Context for a 2FA prompt: how the code arrived and which phones can receive an SMS.
#[derive(Debug, Clone, uniffi::Record)]
pub struct TwoFactorRequest {
    pub method: TwoFactorMethod,
    pub phones: Vec<TrustedPhone>,
}

/// The user's response to a 2FA prompt.
#[derive(Debug, Clone, uniffi::Enum)]
pub enum TwoFactorResponse {
    /// Submit the code the user typed.
    Code { code: String },
    /// Send a fresh code by SMS to the trusted phone with this id.
    SendSms { phone_id: u32 },
}

/// Rust calls this mid-login. Swift shows the 2FA UI (with an SMS fallback when
/// `request.phones` is non-empty) and returns either a code or an SMS request.
#[uniffi::export(with_foreign)]
#[async_trait]
pub trait TwoFactorProvider: Send + Sync {
    async fn provide_two_factor(
        &self,
        request: TwoFactorRequest,
    ) -> Result<TwoFactorResponse, SignrError>;
}

/// Rust streams stage/percent + log lines up to SwiftUI.
#[uniffi::export(with_foreign)]
pub trait ProgressObserver: Send + Sync {
    fn on_stage(&self, stage: SignStage, percent: f64, message: String);
    fn on_log(&self, line: String);
}

/// Rust pushes the full current device list to Swift whenever it changes (USB or WiFi
/// connect/disconnect), so the sidebar updates live without a manual refresh.
#[uniffi::export(with_foreign)]
pub trait DeviceObserver: Send + Sync {
    fn on_devices(&self, devices: Vec<DeviceInfo>);
}

// ============================================================================
// Engine
// ============================================================================

#[derive(Default)]
struct EngineState {
    account: Option<Account>,
    teams: Vec<Team>,
    cancel: Option<tokio_util::sync::CancellationToken>,
    device_watch: Option<tokio_util::sync::CancellationToken>,
}

#[derive(uniffi::Object)]
pub struct SignrEngine {
    data_dir: String,
    state: Mutex<EngineState>,
}

impl SignrEngine {
    fn accounts_path(&self) -> PathBuf {
        accounts_store_path(&self.data_dir)
    }
}

/// The encrypted account store. The on-disk name is deliberately opaque so the file does not
/// advertise what it holds.
fn accounts_store_path(data_dir: &str) -> PathBuf {
    PathBuf::from(data_dir).join("session.dat")
}

// ============================================================================
// Device discovery + live watch
// ============================================================================

/// Connect to a usbmuxd device over lockdown and read its display name + hardware info
/// in a single round-trip. Falls back to empty/None when lockdown is unreachable (e.g.
/// the device hasn't been trusted yet), so an un-paired device still shows up in the list.
async fn device_info_from_usbmuxd(d: idevice::usbmuxd::UsbmuxdDevice) -> DeviceInfo {
    use idevice::IdeviceService;
    use idevice::lockdown::LockdownClient;
    use idevice::usbmuxd::UsbmuxdAddr;

    let udid = d.udid.clone();
    let device_id = d.device_id as u64;
    let link = match d.connection_type {
        idevice::usbmuxd::Connection::Usb => DeviceLink::Usb,
        idevice::usbmuxd::Connection::Network(_) => DeviceLink::Wifi,
        idevice::usbmuxd::Connection::Unknown(_) => DeviceLink::Unknown,
    };

    let provider = d.to_provider(UsbmuxdAddr::default(), "signr_info");
    let (name, product_type, os_version) = match LockdownClient::connect(&provider).await {
        Ok(mut lockdown) => match lockdown.get_value(None, None).await {
            Ok(values) => {
                let get = |k: &str| {
                    values
                        .as_dictionary()
                        .and_then(|dict| dict.get(k))
                        .and_then(|v| v.as_string())
                        .map(str::to_string)
                };
                (
                    get("DeviceName").unwrap_or_default(),
                    get("ProductType"),
                    get("ProductVersion"),
                )
            }
            Err(_) => (String::new(), None, None),
        },
        Err(_) => (String::new(), None, None),
    };

    DeviceInfo { name, udid, device_id, product_type, os_version, is_mac: false, link }
}

/// Collapse the same physical device (matched by udid) appearing over both USB and WiFi into one
/// entry, preferring the USB connection. usbmuxd hands out a separate device_id per transport, so
/// without this a device on USB + WiFi shows up twice. Entries without a udid are left as-is.
/// Returns a name-sorted list.
pub fn dedup_prefer_usb(list: Vec<DeviceInfo>) -> Vec<DeviceInfo> {
    use std::collections::HashMap;
    let mut by_udid: HashMap<String, DeviceInfo> = HashMap::new();
    let mut no_udid: Vec<DeviceInfo> = Vec::new();
    for d in list {
        if d.udid.is_empty() {
            no_udid.push(d);
            continue;
        }
        // Keep an existing USB entry; otherwise this one wins (a USB link replaces a prior
        // WiFi/Unknown one; same-link duplicates just overwrite harmlessly).
        match by_udid.get(&d.udid) {
            Some(existing) if matches!(existing.link, DeviceLink::Usb) => {}
            _ => {
                by_udid.insert(d.udid.clone(), d);
            }
        }
    }
    let mut out: Vec<DeviceInfo> = by_udid.into_values().chain(no_udid).collect();
    out.sort_by(|a, b| a.name.to_lowercase().cmp(&b.name.to_lowercase()));
    out
}

/// Push the current device set to Swift as a de-duplicated, name-sorted list.
fn emit_devices(
    observer: &Arc<dyn DeviceObserver>,
    devices: &std::collections::HashMap<u32, DeviceInfo>,
) {
    observer.on_devices(dedup_prefer_usb(devices.values().cloned().collect()));
}

/// Sleep `secs`, returning true early if the watch was cancelled in the meantime.
async fn sleep_or_cancelled(token: &tokio_util::sync::CancellationToken, secs: u64) -> bool {
    tokio::select! {
        _ = token.cancelled() => true,
        _ = tokio::time::sleep(std::time::Duration::from_secs(secs)) => false,
    }
}

/// Snapshot connected devices, then stream usbmuxd connect/disconnect events forever,
/// re-emitting the full list on every change. Reconnects if the usbmuxd socket drops.
async fn device_watch_loop(
    observer: Arc<dyn DeviceObserver>,
    token: tokio_util::sync::CancellationToken,
) {
    use futures::StreamExt;
    use idevice::usbmuxd::{UsbmuxdConnection, UsbmuxdListenEvent};
    use std::collections::HashMap;

    while !token.is_cancelled() {
        let mut devices: HashMap<u32, DeviceInfo> = HashMap::new();

        let mut muxer = match UsbmuxdConnection::default().await {
            Ok(m) => m,
            Err(_) => {
                if sleep_or_cancelled(&token, 2).await {
                    return;
                }
                continue;
            }
        };

        if let Ok(raw) = muxer.get_devices().await {
            for d in raw {
                let info = device_info_from_usbmuxd(d).await;
                devices.insert(info.device_id as u32, info);
            }
        }
        emit_devices(&observer, &devices);

        let mut stream = match muxer.listen().await {
            Ok(s) => s,
            Err(_) => {
                if sleep_or_cancelled(&token, 2).await {
                    return;
                }
                continue;
            }
        };

        loop {
            tokio::select! {
                _ = token.cancelled() => return,
                event = stream.next() => match event {
                    Some(Ok(UsbmuxdListenEvent::Connected(d))) => {
                        let info = device_info_from_usbmuxd(d).await;
                        devices.insert(info.device_id as u32, info);
                        emit_devices(&observer, &devices);
                    }
                    Some(Ok(UsbmuxdListenEvent::Disconnected(id))) => {
                        if devices.remove(&id).is_some() {
                            emit_devices(&observer, &devices);
                        }
                    }
                    Some(Err(_)) => continue,
                    None => break, // socket dropped; reconnect below
                },
            }
        }

        if sleep_or_cancelled(&token, 2).await {
            return;
        }
    }
}

fn format_elapsed(d: std::time::Duration) -> String {
    let secs = d.as_secs_f64();
    if secs < 60.0 {
        format!("{secs:.1}s")
    } else {
        format!("{}m {}s", (secs / 60.0).floor() as u64, (secs % 60.0).round() as u64)
    }
}

/// The full sign + install pipeline. Runs on a dedicated current-thread runtime
/// because `CertificateIdentity` (Box<dyn PrivateKey>) is not Send and therefore
/// cannot live across awaits on UniFFI's multi-thread runtime.
async fn run_sign_and_install(
    data_dir: String,
    ipa_path: String,
    mut options: SignOptions,
    device_id: Option<String>,
    observer: Arc<dyn ProgressObserver>,
    token: tokio_util::sync::CancellationToken,
) -> Result<SignedApp, SignrError> {
    let started = std::time::Instant::now();
    let check = || -> Result<(), SignrError> {
        if token.is_cancelled() {
            Err(SignrError::Cancelled)
        } else {
            Ok(())
        }
    };

    observer.on_stage(SignStage::Authenticating, 0.05, "Restoring session…".into());
    let accounts_path = accounts_store_path(&data_dir);
    let store = AccountStore::load(&Some(accounts_path)).await.map_err(io_err)?;
    let gsa = store
        .selected_account()
        .ok_or(SignrError::NotAuthenticated)?
        .clone();
    let session = DeveloperSession::new(gsa.adsid().clone(), gsa.xcode_gs_token().clone())
        .await
    .map_err(auth_err)?;
    let team_id = gsa.team_id().clone();
    check()?;

    observer.on_stage(SignStage::CreatingCertificate, 0.15, "Preparing certificate…".into());
    let cert = CertificateIdentity::new_with_session(
        &session,
        PathBuf::from(&data_dir),
        None,
        &team_id,
        false,
        None,
    )
    .await
    .map_err(sign_err)?;
    check()?;

    observer.on_stage(SignStage::Preparing, 0.25, "Unpacking IPA…".into());
    let pkg = Package::new(PathBuf::from(&ipa_path)).map_err(io_err)?;
    let bundle = pkg.get_package_bundle().map_err(io_err)?;

    // "Main binary only": strip app extensions + Watch app so only the main app is
    // registered/signed (matches zsign -E/-W, Sideloadly "Remove Extensions"). Done before
    // modify/register/sign so those steps never see the removed bundles.
    if options.main_binary_only {
        for sub in strip_non_main_bundles(&bundle)? {
            observer.on_log(format!("Removed /{sub} (main binary only)"));
        }
    }

    // Inject the Sideload Spoofer (bypasses sideload detection). Added to the tweak list so
    // it rides the normal injection path, which also pulls in the ElleKit runtime it links.
    if options.enable_sideload_bypass {
        let spoofer = stage_sideload_spoofer()?;
        options.tweaks.push(spoofer.to_string_lossy().to_string());
        observer.on_log("Sideload Spoofer enabled (ElleKit runtime auto-injected)".into());
    }

    let is_free = session
        .qh_list_teams()
        .await
        .map_err(auth_err)?
        .teams
        .iter()
        .find(|t| t.team_id == team_id)
        .map(|t| t.xcode_free_only)
        .unwrap_or(false);

    // App ID / bundle-id strategy:
    //   Free teams                 -> append ".<team_id>" + register an explicit App ID
    //                                 (free provisioning can't register a wildcard).
    //   Paid + wildcard (default)  -> keep the id verbatim, register a single wildcard App ID
    //                                 `*` and sign with its profile (how Sideloadly does it,
    //                                 nothing shows in the dev portal, no 9401 collision).
    //   Paid + wildcard off        -> keep the id verbatim, register the explicit App ID
    //                                 (works for ids you own, 9401s for ids another team owns).
    let use_wildcard = use_wildcard_app_id(options.wildcard_app_id, is_free);
    let original_id = bundle.get_bundle_identifier();
    let resolved_id = resolve_signing_identifier(
        options.custom_bundle_id.as_deref(),
        original_id.as_deref(),
        &team_id,
        is_free,
    );

    let mut signer = Signer::new(Some(cert), build_signer_options(&options));
    signer.options.custom_identifier = resolved_id.clone();

    observer.on_stage(SignStage::Modifying, 0.4, "Applying options & tweaks…".into());
    signer
        .modify_bundle(&bundle, &Some(team_id.clone()))
        .await
        .map_err(sign_err)?;
    check()?;

    let device = match &device_id {
        Some(id) => Some(get_device_for_id(id).await.map_err(dev_err)?),
        None => None,
    };
    if let Some(dev) = &device {
        observer.on_stage(
            SignStage::RegisteringDevice,
            0.5,
            format!("Registering {}…", dev.name),
        );
        session
            .qh_ensure_device(&team_id, &dev.name, &dev.udid)
            .await
            .map_err(dev_err)?;
    }

    observer.on_stage(SignStage::RegisteringApp, 0.6, "Registering app & provisioning…".into());
    if use_wildcard {
        signer
            .register_bundle_wildcard(&bundle, &session, &team_id)
            .await
            .map_err(sign_err)?;
    } else {
        signer
            .register_bundle(&bundle, &session, &team_id, false)
            .await
            .map_err(sign_err)?;
    }
    check()?;

    observer.on_stage(SignStage::Signing, 0.75, "Signing bundle…".into());
    signer.sign_bundle(&bundle).await.map_err(sign_err)?;

    let bundle_id = resolved_id.unwrap_or_default();
    let display_name = options.custom_name.clone().unwrap_or_default();

    if let Some(dev) = device {
        observer.on_stage(SignStage::Installing, 0.83, "Packaging app…".into());
        let ipa = pkg.clone().archive_package_bundle().map_err(io_err)?;

        observer.on_stage(SignStage::Installing, 0.85, format!("Uploading to {}…", dev.name));
        let obs = observer.clone();
        dev.install_ipa(&ipa, move |p: InstallProgress| {
            let obs = obs.clone();
            async move {
                match p {
                    InstallProgress::Uploading(pct) => {
                        let overall = 0.85 + (pct.min(100) as f64 / 100.0) * 0.06;
                        obs.on_stage(SignStage::Installing, overall, format!("Uploading… {pct}%"));
                    }
                    InstallProgress::Preparing(pct) => {
                        // Fixed label so the console logs it once (Swift dedupes consecutive
                        // identical lines) while the synthetic percent keeps the bar moving.
                        let overall = 0.91 + (pct.min(100) as f64 / 100.0) * 0.05;
                        obs.on_stage(SignStage::Installing, overall, "Installing on device…".into());
                    }
                    InstallProgress::Installing(pct) => {
                        let overall = 0.91 + (pct.min(100) as f64 / 100.0) * 0.08;
                        obs.on_stage(SignStage::Installing, overall, format!("Installing… {pct}%"));
                    }
                }
            }
        })
        .await
        .map_err(dev_err)?;
        observer.on_stage(
            SignStage::Done,
            1.0,
            format!("Installed ({})", format_elapsed(started.elapsed())),
        );
        Ok(SignedApp { bundle_id, display_name, output_path: None })
    } else {
        let out = pkg
            .get_archive_based_on_path(&PathBuf::from(&ipa_path))
            .map_err(io_err)?;
        observer.on_stage(
            SignStage::Done,
            1.0,
            format!("Exported signed IPA ({})", format_elapsed(started.elapsed())),
        );
        Ok(SignedApp {
            bundle_id,
            display_name,
            output_path: Some(out.to_string_lossy().to_string()),
        })
    }
}

#[uniffi::export]
impl SignrEngine {
    #[uniffi::constructor]
    pub fn new(data_dir: String) -> Arc<Self> {
        ensure_crypto_provider();
        Arc::new(Self {
            data_dir,
            state: Mutex::new(EngineState::default()),
        })
    }

    /// The signed-in account restored from disk, if any (synchronous, cheap).
    pub fn current_account(&self) -> Option<Account> {
        if let Some(account) = self.state.lock().unwrap().account.clone() {
            return Some(account);
        }
        let store = AccountStore::load_sync(&Some(self.accounts_path())).ok()?;
        let gsa = store.selected_account()?;
        Some(Account {
            apple_id: gsa.email().clone(),
            team_name: gsa.team_id().clone(),
            team_id: gsa.team_id().clone(),
            tier: String::new(),
        })
    }

    pub fn cancel(&self) {
        if let Some(token) = self.state.lock().unwrap().cancel.as_ref() {
            token.cancel();
        }
    }

    pub fn data_dir(&self) -> String {
        self.data_dir.clone()
    }

    /// Teams available for the signed-in account (populated at sign-in). Empty after a
    /// cold launch until the next sign-in.
    pub fn list_teams(&self) -> Vec<Team> {
        self.state.lock().unwrap().teams.clone()
    }

    /// Begin watching for device connect/disconnect (USB + WiFi). `observer.on_devices`
    /// fires immediately with the current set, then on every change. Idempotent: a second
    /// call cancels the previous watch. Runs on its own thread + current-thread runtime.
    pub fn start_device_watch(&self, observer: Arc<dyn DeviceObserver>) {
        let token = tokio_util::sync::CancellationToken::new();
        {
            let mut st = self.state.lock().unwrap();
            if let Some(prev) = st.device_watch.take() {
                prev.cancel();
            }
            st.device_watch = Some(token.clone());
        }
        std::thread::spawn(move || {
            let _ = block_on_caught(async move {
                device_watch_loop(observer, token).await;
                Ok(())
            });
        });
    }

    /// Stop the live device watch started by [`Self::start_device_watch`].
    pub fn stop_device_watch(&self) {
        if let Some(token) = self.state.lock().unwrap().device_watch.take() {
            token.cancel();
        }
    }
}

#[uniffi::export(async_runtime = "tokio")]
impl SignrEngine {
    /// Sign in with an Apple ID. Rust calls back into `tfa` for the 2FA code.
    pub async fn sign_in(
        &self,
        apple_id: String,
        password: String,
        tfa: Arc<dyn TwoFactorProvider>,
        observer: Arc<dyn ProgressObserver>,
    ) -> Result<Account, SignrError> {
        observer.on_stage(SignStage::Authenticating, 0.1, "Contacting Apple…".into());

        // Plume's `Account::login` takes a *synchronous* `tfa_closure`. We run the whole
        // login on a dedicated thread (current-thread runtime), and bridge the blocking
        // closure to the async Swift callback over channels: the closure signals "need a
        // code" and blocks on `code_rx`; this task awaits Swift and replies on `code_tx`.
        let (req_tx, mut req_rx) = tokio::sync::mpsc::unbounded_channel::<TwoFactorRequest>();
        let (resp_tx, resp_rx) = std::sync::mpsc::channel::<Result<TwoFactorAction, String>>();
        let (done_tx, done_rx) =
            tokio::sync::oneshot::channel::<Result<PlumeAccount, SignrError>>();

        let creds = (apple_id.clone(), password);
        std::thread::spawn(move || {
            let result = block_on_caught(async move {
                PlumeAccount::login(
                    move || Ok(creds.clone()),
                    move |req: plume_core::auth::TwoFactorRequest| -> Result<TwoFactorAction, String> {
                        let dto = TwoFactorRequest {
                            method: match req.method {
                                plume_core::auth::TwoFactorMethod::Sms => TwoFactorMethod::Sms,
                                plume_core::auth::TwoFactorMethod::Device => TwoFactorMethod::Device,
                            },
                            phones: req
                                .trusted_phone_numbers
                                .iter()
                                .map(|p| TrustedPhone {
                                    id: p.id,
                                    last_two_digits: p.last_two_digits.clone(),
                                })
                                .collect(),
                        };
                        req_tx.send(dto).map_err(|_| "2FA channel closed".to_string())?;
                        match resp_rx.recv() {
                            Ok(inner) => inner,
                            Err(_) => Err("2FA channel closed".to_string()),
                        }
                    },
                )
                .await
                .map_err(auth_err)
            });
            let _ = done_tx.send(result);
        });

        let mut done_rx = done_rx;
        let account = loop {
            tokio::select! {
                res = &mut done_rx => {
                    match res {
                        Ok(Ok(acc)) => break acc,
                        Ok(Err(e)) => return Err(e),
                        Err(_) => return Err(SignrError::Auth {
                            message: "Login task ended unexpectedly".into(),
                        }),
                    }
                }
                maybe = req_rx.recv() => {
                    if let Some(dto) = maybe {
                        observer.on_stage(SignStage::Authenticating, 0.5, "Two-factor authentication".into());
                        let action = match tfa.provide_two_factor(dto).await {
                            Ok(TwoFactorResponse::Code { code }) => Ok(TwoFactorAction::SubmitCode(code)),
                            Ok(TwoFactorResponse::SendSms { phone_id }) => {
                                Ok(TwoFactorAction::SendSms(phone_id))
                            }
                            Err(e) => Err(format!("{e}")),
                        };
                        let _ = resp_tx.send(action);
                    }
                }
            }
        };

        observer.on_stage(SignStage::RegisteringApp, 0.8, "Loading teams…".into());
        let (first_name, _last) = account.get_name();
        let session = DeveloperSession::using_account(account)
            .await
            .map_err(auth_err)?;
        let plume_teams = session.qh_list_teams().await.map_err(auth_err)?.teams;
        if plume_teams.is_empty() {
            return Err(SignrError::Auth {
                message: "No development teams found on this Apple ID".into(),
            });
        }
        let teams: Vec<Team> = plume_teams
            .iter()
            .map(|t| Team {
                id: t.team_id.clone(),
                name: t.name.clone(),
                tier: team_tier(t.xcode_free_only, &t._type),
            })
            .collect();
        let selected = default_team(&teams);

        let gsa = GsaAccount::new(
            apple_id.clone(),
            first_name,
            session.adsid().clone(),
            session.xcode_gs_token().clone(),
            selected.id.clone(),
        );
        let mut store = AccountStore::load(&Some(self.accounts_path()))
            .await
            .map_err(io_err)?;
        store.accounts_add(gsa).await.map_err(io_err)?;

        let dto = Account {
            apple_id,
            team_name: selected.name.clone(),
            team_id: selected.id.clone(),
            tier: selected.tier.clone(),
        };
        {
            let mut st = self.state.lock().unwrap();
            st.teams = teams;
            st.account = Some(dto.clone());
        }
        observer.on_stage(SignStage::Done, 1.0, format!("Signed in to {}", selected.name));
        Ok(dto)
    }

    /// Re-fetch the account's teams from Apple (used on launch to restore the picker and
    /// the accurate free/paid flag). Keeps the currently-selected team, else picks paid.
    pub async fn refresh_teams(&self) -> Result<Account, SignrError> {
        let store = AccountStore::load(&Some(self.accounts_path()))
            .await
            .map_err(io_err)?;
        let gsa = store
            .selected_account()
            .ok_or(SignrError::NotAuthenticated)?
            .clone();
        let session = DeveloperSession::new(gsa.adsid().clone(), gsa.xcode_gs_token().clone())
            .await
        .map_err(auth_err)?;
        let plume_teams = session.qh_list_teams().await.map_err(auth_err)?.teams;
        if plume_teams.is_empty() {
            return Err(SignrError::Auth {
                message: "No development teams found on this Apple ID".into(),
            });
        }
        let teams: Vec<Team> = plume_teams
            .iter()
            .map(|t| Team {
                id: t.team_id.clone(),
                name: t.name.clone(),
                tier: team_tier(t.xcode_free_only, &t._type),
            })
            .collect();
        let current = gsa.team_id().clone();
        let selected = teams
            .iter()
            .find(|t| t.id == current)
            .cloned()
            .unwrap_or_else(|| default_team(&teams));

        let dto = Account {
            apple_id: gsa.email().clone(),
            team_name: selected.name.clone(),
            team_id: selected.id.clone(),
            tier: selected.tier.clone(),
        };
        {
            let mut st = self.state.lock().unwrap();
            st.teams = teams;
            st.account = Some(dto.clone());
        }
        Ok(dto)
    }

    /// Switch the active team. Persists the choice and returns the updated account.
    pub async fn select_team(&self, team_id: String) -> Result<Account, SignrError> {
        let team = self
            .state
            .lock()
            .unwrap()
            .teams
            .iter()
            .find(|t| t.id == team_id)
            .cloned()
            .ok_or_else(|| SignrError::Unexpected {
                message: "Unknown team".into(),
            })?;

        let mut store = AccountStore::load(&Some(self.accounts_path()))
            .await
            .map_err(io_err)?;
        let email = store
            .selected_account()
            .map(|a| a.email().clone())
            .ok_or(SignrError::NotAuthenticated)?;
        store
            .update_account_team(&email, team.id.clone())
            .await
            .map_err(io_err)?;

        let dto = Account {
            apple_id: email,
            team_name: team.name.clone(),
            team_id: team.id.clone(),
            tier: team.tier.clone(),
        };
        self.state.lock().unwrap().account = Some(dto.clone());
        Ok(dto)
    }

    pub async fn sign_out(&self) {
        if let Ok(mut store) = AccountStore::load(&Some(self.accounts_path())).await {
            if let Some(email) = store.selected_account().map(|a| a.email().clone()) {
                let _ = store.accounts_remove(&email).await;
            }
        }
        self.state.lock().unwrap().account = None;
    }

    /// List connected iOS devices over usbmuxd (USB + WiFi), with product type + iOS version.
    pub async fn list_devices(&self) -> Result<Vec<DeviceInfo>, SignrError> {
        use idevice::usbmuxd::UsbmuxdConnection;

        let mut muxer = UsbmuxdConnection::default().await.map_err(dev_err)?;
        let raw = muxer.get_devices().await.map_err(dev_err)?;

        let mut out = Vec::with_capacity(raw.len());
        for d in raw {
            out.push(device_info_from_usbmuxd(d).await);
        }
        Ok(dedup_prefer_usb(out))
    }

    /// Trust / (re-)pair a device — sets up the usbmuxd pairing record so the device can
    /// be installed to. The user must tap "Trust" on the device when prompted.
    pub async fn pair_device(&self, device_id: String) -> Result<(), SignrError> {
        let device = get_device_for_id(&device_id).await.map_err(dev_err)?;
        device.pair().await.map_err(dev_err)?;
        Ok(())
    }

    /// Sign an IPA with the signed-in Apple ID and install it to `device_id`
    /// (a usbmuxd device id from `list_devices`), or export an .ipa when `None`.
    pub async fn sign_and_install(
        &self,
        ipa_path: String,
        options: SignOptions,
        device_id: Option<String>,
        observer: Arc<dyn ProgressObserver>,
    ) -> Result<SignedApp, SignrError> {
        let token = tokio_util::sync::CancellationToken::new();
        self.state.lock().unwrap().cancel = Some(token.clone());
        let data_dir = self.data_dir.clone();

        let (done_tx, done_rx) =
            tokio::sync::oneshot::channel::<Result<SignedApp, SignrError>>();
        std::thread::spawn(move || {
            // Race the whole pipeline against the cancel token. Without this, cancelling only
            // flips a flag the pipeline checks between stages, so a Cancel during a long await
            // (a stalled WiFi install, a hung Apple API call) does nothing until that await's
            // own timeout fires. Losing the race drops the in-flight future, which closes the
            // usbmuxd socket and tears the operation down at once. `biased` checks the token
            // first so an already-cancelled token returns without starting work.
            let result = block_on_caught(async move {
                tokio::select! {
                    biased;
                    _ = token.cancelled() => Err(SignrError::Cancelled),
                    res = run_sign_and_install(
                        data_dir, ipa_path, options, device_id, observer, token.clone(),
                    ) => res,
                }
            });
            let _ = done_tx.send(result);
        });

        match done_rx.await {
            Ok(inner) => inner,
            Err(_) => Err(SignrError::Unexpected {
                message: "Sign task ended unexpectedly".into(),
            }),
        }
    }

    /// Bridge smoke test: exercises the async 2FA callback + progress without network.
    /// Used by the Swift test suite to verify the FFI round-trip.
    pub async fn self_test(
        &self,
        tfa: Arc<dyn TwoFactorProvider>,
        observer: Arc<dyn ProgressObserver>,
    ) -> Result<String, SignrError> {
        observer.on_stage(SignStage::Authenticating, 0.5, "self-test".into());
        observer.on_log("self-test: requesting 2FA code from Swift".into());
        let request = TwoFactorRequest {
            method: TwoFactorMethod::Device,
            phones: Vec::new(),
        };
        let code = match tfa.provide_two_factor(request).await? {
            TwoFactorResponse::Code { code } => code,
            TwoFactorResponse::SendSms { phone_id } => format!("sms:{phone_id}"),
        };
        observer.on_log(format!("self-test: received {} chars", code.len()));
        observer.on_stage(SignStage::Done, 1.0, "self-test complete".into());
        Ok(code)
    }
}

// ============================================================================
// Free functions (simple smoke tests)
// ============================================================================

#[uniffi::export]
pub fn core_version() -> String {
    env!("CARGO_PKG_VERSION").to_string()
}

/// Read an IPA's Info.plist (bundle id / name / version) without unpacking the whole
/// archive — only the central directory + the Info.plist entry are read, so it's fast
/// even for large IPAs.
#[uniffi::export]
pub fn read_ipa_info(ipa_path: String) -> Result<IpaInfo, SignrError> {
    let file = std::fs::File::open(&ipa_path).map_err(io_err)?;
    let mut zip = zip::ZipArchive::new(file).map_err(io_err)?;

    // Find Payload/<App>.app/Info.plist — the top-level app, not a nested bundle's plist.
    let mut target: Option<String> = None;
    for i in 0..zip.len() {
        let name = zip.by_index(i).map_err(io_err)?.name().to_string();
        if let Some(rest) = name.strip_prefix("Payload/") {
            if rest.ends_with(".app/Info.plist") && rest.matches('/').count() == 1 {
                target = Some(name);
                break;
            }
        }
    }
    let target = target.ok_or_else(|| SignrError::Io {
        message: "Info.plist not found in IPA".into(),
    })?;

    let mut entry = zip.by_name(&target).map_err(io_err)?;
    let mut buf = Vec::new();
    std::io::Read::read_to_end(&mut entry, &mut buf).map_err(io_err)?;

    let value: plist::Value = plist::from_bytes(&buf).map_err(io_err)?;
    let dict = value.as_dictionary().ok_or_else(|| SignrError::Io {
        message: "Malformed Info.plist".into(),
    })?;
    let get = |k: &str| dict.get(k).and_then(|v| v.as_string()).map(str::to_string);

    let device_family = dict
        .get("UIDeviceFamily")
        .and_then(|v| v.as_array())
        .map(|a| {
            let fams: Vec<i64> = a.iter().filter_map(|v| v.as_signed_integer()).collect();
            match (fams.contains(&1), fams.contains(&2)) {
                (true, true) => "Universal".to_string(),
                (false, true) => "iPad".to_string(),
                _ => "iPhone".to_string(),
            }
        });
    let platform = dict
        .get("CFBundleSupportedPlatforms")
        .and_then(|v| v.as_array())
        .and_then(|a| a.first())
        .and_then(|v| v.as_string())
        .map(str::to_string)
        .or_else(|| get("DTPlatformName"));

    Ok(IpaInfo {
        bundle_id: get("CFBundleIdentifier"),
        name: get("CFBundleDisplayName").or_else(|| get("CFBundleName")),
        version: get("CFBundleShortVersionString").or_else(|| get("CFBundleVersion")),
        build: get("CFBundleVersion"),
        min_os: get("MinimumOSVersion").or_else(|| get("LSMinimumSystemVersion")),
        device_family,
        platform,
        sdk_version: get("DTPlatformVersion"),
    })
}

fn icon_base_names(dict: &plist::Dictionary) -> Vec<String> {
    if let Some(files) = dict
        .get("CFBundleIcons")
        .and_then(|v| v.as_dictionary())
        .and_then(|d| d.get("CFBundlePrimaryIcon"))
        .and_then(|v| v.as_dictionary())
        .and_then(|d| d.get("CFBundleIconFiles"))
        .and_then(|v| v.as_array())
    {
        let names: Vec<String> = files
            .iter()
            .filter_map(|v| v.as_string())
            .map(str::to_string)
            .collect();
        if !names.is_empty() {
            return names;
        }
    }
    dict.get("CFBundleIconFiles")
        .and_then(|v| v.as_array())
        .map(|a| {
            a.iter()
                .filter_map(|v| v.as_string())
                .map(str::to_string)
                .collect()
        })
        .unwrap_or_default()
}

/// Read the app's primary icon from an IPA and return a standard PNG (CgBI normalized).
/// Picks the highest-resolution icon. Returns None if none is found.
#[uniffi::export]
pub fn read_ipa_icon(ipa_path: String) -> Option<Vec<u8>> {
    use std::io::Read;

    let file = std::fs::File::open(&ipa_path).ok()?;
    let mut zip = zip::ZipArchive::new(file).ok()?;

    // Locate the "Payload/<App>.app/" prefix.
    let mut app_prefix: Option<String> = None;
    for i in 0..zip.len() {
        let name = zip.by_index(i).ok()?.name().to_string();
        if let Some(rest) = name.strip_prefix("Payload/") {
            if let Some(idx) = rest.find(".app/") {
                app_prefix = Some(format!("Payload/{}", &rest[..idx + 5]));
                break;
            }
        }
    }
    let app_prefix = app_prefix?;

    // Read Info.plist for the declared icon base names.
    let mut info_buf = Vec::new();
    if let Ok(mut e) = zip.by_name(&format!("{app_prefix}Info.plist")) {
        let _ = e.read_to_end(&mut info_buf);
    }
    let bases: Vec<String> = plist::from_bytes::<plist::Value>(&info_buf)
        .ok()
        .as_ref()
        .and_then(|v| v.as_dictionary())
        .map(icon_base_names)
        .unwrap_or_default();

    // Choose the largest matching .png directly inside the .app.
    let mut best: Option<(String, u64)> = None;
    for i in 0..zip.len() {
        let entry = zip.by_index(i).ok()?;
        let name = entry.name().to_string();
        let size = entry.size();
        drop(entry);
        let Some(file_part) = name.strip_prefix(&app_prefix) else {
            continue;
        };
        let lower = file_part.to_ascii_lowercase();
        if file_part.contains('/') || !lower.ends_with(".png") {
            continue;
        }
        let matches = if bases.is_empty() {
            lower.contains("appicon") || lower.starts_with("icon")
        } else {
            bases.iter().any(|b| file_part.starts_with(b.as_str()))
        };
        if matches && best.as_ref().is_none_or(|(_, s)| size > *s) {
            best = Some((name, size));
        }
    }
    let (icon_name, _) = best?;

    let mut buf = Vec::new();
    zip.by_name(&icon_name).ok()?.read_to_end(&mut buf).ok()?;
    Some(plume_utils::cgbi::normalize(buf))
}

/// Returns Plume's signer modes — proves the reused Plume crates are linked in.
#[uniffi::export]
pub fn signer_modes() -> Vec<String> {
    vec![
        SignerMode::Pem.to_string(),
        SignerMode::Adhoc.to_string(),
        SignerMode::None.to_string(),
    ]
}
