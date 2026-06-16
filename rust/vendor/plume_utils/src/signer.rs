// TODO: move to plist macro
use futures::future::try_join_all;
use plist::Value;
use std::sync::Arc;
use tokio::fs;

use plume_core::{
    CertificateIdentity, InMemoryPrivateKey, MobileProvision, PrivateKey, SettingsScope,
    SigningSettings, UnifiedSigner, developer::DeveloperSession,
};
use std::path::Path;

use crate::{Bundle, BundleType, Error, PlistInfoTrait, SignerApp, SignerMode, SignerOptions};

pub struct Signer {
    certificate: Option<CertificateIdentity>,
    pub options: SignerOptions,
    pub provisioning_files: Vec<MobileProvision>,
    /// When wildcard signing, the team id appended to the entitlement's application-identifier
    /// (so it matches Sideloadly's `TEAMID.<bundleid>.<teamid>` and can install over its apps),
    /// while the visible CFBundleIdentifier stays the original bundle id.
    pub wildcard_app_id_suffix: Option<String>,
}

impl Signer {
    pub fn new(certificate: Option<CertificateIdentity>, options: SignerOptions) -> Self {
        Self {
            certificate,
            options,
            provisioning_files: Vec::new(),
            wildcard_app_id_suffix: None,
        }
    }

    pub async fn modify_bundle(
        &mut self,
        bundle: &Bundle,
        team_id: &Option<String>,
    ) -> Result<(), Error> {
        if self.options.mode == SignerMode::None {
            return Ok(());
        }

        let bundles = bundle
            .collect_bundles_sorted()?
            .into_iter()
            .filter(|b| b.bundle_type().should_have_entitlements())
            .collect::<Vec<_>>();

        if let Some(new_name) = self.options.custom_name.as_ref() {
            bundle.set_name(new_name)?;
        }

        if let Some(new_version) = self.options.custom_version.as_ref() {
            bundle.set_version(new_version)?;
        }

        if self.options.features.support_minimum_os_version {
            bundle.set_info_plist_key("MinimumOSVersion", "7.0")?;
        }

        if self.options.features.support_file_sharing {
            bundle.set_info_plist_key("UIFileSharingEnabled", true)?;
            bundle.set_info_plist_key("UISupportsDocumentBrowser", true)?;
        }

        if self.options.features.support_ipad_fullscreen {
            bundle.set_info_plist_key("UIRequiresFullScreen", true)?;
        }

        if self.options.features.support_game_mode {
            bundle.set_info_plist_key("GCSupportsGameMode", true)?;
        }

        if self.options.features.support_pro_motion {
            bundle.set_info_plist_key("CADisableMinimumFrameDurationOnPhone", true)?;
        }

        if self.options.features.remove_url_schemes {
            bundle.remove_info_plist_key("CFBundleURLTypes")?;
        }

        if self.options.features.remove_ui_supported_devices {
            bundle.remove_info_plist_key("UISupportedDevices")?;
        }

        let identifier = bundle.get_bundle_identifier();

        if self.options.mode != SignerMode::Adhoc && self.options.custom_identifier.is_none() {
            if let (Some(identifier), Some(team_id)) = (identifier.as_ref(), team_id.as_ref()) {
                self.options.custom_identifier = Some(format!("{identifier}.{team_id}"));
            }
        }

        if let Some(new_identifier) = self.options.custom_identifier.as_ref() {
            if let Some(orig_identifier) = identifier {
                for embedded_bundle in &bundles {
                    embedded_bundle.set_matching_identifier(&orig_identifier, new_identifier)?;
                }
            }
        }

        if self.options.app == SignerApp::SideStore
            || self.options.app == SignerApp::AltStore
            || self.options.app == SignerApp::LiveContainerAndSideStore
        {
            if let Some(cert_identity) = &self.certificate {
                if let (Some(p12_data), Some(serial_number)) =
                    (&cert_identity.p12_data, &cert_identity.serial_number)
                {
                    let bundles = bundle
                        .collect_bundles_sorted()?
                        .into_iter()
                        .collect::<Vec<_>>();

                    let id_key = match self.options.app {
                        SignerApp::StikStore => "MachineID",
                        _ => "ALTCertificateID",
                    };
                    let cert_file_name = match self.options.app {
                        SignerApp::StikStore => "Certificate.p12",
                        _ => "ALTCertificate.p12",
                    };

                    match self.options.app {
                        SignerApp::LiveContainerAndSideStore => {
                            if let Some(embedded_bundle) = bundles
                                .iter()
                                .find(|b| b.bundle_dir().ends_with("SideStoreApp.framework"))
                            {
                                embedded_bundle.set_info_plist_key(id_key, &**serial_number)?;
                                fs::write(
                                    embedded_bundle.bundle_dir().join(cert_file_name),
                                    p12_data,
                                )
                                .await?;
                            }
                        }
                        SignerApp::SideStore | SignerApp::AltStore => {
                            bundle.set_info_plist_key(id_key, &**serial_number)?;
                            fs::write(bundle.bundle_dir().join(cert_file_name), p12_data).await?;
                        }
                        _ => {}
                    }
                }
            }
        }

        if let Some(custom_icon) = &self.options.custom_icon {
            let image_sizes: &[(&str, u32)] = &[
                ("FRIcon60x60@2x.png", 120),
                ("FRIcon60x60@3x.png", 180),
                ("FRIcon76x76@2x~ipad.png", 152),
            ];

            let img = image::open(custom_icon)?;

            for &(file_name, size) in image_sizes {
                let filled = img.resize_to_fill(size, size, image::imageops::FilterType::Lanczos3);

                let out_path = bundle.bundle_dir().join(file_name);
                filled.save_with_format(&out_path, image::ImageFormat::Png)?;
            }

            let cf_bundle_icons = Value::Dictionary({
                let mut primary = plist::Dictionary::new();
                primary.insert(
                    "CFBundleIconFiles".to_string(),
                    Value::Array(vec![Value::String("FRIcon60x60".to_string())]),
                );
                primary.insert(
                    "CFBundleIconName".to_string(),
                    Value::String("FRIcon".to_string()),
                );
                let mut d = plist::Dictionary::new();
                d.insert(
                    "CFBundlePrimaryIcon".to_string(),
                    Value::Dictionary(primary),
                );
                d
            });

            let cf_bundle_icons_ipad = Value::Dictionary({
                let mut primary = plist::Dictionary::new();
                primary.insert(
                    "CFBundleIconFiles".to_string(),
                    Value::Array(vec![
                        Value::String("FRIcon60x60".to_string()),
                        Value::String("FRIcon76x76".to_string()),
                    ]),
                );
                primary.insert(
                    "CFBundleIconName".to_string(),
                    Value::String("FRIcon".to_string()),
                );
                let mut d = plist::Dictionary::new();
                d.insert(
                    "CFBundlePrimaryIcon".to_string(),
                    Value::Dictionary(primary),
                );
                d
            });

            bundle.set_info_plist_key("CFBundleIcons", cf_bundle_icons)?;
            bundle.set_info_plist_key("CFBundleIcons~ipad", cf_bundle_icons_ipad)?;
        }

        let has_tweaks = self.options.tweaks.as_ref().is_some_and(|t| !t.is_empty());

        if self.options.features.support_ellekit || has_tweaks {
            crate::Tweak::install_ellekit(&bundle).await?;
        }

        if let Some(tweak_files) = self.options.tweaks.as_ref() {
            for tweak_file in tweak_files {
                let tweak = crate::Tweak::new(tweak_file, bundle).await?;
                tweak.apply().await?;
            }
        }

        if self.options.features.support_liquid_glass {
            bundle.set_info_plist_key("UIDesignRequiresCompatibility", false)?;

            let executable_name = bundle
                .get_executable()
                .ok_or(Error::BundleInfoPlistMissing)?;

            let executable_path = bundle.bundle_dir().join(&executable_name);
            if !executable_path.exists() {
                return Err(Error::BundleInfoPlistMissing);
            }

            let mut macho = plume_core::MachO::new(&executable_path)?;
            macho.replace_sdk_version("26.0.0")?;
        }

        Ok(())
    }

    pub async fn register_bundle(
        &mut self,
        bundle: &Bundle,
        session: &DeveloperSession,
        team_id: &String,
        is_refresh: bool,
    ) -> Result<(), Error> {
        if self.options.mode != SignerMode::Pem {
            return Ok(());
        }

        let bundles = bundle
            .collect_bundles_sorted()?
            .into_iter()
            .filter(|b| b.bundle_type().should_have_entitlements())
            .collect::<Vec<_>>();
        let signer_settings = &self.options;

        let bundle_arc = Arc::new(bundle.clone());
        let session_arc = Arc::new(session);
        let team_id_arc = Arc::new(team_id.clone());

        let futures = bundles.iter().filter_map(|sub_bundle| {
            let sub_bundle = sub_bundle.clone();
            let bundle = bundle_arc.clone();
            let session = session_arc.clone();
            let team_id = team_id_arc.clone();
            let signer_settings = signer_settings.clone();

            if signer_settings.embedding.single_profile
                && sub_bundle.bundle_dir() != bundle.bundle_dir()
            {
                return None;
            }
            if *sub_bundle.bundle_type() != BundleType::AppExtension
                && *sub_bundle.bundle_type() != BundleType::App
            {
                return None;
            }

            Some(async move {
                let bundle_executable_name = sub_bundle
                    .get_executable()
                    .ok_or_else(|| Error::Other("Failed to get bundle executable name.".into()))?;
                let bundle_executable_path = sub_bundle.bundle_dir().join(&bundle_executable_name);

                let macho = plume_core::MachO::new(&bundle_executable_path)?;

                let id = sub_bundle
                    .get_bundle_identifier()
                    .ok_or_else(|| Error::Other("Failed to get bundle identifier.".into()))?;

                let name = sub_bundle.get_bundle_name().unwrap_or_else(|| id.clone());

                session.qh_ensure_app_id(&team_id, &name, &id).await?;

                let app_id_id = session
                    .qh_get_app_id(&team_id, &id)
                    .await?
                    .ok_or_else(|| Error::Other("Failed to get ensured app ID.".into()))?;

                // Capabilities the user opted into that the binary may not declare itself.
                // Registering them on the App ID gets them into the downloaded profile, so the
                // signature is authorized by the profile (injecting into the signature alone
                // would fail install with 0xe8008015).
                let mut extra_capabilities: Vec<&str> = Vec::new();
                if signer_settings.features.support_increased_memory_limit {
                    extra_capabilities.push("INCREASED_MEMORY_LIMIT");
                }

                let binary_entitlements = macho.entitlements();
                if binary_entitlements.is_some() || !extra_capabilities.is_empty() {
                    let empty = plist::Dictionary::new();
                    let entitlements = binary_entitlements.as_ref().unwrap_or(&empty);
                    session
                        .v1_request_capabilities_for_entitlements(
                            &team_id,
                            &id,
                            entitlements,
                            &extra_capabilities,
                        )
                        .await?;
                }

                if let Some(app_groups) = macho.app_groups_for_entitlements() {
                    let mut app_group_ids: Vec<String> = Vec::new();

                    for group in &app_groups {
                        if !group.starts_with("group.") {
                            continue;
                        }
                        let mut group_name = format!("{group}.{team_id}");

                        if is_refresh {
                            group_name = group.clone();
                        }
                        let group_id = session
                            .qh_ensure_app_group(&team_id, &group_name, &group_name)
                            .await?;
                        app_group_ids.push(group_id.application_group);
                    }

                    let default_group = format!("group.{}.{}", id, team_id);
                    if !app_group_ids.contains(&default_group) {
                        let default_group_id = session
                            .qh_ensure_app_group(&team_id, &default_group, &default_group)
                            .await?;
                        app_group_ids.push(default_group_id.application_group);
                    }

                    if !is_refresh {
                        if signer_settings.app == SignerApp::SideStore
                            || signer_settings.app == SignerApp::AltStore
                        {
                            bundle.set_info_plist_key(
                                "ALTAppGroups",
                                Value::Array(
                                    app_groups
                                        .iter()
                                        .map(|s| Value::String(format!("{s}.{team_id}")))
                                        .collect(),
                                ),
                            )?;
                        }
                    }

                    session
                        .qh_assign_app_group(&team_id, &app_id_id.app_id_id, &app_group_ids)
                        .await?;
                }

                let profiles = session
                    .qh_get_profile(&team_id, &app_id_id.app_id_id)
                    .await?;
                let profile_data = profiles.provisioning_profile.encoded_profile;

                tokio::fs::write(
                    sub_bundle.bundle_dir().join("embedded.mobileprovision"),
                    &profile_data,
                )
                .await?;
                let mobile_provision =
                    MobileProvision::load_with_bytes(profile_data.as_ref().to_vec())?;
                Ok::<_, Error>(mobile_provision)
            })
        });

        let provisionings: Vec<MobileProvision> = try_join_all(futures).await?;
        self.provisioning_files = provisionings;

        Ok(())
    }

    /// Wildcard variant of [`Self::register_bundle`]: instead of registering the app's real
    /// identifier (which 9401s when another team owns it), it ensures one stable placeholder
    /// App ID in our own namespace, then downloads the team provisioning profile. On a paid
    /// team that profile is the team-wide WILDCARD ("iOS Team Provisioning Profile: *"), so
    /// the app keeps its original bundle id and no per-app App ID is registered (exactly how
    /// Sideloadly signs apps it doesn't own). `merge_entitlements` substitutes `*` with the
    /// concrete bundle id at sign time. Paid teams only — free provisioning is explicit.
    pub async fn register_bundle_wildcard(
        &mut self,
        bundle: &Bundle,
        session: &DeveloperSession,
        team_id: &String,
    ) -> Result<(), Error> {
        if self.options.mode != SignerMode::Pem {
            return Ok(());
        }

        // A real wildcard App ID. downloadTeamProvisioningProfile then returns a wildcard
        // profile (TEAMID.*), and merge_entitlements substitutes `*` with the app's actual
        // bundle id at sign time. (An explicit placeholder App ID instead yields an explicit
        // profile whose application-identifier is the placeholder, which fails on device.)
        let wildcard = "*".to_string();
        session
            .qh_ensure_app_id(team_id, &"Wildcard".to_string(), &wildcard)
            .await?;
        let app_id = session
            .qh_get_app_id(team_id, &wildcard)
            .await?
            .ok_or_else(|| Error::Other("Failed to ensure wildcard app ID.".into()))?;

        let profiles = session.qh_get_profile(team_id, &app_id.app_id_id).await?;
        let profile_data = profiles.provisioning_profile.encoded_profile;

        tokio::fs::write(
            bundle.bundle_dir().join("embedded.mobileprovision"),
            &profile_data,
        )
        .await?;

        let mobile_provision = MobileProvision::load_with_bytes(profile_data.as_ref().to_vec())?;
        self.provisioning_files = vec![mobile_provision];
        self.wildcard_app_id_suffix = Some(team_id.clone());

        Ok(())
    }

    pub async fn sign_bundle(&self, bundle: &Bundle) -> Result<(), Error> {
        if self.options.mode == SignerMode::None {
            return Ok(());
        }

        let bundles = bundle.collect_bundles_sorted()?;

        let entitlements_xml = r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict/>
</plist>
"#.to_string();

        // Signing material pulled out as Send + Sync pieces: each worker parses its own key from
        // the DER (the boxed `dyn PrivateKey` is not Sync, so it cannot be shared across threads),
        // which produces byte-identical signatures to the single-threaded path.
        let cert_x509 = self.certificate.as_ref().and_then(|c| c.cert.clone());
        let key_der = self.certificate.as_ref().and_then(|c| c.key_der.clone());
        let mode = self.options.mode;
        let single_profile = self.options.embedding.single_profile;
        let custom_entitlements = self.options.custom_entitlements.clone();
        let wildcard = self.wildcard_app_id_suffix.clone();
        let provisioning = &self.provisioning_files;

        // Sign deepest bundles first (a container's seal covers its children), but sign all
        // bundles at the same nesting depth concurrently since they can never contain each other.
        use rayon::prelude::*;
        use std::collections::BTreeMap;
        let mut by_depth: BTreeMap<usize, Vec<&Bundle>> = BTreeMap::new();
        for b in &bundles {
            by_depth
                .entry(b.bundle_dir().components().count())
                .or_default()
                .push(b);
        }
        for (_depth, group) in by_depth.iter().rev() {
            group.par_iter().try_for_each(|bundle| -> Result<(), Error> {
                let key = match &key_der {
                    Some((der, true)) => Some(InMemoryPrivateKey::from_pkcs8_der(der)?),
                    Some((der, false)) => Some(InMemoryPrivateKey::from_pkcs1_der(der)?),
                    None => None,
                };
                let mut settings = SigningSettings::default();
                if let (Some(k), Some(c)) = (&key, &cert_x509) {
                    settings.set_signing_key(k.as_key_info_signer(), c.clone());
                    settings.chain_apple_certificates();
                    settings.set_team_id_from_signing_certificate();
                }
                settings.set_for_notarization(false);
                settings.set_shallow(true);

                Self::sign_single_bundle(
                    bundle,
                    provisioning,
                    mode,
                    single_profile,
                    custom_entitlements.as_deref(),
                    wildcard.as_deref(),
                    settings,
                    &entitlements_xml,
                )
            })?;
        }

        if let Some(cert) = &self.certificate {
            if let Some(key) = &cert.key {
                key.finish()?;
            }
        }

        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    fn sign_single_bundle(
        bundle: &Bundle,
        provisioning_files: &[MobileProvision],
        mode: SignerMode,
        single_profile: bool,
        custom_entitlements: Option<&Path>,
        wildcard_app_id_suffix: Option<&str>,
        mut settings: SigningSettings<'_>,
        entitlements_xml: &str,
    ) -> Result<(), Error> {
        if *bundle.bundle_type() == BundleType::Unknown {
            return Ok(());
        }

        let mut entitlements_xml = entitlements_xml.to_string();

        // Only Apps and AppExtensions should have entitlements from provisioning profiles
        // Dylibs, frameworks, and other components should be signed without entitlements
        // Skip provisioning profile handling for adhoc signing
        if mode != SignerMode::Adhoc
            && bundle.bundle_type().should_have_entitlements()
            && !provisioning_files.is_empty()
        {
            let mut matched_prov = None;

            for prov in provisioning_files {
                if let (Some(bundle_id), Some(team_id)) =
                    (bundle.get_bundle_identifier(), prov.bundle_id())
                {
                    if team_id == bundle_id {
                        matched_prov = Some(prov);
                        break;
                    }
                }
            }

            if let Some(prov) = matched_prov.or_else(|| provisioning_files.first()) {
                let mut prov = prov.clone();

                if let Some(bundle_executable) = bundle.get_executable() {
                    if let Some(bundle_id) = bundle.get_bundle_identifier() {
                        let binary_path = bundle.bundle_dir().join(bundle_executable);
                        // For wildcard signing, the entitlement's application-identifier gets the
                        // team-id suffix (matching Sideloadly so installs can replace its apps);
                        // the bundle's own CFBundleIdentifier is left untouched.
                        let app_id = match wildcard_app_id_suffix {
                            Some(suffix) => format!("{bundle_id}.{suffix}"),
                            None => bundle_id.clone(),
                        };
                        prov.merge_entitlements(binary_path, &app_id).ok();
                    }
                }

                std::fs::write(
                    bundle.bundle_dir().join("embedded.mobileprovision"),
                    &prov.data,
                )?;

                if let Ok(ent_xml) = prov.entitlements_as_bytes() {
                    entitlements_xml = String::from_utf8_lossy(&ent_xml).to_string();
                }
            }
        }

        if mode != SignerMode::Adhoc {
            if single_profile {
                if let Some(ent_path) = custom_entitlements {
                    let ent_bytes = std::fs::read(ent_path)?;
                    entitlements_xml = String::from_utf8_lossy(&ent_bytes).to_string();
                }
            }
            settings.set_entitlements_xml(SettingsScope::Main, entitlements_xml)?;
        }

        UnifiedSigner::new(settings).sign_path_in_place(bundle.bundle_dir())?;

        Ok(())
    }
}
