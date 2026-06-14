use plist::Dictionary;
use serde::Deserialize;
use serde_json::json;

use super::{DeveloperSession, RequestType};
use crate::developer_endpoint;

use crate::Error;
use std::collections::HashSet;

const FREE_DEVELOPER_ACCOUNT_UNALLOWED_CAPABILITIES: &[&str] = &[
    "AUTOFILL_CREDENTIAL_PROVIDER",
    "APPLE_ID_AUTH",
    "NETWORK_SLICING",
    "MERCHANT_ACCESSIBILITY_CONTROL",
    "ICLOUD",
    "ICLOUD_EXTENDED_SHARE_ACCESS",
    "IN_APP_PURCHASE",
    "JOURNALING_SUGGESTIONS",
    "MDM_MANAGED_ASSOCIATED_DOMAINS",
];

impl DeveloperSession {
    pub async fn v1_list_capabilities(&self, team: &String) -> Result<CapabilitiesResponse, Error> {
        let endpoint = developer_endpoint!("/v1/capabilities");

        let body = json!({
            "teamId": team,
            "urlEncodedQueryParams": "filter[platform]=IOS"
        });

        let response = self
            .v1_send_request(&endpoint, Some(body), Some(RequestType::Get))
            .await?;
        let response_data: CapabilitiesResponse = serde_json::from_value(response)?;

        Ok(response_data)
    }

    pub async fn v1_request_capabilities_for_entitlements(
        &self,
        team: &String,
        id: &String,
        entitlements: &Dictionary,
        extra_capabilities: &[&str],
    ) -> Result<(), Error> {
        let capabilities = self.v1_list_capabilities(team).await?.data;
        let entitlement_keys: HashSet<&str> = entitlements.keys().map(|k| k.as_str()).collect();
        let capabilities_to_enable =
            select_capabilities(&capabilities, &entitlement_keys, extra_capabilities);

        self.v1_update_app_id(team, id, capabilities_to_enable)
            .await?;

        Ok(())
    }
}

/// Pure selection of the capability IDs to enable on an App ID: every capability whose entitlement
/// `profile_key` matches one of the binary's entitlement keys and that isn't on the free-account
/// blocklist, unioned (deduped) with any caller-requested extras. Extras cover capabilities the
/// user opted into that the binary doesn't declare (e.g. injecting INCREASED_MEMORY_LIMIT). The
/// App ID PATCH replaces the whole list, so extras must be merged here rather than sent as a
/// second call that would clobber the entitlement-derived set. Split out from the network method
/// so it can be unit tested.
pub fn select_capabilities(
    available: &[Capability],
    entitlement_keys: &HashSet<&str>,
    extra_capabilities: &[&str],
) -> Vec<String> {
    let mut selected: Vec<String> = available
        .iter()
        .filter(|cap| !FREE_DEVELOPER_ACCOUNT_UNALLOWED_CAPABILITIES.contains(&cap.id.as_str()))
        .filter_map(|cap| {
            cap.attributes
                .entitlements
                .as_ref()?
                .iter()
                .find(|e| entitlement_keys.contains(e.profile_key.as_str()))
                .map(|_| cap.id.clone())
        })
        .collect();

    for extra in extra_capabilities {
        if !selected.iter().any(|c| c == extra) {
            selected.push((*extra).to_string());
        }
    }

    selected
}

#[allow(dead_code)]
#[derive(Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
pub struct CapabilitiesResponse {
    pub data: Vec<Capability>,
}

#[allow(dead_code)]
#[derive(Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
pub struct Capability {
    pub id: String,
    pub attributes: CapabilityAttributes,
}

#[allow(dead_code)]
#[derive(Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
pub struct CapabilityAttributes {
    pub entitlements: Option<Vec<CapabilityEntitlement>>,
    pub supports_wildcard: bool,
}

#[allow(dead_code)]
#[derive(Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
pub struct CapabilityEntitlement {
    pub profile_key: String,
}
