// Pure capability selection: entitlement-key matching, free-account blocklist filtering, and
// the deduped union of opt-in extras (the INCREASED_MEMORY_LIMIT injection path).

use plume_core::developer::v1::capabilities::{
    Capability, CapabilityAttributes, CapabilityEntitlement, select_capabilities,
};
use std::collections::HashSet;

fn cap(id: &str, profile_key: &str) -> Capability {
    Capability {
        id: id.to_string(),
        attributes: CapabilityAttributes {
            entitlements: Some(vec![CapabilityEntitlement {
                profile_key: profile_key.to_string(),
            }]),
            supports_wildcard: false,
        },
    }
}

fn keys(values: &[&'static str]) -> HashSet<&'static str> {
    values.iter().copied().collect()
}

#[test]
fn selects_capability_whose_entitlement_key_is_declared() {
    let available = vec![
        cap("GAME_CENTER", "com.apple.developer.game-center"),
        cap(
            "INCREASED_MEMORY_LIMIT",
            "com.apple.developer.kernel.increased-memory-limit",
        ),
    ];
    let declared = keys(&["com.apple.developer.kernel.increased-memory-limit"]);

    let selected = select_capabilities(&available, &declared, &[]);

    assert!(selected.contains(&"INCREASED_MEMORY_LIMIT".to_string()));
    assert!(
        !selected.contains(&"GAME_CENTER".to_string()),
        "capability not declared by the binary must not be selected"
    );
}

#[test]
fn excludes_capabilities_blocked_for_free_accounts() {
    let available = vec![cap("ICLOUD", "com.apple.developer.icloud-services")];
    let declared = keys(&["com.apple.developer.icloud-services"]);

    let selected = select_capabilities(&available, &declared, &[]);

    assert!(
        selected.is_empty(),
        "iCloud is on the free-account blocklist and must be filtered out"
    );
}

#[test]
fn unions_extra_capability_not_declared_by_the_binary() {
    let available = vec![cap(
        "INCREASED_MEMORY_LIMIT",
        "com.apple.developer.kernel.increased-memory-limit",
    )];
    let declared: HashSet<&str> = HashSet::new();

    let selected = select_capabilities(&available, &declared, &["INCREASED_MEMORY_LIMIT"]);

    assert_eq!(selected, vec!["INCREASED_MEMORY_LIMIT".to_string()]);
}

#[test]
fn extra_capability_is_not_duplicated_when_also_declared() {
    let available = vec![cap(
        "INCREASED_MEMORY_LIMIT",
        "com.apple.developer.kernel.increased-memory-limit",
    )];
    let declared = keys(&["com.apple.developer.kernel.increased-memory-limit"]);

    let selected = select_capabilities(&available, &declared, &["INCREASED_MEMORY_LIMIT"]);

    assert_eq!(
        selected.iter().filter(|c| c.as_str() == "INCREASED_MEMORY_LIMIT").count(),
        1
    );
}
