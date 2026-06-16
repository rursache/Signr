// A device reachable over both USB and WiFi collapses to a single USB entry (usbmuxd assigns a
// separate device_id per transport, so the same udid would otherwise appear twice).

use signr_core::{dedup_prefer_usb, DeviceInfo, DeviceLink};

fn dev(name: &str, udid: &str, device_id: u64, link: DeviceLink) -> DeviceInfo {
    DeviceInfo {
        name: name.to_string(),
        udid: udid.to_string(),
        device_id,
        product_type: None,
        os_version: None,
        is_mac: false,
        link,
    }
}

#[test]
fn collapses_usb_and_wifi_to_the_usb_entry() {
    let out = dedup_prefer_usb(vec![
        dev("iPad", "UDID-A", 1, DeviceLink::Wifi),
        dev("iPad", "UDID-A", 2, DeviceLink::Usb),
        dev("iPhone", "UDID-B", 3, DeviceLink::Wifi),
    ]);
    assert_eq!(out.len(), 2);
    let ipad = out.iter().find(|d| d.udid == "UDID-A").unwrap();
    assert!(matches!(ipad.link, DeviceLink::Usb));
    assert_eq!(ipad.device_id, 2, "keeps the USB connection's device_id");
    let iphone = out.iter().find(|d| d.udid == "UDID-B").unwrap();
    assert!(matches!(iphone.link, DeviceLink::Wifi), "WiFi-only device is untouched");
}

#[test]
fn prefers_usb_regardless_of_order() {
    let out = dedup_prefer_usb(vec![
        dev("iPad", "U", 2, DeviceLink::Usb),
        dev("iPad", "U", 1, DeviceLink::Wifi),
    ]);
    assert_eq!(out.len(), 1);
    assert!(matches!(out[0].link, DeviceLink::Usb));
    assert_eq!(out[0].device_id, 2);
}

#[test]
fn devices_without_a_udid_are_never_collapsed() {
    let out = dedup_prefer_usb(vec![
        dev("A", "", 1, DeviceLink::Wifi),
        dev("B", "", 2, DeviceLink::Wifi),
    ]);
    assert_eq!(out.len(), 2);
}
