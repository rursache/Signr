//! Native macOS anisette data, sourced from the same on-device ADI that Apple's own apps use.
//!
//! This is the first tier of `plume_core`'s anisette chain. We ask AOSKit's `AOSUtilities` for
//! the one-time-password + machine-id headers (these come from `akd` over XPC, so they are valid
//! for THIS Mac), then fill in the device-identity headers from the machine UDID/serial and a
//! sysctl-built client-info string. The shape matches what omnisette produces, so the tiers are
//! interchangeable from the caller's side.
//!
//! Mapping follows AltServer's proven native pairing (X-Apple-I-MD-LU = base64(UTF8(udid)),
//! device-id = raw udid, serial = machineSerialNumber).
//!
//! macOS 27 refuses this process access to `com.apple.ak.anisette.xpc` regardless of how the
//! binary is signed, so `retrieveOTPHeadersForDSID:` returns an empty dictionary and we report
//! `MissingKey`. That is expected there, and the caller falls through to the emulated-ADI and
//! remote tiers. macOS 26 and earlier are unaffected and still take this path (RS-263).

use std::collections::HashMap;
use std::ffi::CString;

use base64::Engine;
use objc2::rc::{autoreleasepool, Retained};
use objc2::runtime::{AnyClass, AnyObject};
use objc2::msg_send;
use objc2_foundation::NSString;

#[derive(Debug, thiserror::Error)]
pub enum NativeAnisetteError {
    #[error("AOSKit class AOSUtilities not found")]
    ClassNotFound,
    #[error("AOSUtilities returned no OTP header dictionary")]
    NoOtpHeaders,
    #[error("OTP header dictionary missing key {0}")]
    MissingKey(&'static str),
    #[error("machine identifier (UDID) unavailable")]
    NoMachineId,
}

const AOSKIT_PATH: &[u8] = b"/System/Library/PrivateFrameworks/AOSKit.framework/AOSKit\0";
const DSID: &str = "-2"; // production environment pseudo-DSID, same value AltServer uses
const ROUTING_INFO: &str = "17106176"; // matches the value the emulated path shipped with

fn load_aoskit() {
    // dlopen registers AOSKit's ObjC classes with the runtime. Safe to call repeatedly.
    unsafe {
        libc::dlopen(AOSKIT_PATH.as_ptr() as *const _, libc::RTLD_NOW | libc::RTLD_GLOBAL);
    }
}

fn sysctl(name: &str) -> Option<String> {
    let cname = CString::new(name).ok()?;
    let mut size: libc::size_t = 0;
    unsafe {
        if libc::sysctlbyname(cname.as_ptr(), std::ptr::null_mut(), &mut size, std::ptr::null_mut(), 0) != 0 {
            return None;
        }
        let mut buf = vec![0u8; size];
        if libc::sysctlbyname(cname.as_ptr(), buf.as_mut_ptr() as *mut _, &mut size, std::ptr::null_mut(), 0) != 0 {
            return None;
        }
        if buf.last() == Some(&0) {
            buf.pop();
        }
        String::from_utf8(buf).ok()
    }
}

unsafe fn class_string(cls: &AnyClass, sel: impl FnOnce(&AnyClass) -> Option<Retained<NSString>>) -> Option<String> {
    sel(cls).map(|s| s.to_string())
}

unsafe fn dict_get(dict: &AnyObject, key: &str) -> Option<String> {
    let k = NSString::from_str(key);
    let v: Option<Retained<NSString>> = msg_send![dict, objectForKey: &*k];
    v.map(|s| s.to_string())
}

// Apple's GSA edge started returning HTTP 503 for any client-info naming com.apple.dt.Xcode
// (Sept 2026), so the agent has to identify as akd instead.
fn client_info() -> String {
    let model = sysctl("hw.model").unwrap_or_else(|| "iMac21,1".to_string());
    let version = sysctl("kern.osproductversion").unwrap_or_else(|| "26.0".to_string());
    let build = sysctl("kern.osversion").unwrap_or_default();
    format!("<{model}> <macOS;{version};{build}> <com.apple.AuthKit/1 (com.apple.akd/1.0)>")
}

/// This Mac's hardware serial, used to identify the device to a remote anisette server.
pub fn machine_serial() -> Option<String> {
    load_aoskit();
    autoreleasepool(|_| unsafe {
        let cls = AnyClass::get(c"AOSUtilities")?;
        class_string(cls, |c| msg_send![c, machineSerialNumber])
    })
}

/// Build the anisette base headers from this Mac's native ADI. The returned map has the exact
/// 7 keys the emulated provider produced, so it drops straight into plume_core's `AnisetteData`.
pub fn base_headers() -> Result<HashMap<String, String>, NativeAnisetteError> {
    load_aoskit();

    autoreleasepool(|_| unsafe {
        let cls = AnyClass::get(c"AOSUtilities").ok_or(NativeAnisetteError::ClassNotFound)?;

        let dsid = NSString::from_str(DSID);
        let otp_dict: Option<Retained<AnyObject>> = msg_send![cls, retrieveOTPHeadersForDSID: &*dsid];
        let otp_dict = otp_dict.ok_or(NativeAnisetteError::NoOtpHeaders)?;

        let otp = dict_get(&otp_dict, "X-Apple-MD").ok_or(NativeAnisetteError::MissingKey("X-Apple-MD"))?;
        let mid = dict_get(&otp_dict, "X-Apple-MD-M").ok_or(NativeAnisetteError::MissingKey("X-Apple-MD-M"))?;

        let udid = class_string(cls, |c| msg_send![c, machineUDID]).ok_or(NativeAnisetteError::NoMachineId)?;
        let serial = class_string(cls, |c| msg_send![c, machineSerialNumber])
            .unwrap_or_else(|| "C02LKHBBFD57".to_string());

        let local_user = base64::engine::general_purpose::STANDARD.encode(udid.as_bytes());

        let mut headers = HashMap::with_capacity(7);
        headers.insert("X-Apple-I-MD".to_string(), otp);
        headers.insert("X-Apple-I-MD-M".to_string(), mid);
        headers.insert("X-Apple-I-MD-RINFO".to_string(), ROUTING_INFO.to_string());
        headers.insert("X-Apple-I-MD-LU".to_string(), local_user);
        headers.insert("X-Apple-I-SRL-NO".to_string(), serial);
        headers.insert("X-Mme-Client-Info".to_string(), client_info());
        headers.insert("X-Mme-Device-Id".to_string(), udid);
        Ok(headers)
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    const REQUIRED: [&str; 7] = [
        "X-Apple-I-MD",
        "X-Apple-I-MD-M",
        "X-Apple-I-MD-RINFO",
        "X-Apple-I-MD-LU",
        "X-Apple-I-SRL-NO",
        "X-Mme-Client-Info",
        "X-Mme-Device-Id",
    ];

    // RS-263: Apple's GSA edge 503s any client-info naming com.apple.dt.Xcode.
    #[test]
    fn client_info_identifies_as_akd() {
        let info = client_info();
        assert!(info.contains("com.apple.akd/1.0"), "got {info}");
        assert!(!info.contains("dt.Xcode"), "got {info}");
    }

    #[test]
    fn client_info_has_three_angle_bracket_groups() {
        let info = client_info();
        assert_eq!(info.matches('<').count(), 3, "got {info}");
        assert!(info.contains("<macOS;"), "got {info}");
    }

    /// The machine identity half of AOSKit keeps working even where the OTP half is blocked,
    /// so this should hold on every macOS we support.
    #[test]
    fn machine_serial_is_available() {
        assert!(machine_serial().is_some_and(|s| !s.is_empty()));
    }

    /// On macOS 26 and earlier akd answers and we get a full set of headers. On macOS 27 the
    /// anisette XPC service refuses us and AOSKit hands back an empty dictionary. Both are
    /// acceptable here; what must never happen is a partial set or a panic, because the caller
    /// falls back to another provider on `Err` and trusts every key on `Ok`.
    #[test]
    fn base_headers_are_complete_or_cleanly_absent() {
        match base_headers() {
            Ok(h) => {
                for k in REQUIRED {
                    assert!(h.get(k).is_some_and(|v| !v.is_empty()), "missing header {k}");
                }
                assert!(h["X-Mme-Client-Info"].contains("com.apple.akd/1.0"));
            }
            Err(NativeAnisetteError::MissingKey(_) | NativeAnisetteError::NoOtpHeaders) => {
                // akd declined (macOS 27); the fallback chain takes over from here.
            }
            Err(e) => panic!("unexpected native anisette failure: {e}"),
        }
    }

    /// The AOSKit calls run on a tokio blocking worker in production, not the main thread.
    #[test]
    fn base_headers_behaves_the_same_off_the_main_thread() {
        let spawned = std::thread::spawn(base_headers).join().unwrap();
        assert_eq!(spawned.is_ok(), base_headers().is_ok());
    }
}
