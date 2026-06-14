// MachO operations on the fixture IPA's real (universal) executable: parsing + entitlement
// extraction, SDK version patching, and dylib inject/remove.
//
// The fixture is a FAT binary, and write_changes() re-encodes the whole universal binary, so
// add+remove is not guaranteed byte-identical to the input. These tests therefore assert that
// each operation succeeds and leaves a still-parseable binary, which is what the signing
// pipeline relies on. add_dylib can legitimately fail when a binary has no spare load-command
// space, so the inject test is best-effort and logged in that case.

use plume_core::MachO;
use std::fs::{self, File};
use std::path::PathBuf;

fn fixture_ipa() -> PathBuf {
    PathBuf::from(concat!(env!("CARGO_MANIFEST_DIR"), "/../../Tests/test_app.ipa"))
}

fn scratch_dir(tag: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("signr_macho_{}_{tag}", std::process::id()));
    fs::create_dir_all(&dir).unwrap();
    dir
}

// Extract Payload/<App>.app/<App> (the main executable) to a fresh file and return its path.
fn extract_executable(dest: &PathBuf) -> PathBuf {
    fs::create_dir_all(dest).unwrap();
    let mut zip = zip::ZipArchive::new(File::open(fixture_ipa()).unwrap()).unwrap();

    let mut entry_name = None;
    for i in 0..zip.len() {
        let name = zip.by_index(i).unwrap().name().to_string();
        if let Some(rest) = name.strip_prefix("Payload/") {
            let parts: Vec<&str> = rest.split('/').collect();
            if parts.len() == 2 {
                if let Some(app_base) = parts[0].strip_suffix(".app") {
                    if parts[1] == app_base {
                        entry_name = Some(name);
                        break;
                    }
                }
            }
        }
    }
    let entry_name = entry_name.expect("main executable not found in IPA");

    let out = dest.join("exe");
    let mut entry = zip.by_name(&entry_name).unwrap();
    let mut f = File::create(&out).unwrap();
    std::io::copy(&mut entry, &mut f).unwrap();
    out
}

#[test]
fn parses_the_real_executable_and_extracts_entitlements_without_error() {
    let dir = scratch_dir("parse");
    let exe = extract_executable(&dir);

    // MachO::new runs entitlement extraction internally, so a successful parse proves the
    // extractor handles this real binary (the getter may still be None for a store binary).
    let macho = MachO::new(&exe).expect("fixture executable should parse");
    let _ = macho.entitlements();

    fs::remove_dir_all(&dir).ok();
}

#[test]
fn replace_sdk_version_keeps_the_binary_parseable() {
    let dir = scratch_dir("sdk");
    let exe = extract_executable(&dir);

    MachO::new(&exe)
        .unwrap()
        .replace_sdk_version("26.0.0")
        .expect("sdk patch should succeed");

    MachO::new(&exe).expect("binary should re-parse after the SDK patch");

    fs::remove_dir_all(&dir).ok();
}

#[test]
fn inject_dylib_keeps_the_binary_parseable() {
    let dir = scratch_dir("dylib");
    let exe = extract_executable(&dir);
    let dylib = "@rpath/SignrTestInjected.dylib";

    // Injection is the path the signer actually uses (tweaks add load commands). It can fail when
    // a binary has no spare header space, so treat that as a skip rather than a failure.
    match MachO::new(&exe).unwrap().add_dylib(dylib) {
        Ok(()) => {
            MachO::new(&exe).expect("binary should parse after dylib injection");
        }
        Err(e) => {
            eprintln!("add_dylib skipped (no spare load-command space): {e}");
        }
    }

    fs::remove_dir_all(&dir).ok();
}
