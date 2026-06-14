use super::{Bundle, PlistInfoTrait};
use crate::{Error, SignerApp, SignerOptions, cgbi};
use plist::Dictionary;
use rayon::prelude::*;
use std::io::Cursor;
use std::path::{Path, PathBuf};
use std::{env, fs, io::Read};
use uuid::Uuid;
use zip::ZipArchive;
use zip::write::FileOptions;

#[derive(Debug, Clone)]
pub struct Package {
    package_file: PathBuf,
    stage_dir: PathBuf,
    stage_payload_dir: PathBuf,
    info_plist_dictionary: Dictionary,
    archive_entries: Vec<String>,
    pub app_icon_data: Option<Vec<u8>>,
}

impl Package {
    pub fn new(package_file: PathBuf) -> Result<Self, Error> {
        let stage_dir = env::temp_dir().join(format!(
            "plume_stage_{:08}",
            Uuid::new_v4().to_string().to_uppercase()
        ));
        fs::create_dir_all(&stage_dir).ok();

        // Read straight from the original IPA, no full-file copy into the stage dir.
        let file = fs::File::open(&package_file)?;
        let mut archive = ZipArchive::new(file)?;
        let archive_entries = (0..archive.len())
            .filter_map(|i| archive.by_index(i).ok().map(|f| f.name().to_string()))
            .collect::<Vec<_>>();

        let info_plist_dictionary =
            Self::get_info_plist_from_archive(&package_file, &archive_entries)?;

        let app_icon_data =
            Self::extract_icon_from_archive(&package_file, &archive_entries, &info_plist_dictionary);

        Ok(Self {
            package_file,
            stage_dir: stage_dir.clone(),
            stage_payload_dir: stage_dir.join("Payload"),
            info_plist_dictionary,
            archive_entries,
            app_icon_data,
        })
    }

    pub fn package_file(&self) -> &PathBuf {
        &self.package_file
    }

    fn get_info_plist_from_archive(
        archive_path: &PathBuf,
        archive_entries: &[String],
    ) -> Result<Dictionary, Error> {
        let file = fs::File::open(archive_path)?;
        let mut archive = ZipArchive::new(file)?;

        let info_plist_path = archive_entries
            .iter()
            .find(|entry| {
                entry.starts_with("Payload/")
                    && entry.ends_with("/Info.plist")
                    && entry.matches('/').count() == 2
            })
            .ok_or(Error::PackageInfoPlistMissing)?;

        let mut plist_file = archive.by_name(info_plist_path)?;
        let mut plist_data = Vec::new();
        plist_file.read_to_end(&mut plist_data)?;

        Ok(plist::from_bytes(&plist_data)?)
    }

    fn extract_icon_from_archive(
        archive_path: &PathBuf,
        archive_entries: &[String],
        plist: &Dictionary,
    ) -> Option<Vec<u8>> {
        // Collects all candidate icon base names from the plist, in order of preference.
        // CFBundleIcons (iPhone) takes priority, fall back to CFBundleIcons~ipad, then
        // top-level CFBundleIconFiles.
        let mut icon_names: Vec<String> = Vec::new();

        let primary_from = |d: &Dictionary| -> Vec<String> {
            d.get("CFBundlePrimaryIcon")
                .and_then(|v| v.as_dictionary())
                .and_then(|d| d.get("CFBundleIconFiles"))
                .and_then(|v| v.as_array())
                .map(|arr| {
                    arr.iter()
                        .filter_map(|v| v.as_string())
                        .map(|s| s.to_string())
                        .collect::<Vec<_>>()
                })
                .unwrap_or_default()
        };

        if let Some(d) = plist.get("CFBundleIcons").and_then(|v| v.as_dictionary()) {
            icon_names.extend(primary_from(d));
        }
        if let Some(d) = plist
            .get("CFBundleIcons~ipad")
            .and_then(|v| v.as_dictionary())
        {
            for n in primary_from(d) {
                if !icon_names.contains(&n) {
                    icon_names.push(n);
                }
            }
        }
        if let Some(arr) = plist.get("CFBundleIconFiles").and_then(|v| v.as_array()) {
            for n in arr
                .iter()
                .filter_map(|v| v.as_string())
                .map(|s| s.to_string())
            {
                if !icon_names.contains(&n) {
                    icon_names.push(n);
                }
            }
        }

        if icon_names.is_empty() {
            return None;
        }

        let app_prefix = archive_entries
            .iter()
            .find(|e| {
                e.starts_with("Payload/")
                    && e.ends_with("/Info.plist")
                    && e.matches('/').count() == 2
            })?
            .trim_end_matches("/Info.plist");

        let file = fs::File::open(archive_path).ok()?;
        let mut archive = ZipArchive::new(file).ok()?;

        let suffixes = ["@3x.png", "@2x.png", "@1x.png", ".png"];

        for name in &icon_names {
            for suffix in &suffixes {
                let candidate = format!("{app_prefix}/{name}{suffix}");
                if let Ok(mut entry) = archive.by_name(&candidate) {
                    let mut data = Vec::new();
                    if entry.read_to_end(&mut data).is_ok() && !data.is_empty() {
                        return Some(cgbi::normalize(data));
                    }
                }
            }
        }

        None
    }

    pub fn get_package_bundle(&self) -> Result<Bundle, Error> {
        extract_archive_parallel(&self.package_file, &self.stage_dir)?;

        let app_dir = fs::read_dir(&self.stage_payload_dir)?
            .filter_map(Result::ok)
            .map(|e| e.path())
            .find(|p| p.is_dir() && p.extension().and_then(|e| e.to_str()) == Some("app"))
            .ok_or_else(|| Error::PackageInfoPlistMissing)?;

        Ok(Bundle::new(app_dir)?)
    }

    pub fn get_archive_based_on_path(&self, path: &PathBuf) -> Result<PathBuf, Error> {
        if path.is_dir() {
            self.clone().archive_package_bundle()
        } else {
            Ok(self.package_file.clone())
        }
    }

    pub fn archive_package_bundle(self) -> Result<PathBuf, Error> {
        let zip_file_path = self.stage_dir.join("resigned.ipa");
        let file = fs::File::create(&zip_file_path)?;
        let mut zip = zip::ZipWriter::new(file);
        // STORED, not Deflated: the device unzips the IPA the instant it lands, so spending CPU
        // to compress (poorly, on already-compressed app assets) only slows the round-trip. This
        // is what Xcode emits too.
        let options = FileOptions::default().compression_method(zip::CompressionMethod::Stored);

        let payload_dir = self.stage_payload_dir;

        fn add_dir_to_zip(
            zip: &mut zip::ZipWriter<fs::File>,
            path: &PathBuf,
            prefix: &PathBuf,
            options: &FileOptions<'_, zip::write::ExtendedFileOptions>,
        ) -> Result<(), Error> {
            for entry in fs::read_dir(path)? {
                let entry = entry?;
                let entry_path = entry.path();
                let name = entry_path
                    .strip_prefix(prefix)
                    .map_err(|_| Error::PackageInfoPlistMissing)?
                    .to_string_lossy()
                    .to_string();

                if entry_path.is_file() {
                    zip.start_file(&name, options.clone())?;
                    let mut f = fs::File::open(&entry_path)?;
                    std::io::copy(&mut f, zip)?;
                } else if entry_path.is_dir() {
                    zip.add_directory(&name, options.clone())?;
                    add_dir_to_zip(zip, &entry_path, prefix, options)?;
                }
            }
            Ok(())
        }

        add_dir_to_zip(&mut zip, &payload_dir, &self.stage_dir, &options)?;
        zip.finish()?;

        Ok(zip_file_path)
    }

    pub fn remove_package_stage(self) {
        fs::remove_dir_all(&self.stage_dir).ok();
    }
}

/// Extract a zip the way `ZipArchive::extract` would (preserving unix modes and symlinks), but
/// with the per-entry decompression spread across all cores. The input is mmap'd so each worker
/// reads from the shared page cache, and directories/symlinks are created in a cheap serial pass
/// up front so the parallel file writes never race on directory creation.
fn extract_archive_parallel(zip_path: &Path, dest: &Path) -> Result<(), Error> {
    let file = fs::File::open(zip_path)?;
    let mmap = unsafe { memmap2::Mmap::map(&file)? };
    let bytes: &[u8] = &mmap;

    let mut archive = ZipArchive::new(Cursor::new(bytes))?;
    let count = archive.len();

    // Pass 1 (serial, cheap): create directories + symlinks, collect the file entries to inflate.
    let mut file_indices: Vec<usize> = Vec::with_capacity(count);
    for i in 0..count {
        let mut entry = archive.by_index(i)?;
        let Some(rel) = entry.enclosed_name() else { continue };
        let outpath = dest.join(&rel);

        if entry.is_dir() {
            fs::create_dir_all(&outpath)?;
            continue;
        }
        if let Some(parent) = outpath.parent() {
            fs::create_dir_all(parent)?;
        }
        #[cfg(unix)]
        if entry.is_symlink() {
            let mut target = Vec::new();
            entry.read_to_end(&mut target)?;
            let target = String::from_utf8_lossy(&target).into_owned();
            let _ = fs::remove_file(&outpath);
            std::os::unix::fs::symlink(target, &outpath)?;
            continue;
        }
        file_indices.push(i);
    }

    // Pass 2 (parallel): inflate file entries. Each worker opens its own archive over the same
    // mmap so it has an independent read cursor; the central directory is parsed once per worker.
    let nthreads = rayon::current_num_threads().max(1);
    let chunk = file_indices.len().div_ceil(nthreads).max(1);
    file_indices
        .par_chunks(chunk)
        .try_for_each(|indices| -> Result<(), Error> {
            let mut archive = ZipArchive::new(Cursor::new(bytes))?;
            for &i in indices {
                let mut entry = archive.by_index(i)?;
                let Some(rel) = entry.enclosed_name() else { continue };
                let outpath = dest.join(&rel);
                let mut out = fs::File::create(&outpath)?;
                std::io::copy(&mut entry, &mut out)?;
                #[cfg(unix)]
                if let Some(mode) = entry.unix_mode() {
                    use std::os::unix::fs::PermissionsExt;
                    fs::set_permissions(&outpath, fs::Permissions::from_mode(mode))?;
                }
            }
            Ok(())
        })?;

    Ok(())
}

// TODO: make bundle and package share a common trait for plist info access
macro_rules! get_plist_dict_value {
    ($self:ident, $key:expr) => {{
        $self
            .info_plist_dictionary
            .get($key)
            .and_then(|v| v.as_string())
            .map(|s| s.to_string())
    }};
}

impl PlistInfoTrait for Package {
    fn get_name(&self) -> Option<String> {
        get_plist_dict_value!(self, "CFBundleDisplayName")
            .or_else(|| get_plist_dict_value!(self, "CFBundleName"))
            .or_else(|| self.get_executable())
    }

    fn get_executable(&self) -> Option<String> {
        get_plist_dict_value!(self, "CFBundleExecutable")
    }

    fn get_bundle_identifier(&self) -> Option<String> {
        get_plist_dict_value!(self, "CFBundleIdentifier")
    }

    fn get_bundle_name(&self) -> Option<String> {
        get_plist_dict_value!(self, "CFBundleName")
    }

    fn get_version(&self) -> Option<String> {
        get_plist_dict_value!(self, "CFBundleShortVersionString")
    }

    fn get_build_version(&self) -> Option<String> {
        get_plist_dict_value!(self, "CFBundleVersion")
    }
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use std::io::Write;
    use std::os::unix::fs::PermissionsExt;
    use zip::write::SimpleFileOptions;

    #[test]
    fn parallel_extract_preserves_modes_and_symlinks() {
        let dir = env::temp_dir().join(format!("plume_extract_test_{}", Uuid::new_v4()));
        fs::create_dir_all(&dir).unwrap();
        let zip_path = dir.join("t.zip");
        let dest = dir.join("out");

        {
            let f = fs::File::create(&zip_path).unwrap();
            let mut w = zip::ZipWriter::new(f);
            w.add_directory("Payload/", SimpleFileOptions::default()).unwrap();
            w.start_file(
                "Payload/plain.txt",
                SimpleFileOptions::default().unix_permissions(0o644),
            )
            .unwrap();
            w.write_all(b"hello").unwrap();
            w.start_file(
                "Payload/App.app/bin",
                SimpleFileOptions::default().unix_permissions(0o755),
            )
            .unwrap();
            w.write_all(b"#!/bin/sh\n").unwrap();
            w.add_symlink(
                "Payload/App.app/Current",
                "Versions/A",
                SimpleFileOptions::default(),
            )
            .unwrap();
            w.finish().unwrap();
        }

        extract_archive_parallel(&zip_path, &dest).unwrap();

        let plain = dest.join("Payload/plain.txt");
        assert_eq!(fs::read(&plain).unwrap(), b"hello");
        assert_eq!(fs::metadata(&plain).unwrap().permissions().mode() & 0o777, 0o644);

        let bin = dest.join("Payload/App.app/bin");
        assert_eq!(fs::metadata(&bin).unwrap().permissions().mode() & 0o777, 0o755);

        let link = dest.join("Payload/App.app/Current");
        let meta = fs::symlink_metadata(&link).unwrap();
        assert!(meta.file_type().is_symlink());
        assert_eq!(fs::read_link(&link).unwrap(), Path::new("Versions/A"));

        fs::remove_dir_all(&dir).ok();
    }
}

impl Package {
    pub fn load_into_signer_options<'settings, 'slf: 'settings>(
        &'slf self,
        settings: &'settings mut SignerOptions,
    ) {
        let app = if self
            .archive_entries
            .iter()
            .any(|entry| entry.contains("SideStoreApp.framework"))
        {
            SignerApp::LiveContainerAndSideStore
        } else {
            SignerApp::from_bundle_identifier(self.get_bundle_identifier().as_deref())
        };

        let new_settings = SignerOptions::new_for_app(app);
        *settings = new_settings;
    }
}
