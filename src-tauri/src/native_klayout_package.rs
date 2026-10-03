//! The optional viewer package is pinned independently of qualified engine tools.
use serde::Deserialize;
use sha2::{Digest, Sha256};
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::path::{Component, Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

pub(super) const VERSION: &str = "0.30.12";
pub(super) const DESCRIPTOR: &str = include_str!("../../packaging/extensions/klayout/0.30.12.json");
const MAX_FILES: usize = 40_000;
const MAX_EXPANDED: u64 = 1_200_000_000;
const MAX_FILE: u64 = 128 * 1024 * 1024;

#[derive(Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(super) struct Package {
    pub url: String,
    pub sha256: String,
    pub size_bytes: u64,
    pub archive_root: Option<String>,
    pub executable: String,
}
pub(super) fn package(id: &str) -> Result<Package, String> {
    let document: serde_json::Value =
        serde_json::from_str(DESCRIPTOR).map_err(|_| "klayout.package_invalid")?;
    serde_json::from_value(document["packages"][id].clone())
        .map_err(|_| "klayout.unsupported".into())
}
pub(super) fn check(cancel: &AtomicBool) -> Result<(), String> {
    if cancel.load(Ordering::Acquire) {
        Err("klayout.cancelled".into())
    } else {
        Ok(())
    }
}
pub(super) fn regular(path: &Path) -> Result<fs::Metadata, String> {
    let metadata = fs::symlink_metadata(path).map_err(|_| "klayout.integrity_failed")?;
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt;
        if metadata.file_attributes() & 0x400 != 0 {
            return Err("klayout.integrity_failed".into());
        }
    }
    if metadata.file_type().is_symlink() {
        return Err("klayout.integrity_failed".into());
    }
    Ok(metadata)
}
pub(super) fn safe_directory(path: &Path) -> Result<(), String> {
    if !path.is_absolute() {
        return Err("klayout.storage_unavailable".into());
    }
    for ancestor in path.ancestors().collect::<Vec<_>>().into_iter().rev() {
        if ancestor.exists() {
            if !regular(ancestor)?.is_dir() {
                return Err("klayout.storage_unavailable".into());
            }
        } else {
            fs::create_dir(ancestor).map_err(|_| "klayout.storage_unavailable")?;
        }
    }
    Ok(())
}
fn digest_reader(mut reader: impl Read, cancel: &AtomicBool) -> Result<(u64, String), String> {
    let mut hash = Sha256::new();
    let mut length = 0;
    let mut buffer = [0; 128 * 1024];
    loop {
        check(cancel)?;
        let size = reader
            .read(&mut buffer)
            .map_err(|_| "klayout.read_failed")?;
        if size == 0 {
            break;
        }
        length += size as u64;
        hash.update(&buffer[..size]);
    }
    Ok((length, format!("{:x}", hash.finalize())))
}
pub(super) fn verify_archive(
    path: &Path,
    pin: &Package,
    cancel: &AtomicBool,
) -> Result<(), String> {
    let metadata = regular(path)?;
    if !metadata.is_file() || metadata.len() != pin.size_bytes {
        return Err("klayout.integrity_failed".into());
    }
    let (size, hash) = digest_reader(File::open(path).map_err(|_| "klayout.read_failed")?, cancel)?;
    if size != pin.size_bytes || hash != pin.sha256 {
        return Err("klayout.integrity_failed".into());
    }
    Ok(())
}
pub(super) fn download(pin: &Package, path: &Path, cancel: &AtomicBool) -> Result<(), String> {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|_| "klayout.download_failed")?;
    runtime.block_on(download_async(pin, path, cancel))
}
async fn cancellable<T>(
    future: impl std::future::Future<Output = T>,
    cancel: &AtomicBool,
) -> Result<T, String> {
    tokio::pin!(future);
    loop {
        check(cancel)?;
        tokio::select! {
            result = &mut future => return Ok(result),
            _ = tokio::time::sleep(Duration::from_millis(50)) => {},
        }
    }
}
async fn download_async(pin: &Package, path: &Path, cancel: &AtomicBool) -> Result<(), String> {
    // Neither redirects, renderer URLs nor credentials participate in this download.
    check(cancel)?;
    let client = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .connect_timeout(Duration::from_secs(15))
        .timeout(Duration::from_secs(600))
        .build()
        .map_err(|_| "klayout.download_failed")?;
    let mut response = cancellable(client.get(&pin.url).send(), cancel)
        .await?
        .map_err(|_| "klayout.download_failed")?
        .error_for_status()
        .map_err(|_| "klayout.download_failed")?;
    if response
        .content_length()
        .is_some_and(|size| size != pin.size_bytes)
    {
        return Err("klayout.integrity_failed".into());
    }
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
        .map_err(|_| "klayout.storage_unavailable")?;
    let started = Instant::now();
    let mut hash = Sha256::new();
    let mut size = 0u64;
    loop {
        check(cancel)?;
        if started.elapsed() > Duration::from_secs(600) {
            return Err("klayout.download_timed_out".into());
        }
        let chunk = cancellable(response.chunk(), cancel)
            .await?
            .map_err(|_| "klayout.download_failed")?;
        let Some(chunk) = chunk else {
            break;
        };
        size += chunk.len() as u64;
        if size > pin.size_bytes {
            return Err("klayout.integrity_failed".into());
        }
        hash.update(&chunk);
        file.write_all(&chunk)
            .map_err(|_| "klayout.storage_unavailable")?;
    }
    file.sync_all().map_err(|_| "klayout.storage_unavailable")?;
    check(cancel)?;
    if size != pin.size_bytes || format!("{:x}", hash.finalize()) != pin.sha256 {
        return Err("klayout.integrity_failed".into());
    }
    Ok(())
}
fn zip_path(name: &str, root: &str) -> Result<Option<PathBuf>, String> {
    if name == format!("{root}/") {
        return Ok(None);
    }
    let relative = name
        .strip_prefix(&format!("{root}/"))
        .ok_or("klayout.archive_invalid")?;
    if relative.is_empty()
        || relative.contains(['\\', ':', '\0'])
        || relative
            .split('/')
            .any(|part| part == ".." || part == "." || part.ends_with(['.', ' ']))
    {
        return Err("klayout.archive_invalid".into());
    }
    let path = PathBuf::from(relative.trim_end_matches('/'));
    if path
        .components()
        .any(|component| !matches!(component, Component::Normal(_)))
    {
        return Err("klayout.archive_invalid".into());
    }
    Ok(Some(path))
}
pub(super) fn zip_payload(
    archive: &Path,
    payload: &Path,
    pin: &Package,
    extract: bool,
    cancel: &AtomicBool,
) -> Result<(), String> {
    verify_archive(archive, pin, cancel)?;
    let mut zip = zip::ZipArchive::new(File::open(archive).map_err(|_| "klayout.read_failed")?)
        .map_err(|_| "klayout.archive_invalid")?;
    if zip.len() > MAX_FILES {
        return Err("klayout.archive_invalid".into());
    }
    let root = pin
        .archive_root
        .as_deref()
        .ok_or("klayout.archive_invalid")?;
    let mut expected = std::collections::BTreeSet::new();
    let mut expanded = 0u64;
    for index in 0..zip.len() {
        check(cancel)?;
        let mut entry = zip.by_index(index).map_err(|_| "klayout.archive_invalid")?;
        let Some(relative) = zip_path(entry.name(), root)? else {
            continue;
        };
        let kind = entry.unix_mode().unwrap_or(0) & 0o170000;
        if kind != 0 && kind != 0o040000 && kind != 0o100000 || entry.size() > MAX_FILE {
            return Err("klayout.archive_invalid".into());
        }
        if !expected.insert(relative.clone()) {
            return Err("klayout.archive_invalid".into());
        }
        let destination = payload.join(&relative);
        if entry.is_dir() {
            if extract {
                fs::create_dir_all(&destination).map_err(|_| "klayout.storage_unavailable")?;
            }
            if !regular(&destination)?.is_dir() {
                return Err("klayout.integrity_failed".into());
            }
            continue;
        }
        expanded = expanded
            .checked_add(entry.size())
            .ok_or("klayout.archive_invalid")?;
        if expanded > MAX_EXPANDED {
            return Err("klayout.archive_invalid".into());
        }
        let mut hash = Sha256::new();
        let mut length = 0u64;
        let mut buffer = [0; 64 * 1024];
        let mut output = if extract {
            let parent = destination.parent().ok_or("klayout.archive_invalid")?;
            fs::create_dir_all(parent).map_err(|_| "klayout.storage_unavailable")?;
            Some(
                OpenOptions::new()
                    .write(true)
                    .create_new(true)
                    .open(&destination)
                    .map_err(|_| "klayout.storage_unavailable")?,
            )
        } else {
            None
        };
        loop {
            check(cancel)?;
            let read = entry
                .read(&mut buffer)
                .map_err(|_| "klayout.archive_invalid")?;
            if read == 0 {
                break;
            }
            length += read as u64;
            if length > entry.size() {
                return Err("klayout.archive_invalid".into());
            }
            hash.update(&buffer[..read]);
            if let Some(file) = output.as_mut() {
                file.write_all(&buffer[..read])
                    .map_err(|_| "klayout.storage_unavailable")?;
            }
        }
        if length != entry.size() {
            return Err("klayout.archive_invalid".into());
        }
        drop(output);
        if !extract {
            let metadata = regular(&destination)?;
            if !metadata.is_file() || metadata.len() != length {
                return Err("klayout.integrity_failed".into());
            }
            let actual = digest_reader(
                File::open(&destination).map_err(|_| "klayout.read_failed")?,
                cancel,
            )?;
            if actual.0 != length || actual.1 != format!("{:x}", hash.finalize()) {
                return Err("klayout.integrity_failed".into());
            }
        }
    }
    // Reject added DLLs, plugins and files as well as changed upstream bytes.
    fn inventory(
        root: &Path,
        directory: &Path,
        names: &mut std::collections::BTreeSet<PathBuf>,
    ) -> Result<(), String> {
        for item in fs::read_dir(directory).map_err(|_| "klayout.integrity_failed")? {
            let path = item.map_err(|_| "klayout.integrity_failed")?.path();
            let metadata = regular(&path)?;
            names.insert(
                path.strip_prefix(root)
                    .map_err(|_| "klayout.integrity_failed")?
                    .to_owned(),
            );
            if names.len() > MAX_FILES {
                return Err("klayout.integrity_failed".into());
            }
            if metadata.is_dir() {
                inventory(root, &path, names)?;
            } else if !metadata.is_file() {
                return Err("klayout.integrity_failed".into());
            }
        }
        Ok(())
    }
    let mut actual = std::collections::BTreeSet::new();
    inventory(payload, payload, &mut actual)?;
    if actual != expected || !regular(&payload.join(&pin.executable))?.is_file() {
        return Err("klayout.integrity_failed".into());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn archive_paths_fail_closed_on_windows_aliases_and_escapes() {
        for name in [
            "root/../escape",
            "root/./file",
            "root/C:/file",
            "root/a\\b",
            "root/evil. ",
            "root/file.",
        ] {
            assert!(zip_path(name, "root").is_err(), "{name}");
        }
        assert_eq!(
            zip_path("root/lib/file.dll", "root").unwrap(),
            Some(PathBuf::from("lib/file.dll"))
        );
    }
    #[test]
    fn optional_viewer_pin_is_distinct_from_engine_qualification() {
        let pin = package("windows-x86_64").unwrap();
        assert_eq!(pin.size_bytes, 370182806);
        assert_eq!(pin.sha256.len(), 64);
        let value: serde_json::Value = serde_json::from_str(DESCRIPTOR).unwrap();
        assert_eq!(value["qualification"], "optional-external-viewer-only");
        assert!(package("renderer-url").is_err());
    }
    fn fixture(name: &str, contents: &[u8]) -> (PathBuf, Package) {
        let directory = std::env::temp_dir().join(format!(
            "dds-klayout-package-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        fs::create_dir(&directory).unwrap();
        let cursor = std::io::Cursor::new(Vec::new());
        let mut writer = zip::ZipWriter::new(cursor);
        let options = zip::write::SimpleFileOptions::default();
        writer.add_directory("fixture/", options).unwrap();
        writer.start_file(name, options).unwrap();
        writer.write_all(contents).unwrap();
        let bytes = writer.finish().unwrap().into_inner();
        fs::write(directory.join("archive.zip"), &bytes).unwrap();
        fs::create_dir(directory.join("payload")).unwrap();
        let pin = Package {
            url: "https://example.invalid/fixture.zip".into(),
            sha256: format!("{:x}", Sha256::digest(&bytes)),
            size_bytes: bytes.len() as u64,
            archive_root: Some("fixture".into()),
            executable: "viewer.exe".into(),
        };
        (directory, pin)
    }
    #[test]
    fn staged_package_rejects_tampered_added_and_missing_installed_files() {
        let (directory, pin) = fixture("fixture/viewer.exe", b"fixture binary");
        let cancel = AtomicBool::new(false);
        zip_payload(
            &directory.join("archive.zip"),
            &directory.join("payload"),
            &pin,
            true,
            &cancel,
        )
        .unwrap();
        zip_payload(
            &directory.join("archive.zip"),
            &directory.join("payload"),
            &pin,
            false,
            &cancel,
        )
        .unwrap();
        fs::write(directory.join("payload/viewer.exe"), b"tamper! binary").unwrap();
        assert!(zip_payload(
            &directory.join("archive.zip"),
            &directory.join("payload"),
            &pin,
            false,
            &cancel
        )
        .is_err());
        fs::write(directory.join("payload/viewer.exe"), b"fixture binary").unwrap();
        fs::write(directory.join("payload/extra.dll"), b"extra").unwrap();
        assert!(zip_payload(
            &directory.join("archive.zip"),
            &directory.join("payload"),
            &pin,
            false,
            &cancel
        )
        .is_err());
        fs::remove_file(directory.join("payload/extra.dll")).unwrap();
        fs::remove_file(directory.join("payload/viewer.exe")).unwrap();
        assert!(zip_payload(
            &directory.join("archive.zip"),
            &directory.join("payload"),
            &pin,
            false,
            &cancel
        )
        .is_err());
        fs::remove_dir_all(directory).unwrap();
    }
    #[test]
    fn cancellation_and_escaped_archives_never_extract_a_payload() {
        let (directory, pin) = fixture("fixture/../viewer.exe", b"fixture");
        assert!(zip_payload(
            &directory.join("archive.zip"),
            &directory.join("payload"),
            &pin,
            true,
            &AtomicBool::new(false)
        )
        .is_err());
        assert!(!directory.join("viewer.exe").exists());
        assert_eq!(
            zip_payload(
                &directory.join("archive.zip"),
                &directory.join("payload"),
                &pin,
                true,
                &AtomicBool::new(true)
            )
            .unwrap_err(),
            "klayout.cancelled"
        );
        fs::remove_dir_all(directory).unwrap();
    }
    #[test]
    fn cancellation_drops_a_stalled_network_future_without_waiting_for_timeout() {
        let cancel = std::sync::Arc::new(AtomicBool::new(false));
        let other = cancel.clone();
        let worker = std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(80));
            other.store(true, Ordering::Release);
        });
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let started = Instant::now();
        let result = runtime.block_on(cancellable(std::future::pending::<()>(), &cancel));
        assert_eq!(result.unwrap_err(), "klayout.cancelled");
        assert!(started.elapsed() < Duration::from_secs(2));
        worker.join().unwrap();
    }
}
