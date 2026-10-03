//! Standalone entry points into the unmodified DDS package implementation.
//! This harness does not emulate DDS workspace, session, window or WSL authority.
use std::path::Path;
use std::sync::atomic::AtomicBool;

#[path = "../src-tauri/src/native_klayout_package.rs"]
mod package;

/// Exact upstream viewer version pinned by the exported DDS implementation.
pub fn viewer_version() -> &'static str {
    package::VERSION
}

/// The exact descriptor used by the native DDS adapter.
pub fn descriptor() -> &'static str {
    package::DESCRIPTOR
}

/// Verify the official archive's pinned size and SHA-256 without executing it.
pub fn verify_archive(target: &str, archive: &Path, cancel: &AtomicBool) -> Result<(), String> {
    package::verify_archive(archive, &package::package(target)?, cancel)
}

/// Download one descriptor-pinned upstream archive into a new caller-selected file.
/// The implementation accepts no custom URL and follows no redirect.
pub fn download_archive(target: &str, archive: &Path, cancel: &AtomicBool) -> Result<(), String> {
    package::download(&package::package(target)?, archive, cancel)
}

/// Audit a Windows payload against the original pinned archive, including extra files.
pub fn verify_windows_payload(
    archive: &Path,
    payload: &Path,
    cancel: &AtomicBool,
) -> Result<(), String> {
    package::zip_payload(
        archive,
        payload,
        &package::package("windows-x86_64")?,
        false,
        cancel,
    )
}

/// Extract the pinned Windows ZIP into an empty, absolute caller-selected directory.
/// This does not install or launch KLayout and does not manage DDS installation state.
pub fn extract_windows_payload(
    archive: &Path,
    payload: &Path,
    cancel: &AtomicBool,
) -> Result<(), String> {
    package::check(cancel)?;
    package::safe_directory(payload)?;
    if payload
        .read_dir()
        .map_err(|_| "klayout.storage_unavailable")?
        .next()
        .is_some()
    {
        return Err("klayout.destination_not_empty".into());
    }
    package::zip_payload(
        archive,
        payload,
        &package::package("windows-x86_64")?,
        true,
        cancel,
    )
}
