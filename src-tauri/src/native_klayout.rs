//! Explicit optional KLayout viewer capability. This never supplies engine tool inventories.
use crate::native_console::{Environment, WorkspaceLease};
use desktop_runtime_security::sanitize_child_environment;
use serde::{Deserialize, Serialize};
use std::fs;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::{atomic::AtomicBool, Arc, Mutex, OnceLock};
use std::time::{Duration, Instant};
use tauri::{Manager, WebviewWindow};
use tauri_plugin_dialog::DialogExt;

#[path = "native_klayout_package.rs"]
mod package;
const SCRIPT: &str = include_str!("native_klayout_linux.py");
const SCHEMA: &str = "altifigence.klayout-extension.v1";

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct Status {
    schema: String,
    version: String,
    target: String,
    installation_scope: String,
    distribution: Option<String>,
    supported: bool,
    installed: bool,
    ready: bool,
    code: String,
    dependencies: Vec<String>,
}
impl Status {
    fn empty(target: &str, scope: &str, supported: bool) -> Self {
        Self {
            schema: SCHEMA.into(),
            version: package::VERSION.into(),
            target: target.into(),
            installation_scope: scope.into(),
            distribution: None,
            supported,
            installed: false,
            ready: false,
            code: if supported { "missing" } else { "unsupported" }.into(),
            dependencies: vec![],
        }
    }
    fn validate(&self) -> Result<(), String> {
        if self.schema != SCHEMA
            || self.version != package::VERSION
            || self.dependencies.len() > 32
            || self.dependencies.iter().any(|value| {
                value.len() > 64
                    || !value
                        .bytes()
                        .next()
                        .is_some_and(|b| b.is_ascii_alphanumeric())
                    || !value
                        .bytes()
                        .all(|b| b.is_ascii_alphanumeric() || b".+-".contains(&b))
            })
            || !matches!(
                self.code.as_str(),
                "missing"
                    | "ready"
                    | "unsupported"
                    | "dependencies-missing"
                    | "display-missing"
                    | "integrity-failed"
                    | "version-failed"
            )
            || self.ready && (!self.supported || !self.installed || self.code != "ready")
        {
            return Err("klayout.response_invalid".into());
        }
        Ok(())
    }
}
#[derive(Clone)]
enum Target {
    Windows(PathBuf),
    #[cfg(windows)]
    Wsl(String),
    #[cfg(target_os = "linux")]
    Linux,
    Unsupported,
}
impl Target {
    fn key(&self) -> String {
        match self {
            Self::Windows(root) => format!("windows:{}", root.display()),
            #[cfg(windows)]
            Self::Wsl(distribution) => format!("wsl:{distribution}"),
            #[cfg(target_os = "linux")]
            Self::Linux => "linux-user".into(),
            Self::Unsupported => "unsupported".into(),
        }
    }
}
fn target(app: &tauri::AppHandle, state: &WorkspaceLease) -> Result<Target, String> {
    if state.environment() != Environment::OnPremises {
        return Ok(Target::Unsupported);
    }
    #[cfg(windows)]
    {
        if let Some(workspace) = state.wsl() {
            return Ok(Target::Wsl(
                workspace.connection.project().distribution.clone(),
            ));
        }
        if cfg!(target_arch = "x86_64") {
            return Ok(Target::Windows(
                app.path()
                    .app_local_data_dir()
                    .map_err(|_| "klayout.storage_unavailable")?
                    .join("extensions/org.klayout.viewer"),
            ));
        }
    }
    #[cfg(target_os = "linux")]
    {
        let _ = app;
        if cfg!(target_arch = "x86_64") {
            return Ok(Target::Linux);
        }
    }
    let _ = app;
    Ok(Target::Unsupported)
}
fn authorize(window: &WebviewWindow) -> Result<(), String> {
    if window.label() != "main" {
        Err("klayout.window_unsupported".into())
    } else {
        Ok(())
    }
}

/// Bounded pipes for fixed native commands; no renderer executable, environment or shell text.
fn process(mut command: Command, input: Vec<u8>, timeout: Duration) -> Result<Vec<u8>, String> {
    sanitize_child_environment(&mut command);
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        command.creation_flags(0x0800_0000);
    }
    let mut child = command
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|_| "klayout.process_unavailable")?;
    let (sender, receiver) = std::sync::mpsc::channel();
    let output = child.stdout.take().ok_or("klayout.process_unavailable")?;
    let error = child.stderr.take().ok_or("klayout.process_unavailable")?;
    for (is_output, pipe) in [
        (true, Box::new(output) as Box<dyn Read + Send>),
        (false, Box::new(error) as Box<dyn Read + Send>),
    ] {
        let sender = sender.clone();
        std::thread::spawn(move || {
            let mut bytes = vec![];
            let result = pipe.take(16 * 1024 + 1).read_to_end(&mut bytes);
            let _ = sender.send((
                is_output,
                if result.is_ok() && bytes.len() <= 16 * 1024 {
                    Some(bytes)
                } else {
                    None
                },
            ));
        });
    }
    let mut stdin = child.stdin.take().ok_or("klayout.process_unavailable")?;
    std::thread::spawn(move || {
        let _ = stdin.write_all(&input);
    });
    let deadline = Instant::now() + timeout;
    let mut output = None;
    let mut error = None;
    let result = loop {
        if Instant::now() > deadline {
            break Err("klayout.process_timed_out".into());
        }
        if let Ok((is_output, value)) = receiver.recv_timeout(Duration::from_millis(20)) {
            let Some(bytes) = value else {
                break Err("klayout.output_limit".into());
            };
            if is_output {
                output = Some(bytes);
            } else {
                error = Some(bytes);
            }
        }
        if let Some(exit) = child.try_wait().map_err(|_| "klayout.process_failed")? {
            if let (Some(output), Some(error)) = (&output, &error) {
                if exit.success() {
                    break Ok(output.clone());
                }
                let code = serde_json::from_slice::<serde_json::Value>(error)
                    .ok()
                    .and_then(|value| value["message"].as_str().map(str::to_owned))
                    .filter(|value| {
                        value.starts_with("klayout.")
                            && value.len() < 80
                            && value
                                .bytes()
                                .all(|b| b.is_ascii_alphanumeric() || b"._-".contains(&b))
                    });
                break Err(code.unwrap_or_else(|| "klayout.process_failed".into()));
            }
        }
    };
    if result.is_err() {
        let _ = child.kill();
    }
    let _ = child.wait();
    result
}
fn linux_call(
    target: &Target,
    action: &str,
    id: &str,
    file: &str,
    input: Vec<u8>,
) -> Result<Status, String> {
    let mut command = match target {
        #[cfg(windows)]
        Target::Wsl(distribution) => {
            desktop_wsl_backend::transport::WslProject::new(distribution.clone(), "/home".into())?;
            let mut command = desktop_wsl_backend::transport::system_wsl_command()?;
            command.args([
                "--distribution",
                distribution,
                "--cd",
                "/",
                "--exec",
                "/usr/bin/timeout",
                "--kill-after=5",
                "120",
                "/usr/bin/python3",
            ]);
            command
        }
        #[cfg(target_os = "linux")]
        Target::Linux => Command::new("/usr/bin/python3"),
        _ => return Err("klayout.unsupported".into()),
    };
    command.args(["-I", "-c", SCRIPT, action, id, file, package::DESCRIPTOR]);
    let bytes = process(command, input, Duration::from_secs(135))?;
    let mut status: Status =
        serde_json::from_slice(&bytes).map_err(|_| "klayout.response_invalid")?;
    status.validate()?;
    if status.target != "ubuntu24-x86_64"
        || status.installation_scope != "linux-user"
        || status.distribution.is_some()
    {
        return Err("klayout.response_invalid".into());
    }
    #[cfg(windows)]
    if let Target::Wsl(distribution) = target {
        status.installation_scope = "wsl".into();
        status.distribution = Some(distribution.clone());
    }
    Ok(status)
}
fn windows_probe(directory: &Path, pin: &package::Package) -> bool {
    let payload = directory.join("payload");
    let mut command = Command::new(payload.join(&pin.executable));
    command
        .args(["-b", "-v"])
        .current_dir(&payload)
        .env("PATH", &payload)
        .env("KLAYOUT_PATH", "")
        .env(
            "KLAYOUT_HOME",
            directory
                .parent()
                .unwrap_or(directory)
                .join("configuration"),
        )
        .env("KLAYOUT_PYTHONPATH", "")
        .env("KLAYOUT_PYTHONHOME", &payload);
    process(command, vec![], Duration::from_secs(15)).is_ok_and(|bytes| {
        bytes.len() < 256
            && String::from_utf8_lossy(&bytes).trim() == format!("KLayout {}", package::VERSION)
    })
}
type Fingerprint = Vec<(PathBuf, u64, std::time::SystemTime)>;
static WINDOWS_CACHE: OnceLock<Mutex<Option<(PathBuf, Status, Fingerprint)>>> = OnceLock::new();
static WINDOWS_VERIFICATION: Mutex<()> = Mutex::new(());
fn fingerprint(root: &Path) -> Result<Fingerprint, String> {
    fn walk(path: &Path, names: &mut Fingerprint) -> Result<(), String> {
        let metadata = package::regular(path)?;
        names.push((
            path.to_owned(),
            metadata.len(),
            metadata
                .modified()
                .map_err(|_| "klayout.integrity_failed")?,
        ));
        if names.len() > 40_010 {
            return Err("klayout.integrity_failed".into());
        }
        if metadata.is_dir() {
            for entry in fs::read_dir(path).map_err(|_| "klayout.integrity_failed")? {
                walk(
                    &entry.map_err(|_| "klayout.integrity_failed")?.path(),
                    names,
                )?;
            }
        } else if !metadata.is_file() {
            return Err("klayout.integrity_failed".into());
        }
        Ok(())
    }
    let mut names = vec![];
    walk(root, &mut names)?;
    names.sort_by(|a, b| a.0.cmp(&b.0));
    Ok(names)
}
fn windows_status(root: &Path, force_verification: bool) -> Result<Status, String> {
    let _verification = WINDOWS_VERIFICATION
        .lock()
        .map_err(|_| "klayout.operation_failed")?;
    let mut status = Status::empty("windows-x86_64", "device", true);
    let directory = root.join(package::VERSION);
    if !directory.exists() {
        return Ok(status);
    }
    let observed = fingerprint(&directory);
    if !force_verification {
        if let (Ok(observed), Ok(cache)) = (
            &observed,
            WINDOWS_CACHE.get_or_init(|| Mutex::new(None)).lock(),
        ) {
            if let Some((cached_root, cached_status, cached_files)) = &*cache {
                if cached_root == root && cached_files == observed {
                    return Ok(cached_status.clone());
                }
            }
        }
    }
    let cancel = AtomicBool::new(false);
    let pin = package::package("windows-x86_64")?;
    let verified = (|| {
        package::regular(&directory)?;
        let mut names = fs::read_dir(&directory)
            .map_err(|_| "klayout.integrity_failed")?
            .map(|entry| entry.map(|entry| entry.file_name().to_string_lossy().into_owned()))
            .collect::<Result<Vec<_>, _>>()
            .map_err(|_| "klayout.integrity_failed")?;
        names.sort();
        if names != ["archive.zip", "payload"] {
            return Err("klayout.integrity_failed".into());
        }
        package::zip_payload(
            &directory.join("archive.zip"),
            &directory.join("payload"),
            &pin,
            false,
            &cancel,
        )
    })();
    if verified.is_err() {
        status.code = "integrity-failed".into();
        return Ok(status);
    }
    status.installed = true;
    status.ready = windows_probe(&directory, &pin);
    status.code = if status.ready {
        "ready"
    } else {
        "version-failed"
    }
    .into();
    if status.ready {
        if let (Ok(observed), Ok(mut cache)) = (
            observed,
            WINDOWS_CACHE.get_or_init(|| Mutex::new(None)).lock(),
        ) {
            *cache = Some((root.to_owned(), status.clone(), observed));
        }
    }
    Ok(status)
}
fn read(target: &Target) -> Result<Status, String> {
    match target {
        Target::Windows(root) => windows_status(root, false),
        Target::Unsupported => Ok(Status::empty("unsupported", "device", false)),
        #[cfg(windows)]
        Target::Wsl(_) => linux_call(target, "inspect", "", "", vec![]),
        #[cfg(target_os = "linux")]
        Target::Linux => linux_call(target, "inspect", "", "", vec![]),
    }
}
fn remove_owned(directory: &Path) -> Result<(), String> {
    fn inspect(path: &Path) -> Result<(), String> {
        let metadata = package::regular(path)?;
        if metadata.is_dir() {
            for child in fs::read_dir(path).map_err(|_| "klayout.remove_failed")? {
                inspect(&child.map_err(|_| "klayout.remove_failed")?.path())?;
            }
        } else if !metadata.is_file() {
            return Err("klayout.remove_failed".into());
        }
        Ok(())
    }
    inspect(directory)?;
    fs::remove_dir_all(directory).map_err(|_| "klayout.remove_failed".into())
}
fn change(
    target: &Target,
    id: &str,
    installed: bool,
    cancel: &AtomicBool,
) -> Result<Status, String> {
    package::check(cancel)?;
    match target {
        Target::Windows(root) => {
            package::safe_directory(root)?;
            let directory = root.join(package::VERSION);
            if !installed {
                if directory.exists() {
                    remove_owned(&directory)?;
                }
                return windows_status(root, false);
            }
            if directory.exists() {
                return Err("klayout.already_installed".into());
            }
            let stage = root.join(format!("staging-{id}"));
            fs::create_dir(&stage).map_err(|_| "klayout.storage_unavailable")?;
            let result = (|| {
                let pin = package::package("windows-x86_64")?;
                package::download(&pin, &stage.join("archive.zip"), cancel)?;
                fs::create_dir(stage.join("payload")).map_err(|_| "klayout.storage_unavailable")?;
                package::zip_payload(
                    &stage.join("archive.zip"),
                    &stage.join("payload"),
                    &pin,
                    true,
                    cancel,
                )?;
                package::check(cancel)?;
                fs::rename(&stage, &directory).map_err(|_| "klayout.publish_failed")?;
                windows_status(root, true)
            })();
            if stage.exists() {
                remove_owned(&stage)?;
            }
            result
        }
        Target::Unsupported => Err("klayout.unsupported".into()),
        #[cfg(any(windows, target_os = "linux"))]
        _ => {
            if !installed {
                return linux_call(target, "uninstall", id, "", vec![]);
            }
            let pin = package::package("ubuntu24-x86_64")?;
            let temporary = std::env::temp_dir().join(format!("dds-klayout-{id}.deb"));
            let result = (|| {
                package::download(&pin, &temporary, cancel)?;
                package::check(cancel)?;
                let input = fs::read(&temporary).map_err(|_| "klayout.read_failed")?;
                let stage = linux_call(target, "stage", id, "", input)?;
                if !stage.installed {
                    return Err("klayout.integrity_failed".into());
                }
                package::check(cancel)?;
                linux_call(target, "commit", id, "", vec![])
            })();
            let cleanup = if result.is_err() {
                linux_call(target, "discard", id, "", vec![]).map(|_| ())
            } else {
                Ok(())
            };
            if temporary.exists() {
                fs::remove_file(&temporary).map_err(|_| "klayout.cleanup_failed")?;
            }
            cleanup?;
            result
        }
    }
}

#[derive(Clone, PartialEq)]
struct Owner {
    window: String,
    session: String,
    target: String,
}
struct Reservation {
    id: String,
    owner: Owner,
    installed: bool,
    executing: bool,
    expires: Instant,
    cancel: Arc<AtomicBool>,
}
static OPERATION: OnceLock<Mutex<Option<Reservation>>> = OnceLock::new();
fn operation() -> &'static Mutex<Option<Reservation>> {
    OPERATION.get_or_init(|| Mutex::new(None))
}
struct Release(String);
impl Drop for Release {
    fn drop(&mut self) {
        if let Ok(mut slot) = operation().lock() {
            if slot.as_ref().is_some_and(|value| value.id == self.0) {
                *slot = None;
            }
        }
    }
}
fn owner(
    window: &WebviewWindow,
    request: &tauri::ipc::Request<'_>,
    target: &Target,
) -> Result<Owner, String> {
    authorize(window)?;
    Ok(Owner {
        window: window.label().into(),
        session: crate::native_console::request_session(request)?.into(),
        target: target.key(),
    })
}
#[tauri::command]
pub(crate) async fn read_klayout_extension(
    app: tauri::AppHandle,
    window: WebviewWindow,
    state: WorkspaceLease,
) -> Result<Status, String> {
    authorize(&window)?;
    let target = target(&app, &state)?;
    tauri::async_runtime::spawn_blocking(move || {
        let _lease = state;
        read(&target)
    })
    .await
    .map_err(|_| "klayout.operation_failed".to_owned())?
}
#[tauri::command]
pub(crate) async fn prepare_klayout_extension(
    app: tauri::AppHandle,
    window: WebviewWindow,
    state: WorkspaceLease,
    request: tauri::ipc::Request<'_>,
    installed: bool,
) -> Result<String, String> {
    let target = target(&app, &state)?;
    let owner = owner(&window, &request, &target)?;
    let status = tauri::async_runtime::spawn_blocking(move || {
        let _lease = state;
        read(&target)
    })
    .await
    .map_err(|_| "klayout.operation_failed")??;
    if !status.supported {
        return Err("klayout.unsupported".into());
    }
    let mut slot = operation().lock().map_err(|_| "klayout.operation_failed")?;
    if slot
        .as_ref()
        .is_some_and(|value| value.executing || value.expires > Instant::now())
    {
        return Err("klayout.busy".into());
    }
    let id = uuid::Uuid::new_v4().to_string();
    *slot = Some(Reservation {
        id: id.clone(),
        owner,
        installed,
        executing: false,
        expires: Instant::now() + Duration::from_secs(600),
        cancel: Arc::new(AtomicBool::new(false)),
    });
    Ok(id)
}
#[tauri::command]
pub(crate) async fn change_klayout_extension(
    app: tauri::AppHandle,
    window: WebviewWindow,
    state: WorkspaceLease,
    request: tauri::ipc::Request<'_>,
    id: String,
) -> Result<Status, String> {
    let target = target(&app, &state)?;
    let owner = owner(&window, &request, &target)?;
    let (installed, cancel) = {
        let mut slot = operation().lock().map_err(|_| "klayout.operation_failed")?;
        let value = slot.as_mut().ok_or("klayout.request_missing")?;
        if value.id != id
            || value.owner != owner
            || value.executing
            || value.expires <= Instant::now()
        {
            return Err("klayout.request_invalid".into());
        }
        value.executing = true;
        (value.installed, value.cancel.clone())
    };
    tauri::async_runtime::spawn_blocking(move || {
        let _lease = state;
        let _release = Release(id.clone());
        change(&target, &id, installed, &cancel)
    })
    .await
    .map_err(|_| "klayout.operation_failed".to_owned())?
}
#[tauri::command]
pub(crate) fn cancel_klayout_extension(
    window: WebviewWindow,
    request: tauri::ipc::Request<'_>,
    id: String,
) -> Result<(), String> {
    authorize(&window)?;
    let session = crate::native_console::request_session(&request)?;
    let mut slot = operation().lock().map_err(|_| "klayout.operation_failed")?;
    if let Some(value) = slot.as_mut() {
        if value.id != id || value.owner.window != window.label() || value.owner.session != session
        {
            return Err("klayout.request_invalid".into());
        }
        value
            .cancel
            .store(true, std::sync::atomic::Ordering::Release);
        if !value.executing {
            *slot = None;
        }
    }
    Ok(())
}
#[tauri::command]
pub(crate) async fn open_klayout_extension(
    app: tauri::AppHandle,
    window: WebviewWindow,
    state: WorkspaceLease,
) -> Result<bool, String> {
    authorize(&window)?;
    let target = target(&app, &state)?;
    let Some(file) = window
        .dialog()
        .file()
        .set_title("Open a saved layout in KLayout")
        .add_filter("GDSII / OASIS", &["gds", "gdsii", "oas", "oasis"])
        .blocking_pick_file()
    else {
        return Ok(false);
    };
    let file = file.into_path().map_err(|_| "klayout.layout_invalid")?;
    if !file.is_absolute()
        || !file
            .extension()
            .and_then(|name| name.to_str())
            .is_some_and(|name| {
                matches!(
                    name.to_ascii_lowercase().as_str(),
                    "gds" | "gdsii" | "oas" | "oasis"
                )
            })
    {
        return Err("klayout.layout_invalid".into());
    }
    tauri::async_runtime::spawn_blocking(move || {
        let _lease = state;
        // Status caching only improves presentation; an actual launch always rechecks bytes.
        let status = match &target {
            Target::Windows(root) => windows_status(root, true)?,
            _ => read(&target)?,
        };
        if !status.ready {
            return Err(format!("klayout.{}", status.code.replace('-', "_")));
        }
        match &target {
            Target::Windows(root) => {
                if !package::regular(&file)?.is_file() {
                    return Err("klayout.layout_invalid".into());
                }
                let payload = root.join(package::VERSION).join("payload");
                let pin = package::package("windows-x86_64")?;
                let mut command = Command::new(payload.join(pin.executable));
                command
                    .args(["-nc", "-rx", "-ne"])
                    .arg(file)
                    .current_dir(&payload)
                    .env("PATH", &payload)
                    .env("KLAYOUT_PATH", "")
                    .env("KLAYOUT_HOME", root.join("configuration"))
                    .env("KLAYOUT_PYTHONPATH", "")
                    .env("KLAYOUT_PYTHONHOME", &payload)
                    .stdin(Stdio::null())
                    .stdout(Stdio::null())
                    .stderr(Stdio::null());
                sanitize_child_environment(&mut command);
                #[cfg(windows)]
                {
                    use std::os::windows::process::CommandExt;
                    command.creation_flags(0x0800_0000);
                }
                command.spawn().map_err(|_| "klayout.open_failed")?;
            }
            #[cfg(windows)]
            Target::Wsl(distribution) => {
                let file = desktop_wsl_backend::transport::WslProject::from_unc(
                    file.to_str().ok_or("klayout.layout_invalid")?,
                )?
                .ok_or("klayout.layout_invalid")?;
                if &file.distribution != distribution {
                    return Err("klayout.distribution_mismatch".into());
                }
                linux_call(
                    &target,
                    "open",
                    &uuid::Uuid::new_v4().to_string(),
                    &file.directory,
                    vec![],
                )?;
            }
            #[cfg(target_os = "linux")]
            Target::Linux => {
                linux_call(
                    &target,
                    "open",
                    &uuid::Uuid::new_v4().to_string(),
                    file.to_str().ok_or("klayout.layout_invalid")?,
                    vec![],
                )?;
            }
            Target::Unsupported => return Err("klayout.unsupported".into()),
        }
        Ok(true)
    })
    .await
    .map_err(|_| "klayout.operation_failed".to_owned())?
}
