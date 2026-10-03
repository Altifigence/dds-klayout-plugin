//! A read-only audit CLI using the actual DDS package verifier.
use std::path::Path;
use std::sync::atomic::AtomicBool;

fn main() {
    let arguments: Vec<String> = std::env::args().skip(1).collect();
    let cancel = AtomicBool::new(false);
    let result = match arguments.as_slice() {
        [command] if command == "descriptor" => {
            println!("{}", dds_klayout_plugin::descriptor());
            Ok(())
        }
        [command, target, archive] if command == "verify-archive" => {
            dds_klayout_plugin::verify_archive(target, Path::new(archive), &cancel)
        }
        [command, archive, payload] if command == "verify-windows-payload" => {
            dds_klayout_plugin::verify_windows_payload(
                Path::new(archive),
                Path::new(payload),
                &cancel,
            )
        }
        _ => {
            eprintln!("Usage: dds-klayout-plugin descriptor | verify-archive <windows-x86_64|ubuntu24-x86_64> <archive> | verify-windows-payload <archive.zip> <payload-directory>");
            std::process::exit(2);
        }
    };
    if let Err(error) = result {
        eprintln!("{error}");
        std::process::exit(1);
    }
}
