//! Called only after the hosted-runner, fixture-path and native SID guards.
use super::*;

const MISSING_RECEIPT: &str = "receipt/result signing credential is unavailable; initialize it explicitly after reviewing legacy keys";
const LEGACY_RECEIPT: &str = "legacy receipt/result signing state requires operator-reviewed migration or explicit rotation; no key was imported or replaced";

fn product(state: &Path, selected: &Path, output: &Path, error: Option<&str>) {
    let executable = fs::canonicalize(env::var_os("ZERO_ACCOUNT_PRODUCT").unwrap()).unwrap();
    let fixture = fs::canonicalize(env::var_os("ZERO_ACCOUNT_FIXTURE").unwrap()).unwrap();
    assert_eq!(executable.parent(), fixture.parent());
    assert_eq!(executable.file_name().unwrap(), "fixture-product.exe");
    let status = std::process::Command::new(executable)
        .arg("--quiet")
        .arg("--state-dir")
        .arg(state)
        .arg("--receipts")
        .arg(output)
        .arg(selected)
        .status()
        .unwrap();
    if let Some(expected) = error {
        assert_eq!(status.code(), Some(1));
        assert_eq!(
            fs::read_to_string(state.join("last-error.txt")).unwrap(),
            expected
        );
        assert!(!output.exists());
    } else {
        assert!(status.success());
        assert!(!selected.exists());
        assert!(!state.join("last-error.txt").exists());
    }
}

fn protected_files(root: &Path) -> Vec<(PathBuf, Vec<u8>, FileIdentity)> {
    let mut records = Vec::new();
    for entry in fs::read_dir(root).unwrap() {
        let path = entry.unwrap().path();
        assert!(
            !fs::symlink_metadata(&path)
                .unwrap()
                .file_type()
                .is_symlink()
        );
        if path.is_dir() {
            records.extend(protected_files(&path));
        } else if path.file_name().unwrap() != "last-error.txt" {
            // Rule out an ACL denial as the reason another account cannot proceed.
            let handle = open_for_destroy(&path).unwrap();
            let identity = file_identity(&handle).unwrap();
            drop(handle);
            records.push((path.clone(), fs::read(path).unwrap(), identity));
        }
    }
    records.sort_by(|left, right| left.0.cmp(&right.0));
    records
}

fn only_receipt(output: &Path) -> PathBuf {
    let paths: Vec<_> = fs::read_dir(output)
        .unwrap()
        .map(|entry| entry.unwrap().path())
        .collect();
    assert_eq!(paths.len(), 1);
    paths.into_iter().next().unwrap()
}

pub(crate) fn run(root: &Path, mode: &str) {
    let authority = root.join("authority");
    let owner = authority.join("owner");
    let other = authority.join("other");
    let active = if mode == "state-other-key" {
        &other
    } else {
        &owner
    };
    let state = active.join("state");
    let selected = active.join("selected.bin");
    let sentinel = active.join("sentinel.bin");
    let output = active.join("receipts");
    let mut args = [
        std::ffi::OsString::from("--state-dir"),
        state.clone().into_os_string(),
    ]
    .into_iter()
    .peekable();
    state::initialize(&mut args).unwrap();
    assert!(args.next().is_none());
    match mode {
        "state-create" | "state-other-key" => {
            assert!(!active.exists());
            fs::create_dir_all(&state).unwrap();
            fs::write(&selected, b"synthetic selected receipt payload").unwrap();
            fs::write(&sentinel, b"synthetic unselected sentinel").unwrap();
            receipts::initialize_signing_key(&state).unwrap();
            profiles::create(
                "benign",
                std::slice::from_ref(&selected),
                None,
                &FileFilters::default(),
            )
            .unwrap();
            remote::account_fixture::create(&state, &selected);
            assert_eq!(
                profiles::load("benign").unwrap().paths.as_slice(),
                std::slice::from_ref(&selected)
            );
            remote::account_fixture::assert_load(&state, &selected, None);
            if mode == "state-other-key" {
                let owner_public =
                    fs::read_to_string(owner.join("state/receipt-public-key.hex")).unwrap();
                let own_public = fs::read_to_string(state.join("receipt-public-key.hex")).unwrap();
                assert_ne!(own_public, owner_public);
                remote::account_fixture::write_result(&state, &active.join("result.json"));
                remote::verify_result(
                    &active.join("result.json"),
                    &state.join("receipt-public-key.hex"),
                )
                .unwrap();
                product(&state, &selected, &output, None);
                let receipt = only_receipt(&output);
                assert_eq!(
                    receipts::verify_receipt(&receipt, &own_public)
                        .unwrap()
                        .original_bytes,
                    34
                );
                assert_eq!(
                    receipts::verify_receipt(&receipt, &owner_public)
                        .unwrap_err()
                        .to_string(),
                    "receipt format or trusted public key does not match"
                );
                assert_eq!(
                    remote::verify_result(
                        &active.join("result.json"),
                        &owner.join("state/receipt-public-key.hex")
                    )
                    .err()
                    .unwrap()
                    .to_string(),
                    "remote result is not signed by the trusted device key"
                );
            }
        }
        "state-reject-missing" | "state-reject-foreign" => {
            let before = protected_files(&owner);
            assert_eq!(before.len(), 6);
            let probe = state.join("write-probe");
            fs::write(&probe, b"synthetic permission probe").unwrap();
            fs::remove_file(probe).unwrap();
            let expected = if mode == "state-reject-missing" {
                "state authentication credential is unavailable; processing refused"
            } else {
                "state record authentication failed"
            };
            assert_eq!(
                profiles::load("benign").err().unwrap().to_string(),
                expected
            );
            remote::account_fixture::assert_load(&state, &selected, Some(expected));
            assert_eq!(
                receipts::signing_key(&state).err().unwrap().to_string(),
                MISSING_RECEIPT
            );
            product(&state, &selected, &output, Some(MISSING_RECEIPT));
            assert_eq!(
                receipts::initialize_signing_key(&state)
                    .unwrap_err()
                    .to_string(),
                LEGACY_RECEIPT
            );
            assert_eq!(
                receipts::signing_key(&state).err().unwrap().to_string(),
                MISSING_RECEIPT
            );
            assert_eq!(protected_files(&owner), before);
            println!("Verified profile, enrollment and snapshot refusal: {expected}");
            println!(
                "Verified actual receipt-backed CLI refusal and explicit initialization refusal; all six protected files unchanged."
            );
        }
        "state-owner" => {
            assert_eq!(
                profiles::load("benign").unwrap().paths.as_slice(),
                std::slice::from_ref(&selected)
            );
            remote::account_fixture::assert_load(&state, &selected, None);
            let trusted = fs::read_to_string(state.join("receipt-public-key.hex")).unwrap();
            assert_eq!(
                receipts::hex(
                    &receipts::signing_key(&state)
                        .unwrap()
                        .verifying_key()
                        .to_bytes()
                ),
                trusted
            );
            remote::account_fixture::write_result(&state, &active.join("result.json"));
            remote::verify_result(
                &active.join("result.json"),
                &state.join("receipt-public-key.hex"),
            )
            .unwrap();
            product(&state, &selected, &output, None);
            assert_eq!(
                receipts::verify_receipt(&only_receipt(&output), &trusted)
                    .unwrap()
                    .original_bytes,
                34
            );
            assert_eq!(
                fs::read_to_string(state.join("receipt-public-key.hex")).unwrap(),
                trusted
            );
            let other_public =
                fs::read_to_string(other.join("state/receipt-public-key.hex")).unwrap();
            let other_receipt = only_receipt(&other.join("receipts"));
            receipts::verify_receipt(&other_receipt, &other_public).unwrap();
            assert_eq!(
                receipts::verify_receipt(&other_receipt, &trusted)
                    .unwrap_err()
                    .to_string(),
                "receipt format or trusted public key does not match"
            );
            println!(
                "Verified separate-process owner state loading, original receipt credential reuse, actual selected-file processing and trusted receipt/result verification."
            );
        }
        _ => panic!("unknown state authority fixture mode"),
    }
    assert_eq!(
        fs::read(sentinel).unwrap(),
        b"synthetic unselected sentinel"
    );
}
