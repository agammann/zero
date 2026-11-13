//! Test-only driver for disposable Windows runners; never included in Zero.exe.
use super::*;

#[test]
#[ignore = "requires scripts/verify-recovery-accounts.ps1 on a disposable GitHub-hosted runner"]
fn recovery_cross_account_driver() {
    assert_eq!(env::var("GITHUB_ACTIONS").as_deref(), Ok("true"));
    assert_eq!(env::var("RUNNER_ENVIRONMENT").as_deref(), Ok("github-hosted"));
    let root = fs::canonicalize(env::var_os("ZERO_ACCOUNT_FIXTURE").unwrap()).unwrap();
    let runner_temp = fs::canonicalize(env::var_os("RUNNER_TEMP").unwrap()).unwrap();
    assert!(root.starts_with(runner_temp));
    assert_eq!(root.file_name().unwrap(), "fixture");
    assert!(
        root.parent()
            .unwrap()
            .file_name()
            .unwrap()
            .to_str()
            .unwrap()
            .starts_with("zero-recovery-accounts-")
    );
    let sid = scheduler::current_sid().unwrap();
    assert_eq!(sid, env::var("ZERO_ACCOUNT_EXPECTED_SID").unwrap());
    let mode = env::var("ZERO_ACCOUNT_MODE").unwrap();
    let state = root.join("state");
    let source = root.join("selected.bin");
    let stage = root.join("encrypted-stage.tmp");
    match mode.as_str() {
        "create" => {
            assert_eq!(fs::read_dir(&root).unwrap().count(), 0);
            fs::write(&source, b"original synthetic plaintext").unwrap();
            fs::write(&stage, b"synthetic encrypted stage").unwrap();
            let mut source_file = open_for_destroy(&source).unwrap();
            let stage_file = open_for_destroy(&stage).unwrap();
            let journal =
                PendingJournal::create(&source, &source_file, &stage, &stage_file, &state).unwrap();
            source_file.write_all(b"interrupted fixture").unwrap();
            source_file.sync_all().unwrap();
            drop(source_file);
            drop(stage_file);
            assert!(journal.path.exists());
        }
        "seed-own-key" => {
            let body = b"independent account credential probe";
            let signature = recovery::sign(body).unwrap();
            recovery::verify(body, &signature).unwrap();
        }
        "reject-missing" | "reject-foreign" => {
            let records: Vec<_> = fs::read_dir(&state)
                .unwrap()
                .map(|entry| entry.unwrap().path())
                .collect();
            assert_eq!(records.len(), 1);
            let paths = [&source, &stage, &records[0]];
            let snapshots: Vec<_> = paths
                .iter()
                .map(|path| {
                    // Prove the second account has the access recovery would need.
                    let handle = open_for_destroy(path).unwrap();
                    let identity = file_identity(&handle).unwrap();
                    drop(handle);
                    (fs::read(path).unwrap(), identity)
                })
                .collect();
            let probe = state.join("account-write-probe");
            OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&probe)
                .unwrap()
                .write_all(b"temporary access probe")
                .unwrap();
            fs::remove_file(probe).unwrap();
            let error = recover_pending_jobs(&state).unwrap_err().to_string();
            let expected = if mode == "reject-missing" {
                "recovery credential is unavailable; automatic recovery refused"
            } else {
                "recovery record authentication failed"
            };
            assert_eq!(error, expected);
            for (path, (bytes, identity)) in paths.iter().zip(snapshots) {
                assert_eq!(fs::read(path).unwrap(), bytes);
                assert_eq!(file_identity(&File::open(path).unwrap()).unwrap(), identity);
            }
            println!("Verified read/write/delete access and refusal: {error}");
        }
        "recover" => {
            assert!(source.exists());
            assert!(stage.exists());
            assert_eq!(fs::read_dir(&state).unwrap().count(), 1);
            recover_pending_jobs(&state).unwrap();
            assert!(!source.exists());
            assert!(!stage.exists());
            assert_eq!(fs::read_dir(&state).unwrap().count(), 0);
        }
        _ => panic!("unknown recovery account test mode"),
    }
    println!(
        "ZERO_ACCOUNT_EVIDENCE={}",
        serde_json::json!({"mode": mode, "sid": sid, "pid": std::process::id()})
    );
}
