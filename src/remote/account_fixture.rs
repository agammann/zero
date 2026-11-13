//! Synthetic signed state for the hosted, two-account test driver only.
use super::*;

pub(crate) fn create(state: &Path, selected: &Path) {
    let config = DeviceConfig {
        version: 1,
        device_id: "synthetic".to_owned(),
        queue: state.join("queue").as_os_str().encode_wide().collect(),
        controller_public_key: "11".repeat(32),
        allowed_profiles: vec!["benign".to_owned()],
    };
    write_new(&config_path(state), &sign_config(state, config).unwrap()).unwrap();
    let snapshot = Snapshot {
        version: 2,
        command: CommandBody {
            version: 1,
            device_id: "synthetic".to_owned(),
            profile: "benign".to_owned(),
            nonce: "aa".repeat(16),
            issued_unix_seconds: 1,
        },
        files: vec![SnapshotFile {
            path: selected.as_os_str().encode_wide().collect(),
            identity: crate::file_identity(&fs::File::open(selected).unwrap()).unwrap(),
        }],
        receipt_directory: None,
        filters: FileFilters::default(),
    };
    write_new(
        &state.join("working.json"),
        &sign_snapshot(state, snapshot).unwrap(),
    )
    .unwrap();
}

pub(crate) fn assert_load(state: &Path, selected: &Path, error: Option<&str>) {
    let config = load_config(state);
    let snapshot = load_snapshot(state, &state.join("working.json"));
    if let Some(expected) = error {
        assert_eq!(config.err().unwrap().to_string(), expected);
        assert_eq!(snapshot.err().unwrap().to_string(), expected);
    } else {
        let config = config.unwrap();
        assert_eq!(config.device_id, "synthetic");
        assert_eq!(config.allowed_profiles, ["benign"]);
        assert_eq!(config.controller_public_key, "11".repeat(32));
        let snapshot = snapshot.unwrap();
        assert_eq!(snapshot.files.len(), 1);
        assert_eq!(
            PathBuf::from(OsString::from_wide(&snapshot.files[0].path)),
            selected
        );
        assert_eq!(
            snapshot.files[0].identity,
            crate::file_identity(&fs::File::open(selected).unwrap()).unwrap()
        );
    }
}

pub(crate) fn write_result(state: &Path, output: &Path) {
    let snapshot = load_snapshot(state, &state.join("working.json")).unwrap();
    // A zero-completion synthetic result tests key authority, not file processing.
    let result = result_for(&snapshot, 0, 0, 0, StorageSummary::default()).unwrap();
    write_new(output, &result).unwrap();
}
