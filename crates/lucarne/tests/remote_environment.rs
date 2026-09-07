use lucarne::agent_runtime::{
    AgentStatus, RemoteEnvironmentConfig, RemoteEnvironmentError, RemoteEnvironmentRegistry,
    RemoteFileSafety, RemoteTransport, SessionOrigin,
};
use lucarne::control_plane::StatusSnapshot;
use serde_json::{from_str, to_string};
use smol_str::SmolStr;

#[test]
fn remote_environment_config_serde_and_origin_label() {
    let mut config = RemoteEnvironmentConfig::new("gpu-cluster-1", "cluster.ai.corp:8443")
        .with_transport(RemoteTransport::Gateway)
        .with_cwd("/home/agent/workspace")
        .with_auth_token("secret-token-123");
    config.env.insert("CUDA_VISIBLE_DEVICES".into(), "0,1".into());

    assert_eq!(config.name.as_str(), "gpu-cluster-1");
    assert_eq!(config.endpoint.as_str(), "cluster.ai.corp:8443");
    assert_eq!(config.transport, RemoteTransport::Gateway);
    assert_eq!(config.remote_cwd.as_deref(), Some("/home/agent/workspace"));
    assert_eq!(config.origin_label().as_str(), "remote:gpu-cluster-1");
    assert_eq!(config.env.get("CUDA_VISIBLE_DEVICES").unwrap(), "0,1");
    assert!(config.enabled);

    let json = to_string(&config).expect("serialization failed");
    let deserialized: RemoteEnvironmentConfig = from_str(&json).expect("deserialization failed");
    assert_eq!(deserialized, config);
}

#[test]
fn remote_environment_registry_management() {
    let mut registry = RemoteEnvironmentRegistry::new();
    let env_ssh = RemoteEnvironmentConfig::new("dev-box", "ssh.corp.internal:22")
        .with_transport(RemoteTransport::Ssh);
    let env_bridge = RemoteEnvironmentConfig::new("worker-node", "127.0.0.1:9099")
        .with_transport(RemoteTransport::Bridge);

    registry.register(env_ssh);
    registry.register(env_bridge);

    assert_eq!(registry.list().len(), 2);
    assert!(registry.get("dev-box").is_some());
    assert!(registry.get("worker-node").is_some());
    assert!(registry.get("non-existent").is_none());

    // Without default, resolving None yields "local"
    assert_eq!(
        registry.resolve_origin_label(None).unwrap().as_str(),
        "local"
    );

    // Resolving named environment
    assert_eq!(
        registry.resolve_origin_label(Some("dev-box")).unwrap().as_str(),
        "remote:dev-box"
    );

    // Set default
    assert!(registry.set_default("worker-node").is_ok());
    assert_eq!(
        registry.resolve_origin_label(None).unwrap().as_str(),
        "remote:worker-node"
    );

    // Setting invalid default returns error
    assert!(matches!(
        registry.set_default("missing-env"),
        Err(RemoteEnvironmentError::EnvironmentNotFound(_))
    ));
}

#[test]
fn remote_file_safety_traversal_prevention() {
    // Valid relative paths
    assert!(RemoteFileSafety::validate_relative_path("src/main.rs").is_ok());
    assert!(RemoteFileSafety::validate_relative_path("data/models/weights.bin").is_ok());
    assert_eq!(
        RemoteFileSafety::validate_relative_path("sub\\dir\\file.txt").unwrap(),
        "sub/dir/file.txt"
    );

    // Traversal attempts
    assert!(matches!(
        RemoteFileSafety::validate_relative_path("../secret.key"),
        Err(RemoteEnvironmentError::SafeFileTransferRejected { .. })
    ));
    assert!(matches!(
        RemoteFileSafety::validate_relative_path("foo/../../bar"),
        Err(RemoteEnvironmentError::SafeFileTransferRejected { .. })
    ));

    // Absolute paths
    assert!(matches!(
        RemoteFileSafety::validate_relative_path("/etc/shadow"),
        Err(RemoteEnvironmentError::SafeFileTransferRejected { .. })
    ));
    assert!(matches!(
        RemoteFileSafety::validate_relative_path("C:\\Windows\\System32"),
        Err(RemoteEnvironmentError::SafeFileTransferRejected { .. })
    ));
}

#[test]
fn remote_file_safety_size_limits() {
    assert!(RemoteFileSafety::validate_file_size(500, 1000).is_ok());
    assert!(RemoteFileSafety::validate_file_size(1000, 1000).is_ok());
    assert!(matches!(
        RemoteFileSafety::validate_file_size(1001, 1000),
        Err(RemoteEnvironmentError::SafeFileTransferRejected { .. })
    ));
}

#[test]
fn session_origin_labels_and_serde() {
    let local = SessionOrigin::Local;
    let remote = SessionOrigin::Remote(SmolStr::new("gpu-server"));

    assert_eq!(local.as_str(), "local");
    assert_eq!(local.to_display_label().as_str(), "local");

    assert_eq!(remote.as_str(), "gpu-server");
    assert_eq!(remote.to_display_label().as_str(), "remote:gpu-server");

    let json = to_string(&remote).unwrap();
    let deserialized: SessionOrigin = from_str(&json).unwrap();
    assert_eq!(deserialized, remote);
}

#[test]
fn agent_status_and_snapshot_origin_propagation() {
    let status = AgentStatus {
        version: Some("0.1.0".into()),
        origin: Some("remote:gpu-server".into()),
        model: Some("gemini-2.5-pro".into()),
        ..Default::default()
    };

    let json = to_string(&status).unwrap();
    assert!(json.contains("\"origin\":\"remote:gpu-server\""));
    let deserialized: AgentStatus = from_str(&json).unwrap();
    assert_eq!(deserialized.origin.as_deref(), Some("remote:gpu-server"));

    let snapshot = StatusSnapshot {
        provider_id: Some("codex".into()),
        origin: Some("remote:gpu-server".into()),
        ..Default::default()
    };

    let snap_json = to_string(&snapshot).unwrap();
    assert!(snap_json.contains("\"origin\":\"remote:gpu-server\""));
    let deserialized_snap: StatusSnapshot = from_str(&snap_json).unwrap();
    assert_eq!(deserialized_snap.origin.as_deref(), Some("remote:gpu-server"));
}
