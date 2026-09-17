//! Remote Agent Environment Configuration & Orchestration
//!
//! Implements support for managing agents running outside the local machine
//! while keeping channel UX (Telegram/WeChat) consistent.
//!
//! Resolves Issue #13: Support remote agent environments.

use serde::{Deserialize, Serialize};
use smol_str::SmolStr;
use std::collections::HashMap;

/// Supported transport mechanisms to connect to a remote agent runtime.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum RemoteTransport {
    /// Secure SSH execution channel
    Ssh,
    /// Secure WebSocket / HTTP agent gateway
    #[default]
    Gateway,
    /// Unix domain or TCP bridge
    Bridge,
}

/// Configuration for a remote execution environment.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RemoteEnvironmentConfig {
    /// Unique identifier for this remote environment (e.g. "cloud-gpu", "staging-cluster").
    pub name: SmolStr,
    /// Network address or endpoint (e.g. "agent.internal.net:9000", "192.168.1.50").
    pub endpoint: SmolStr,
    /// Transport protocol.
    #[serde(default)]
    pub transport: RemoteTransport,
    /// Remote base working directory.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub remote_cwd: Option<SmolStr>,
    /// Environment variables specific to the remote host.
    #[serde(default)]
    pub env: HashMap<String, String>,
    /// Authorization token or credential reference (kept safe, not serialized or logged in plain text).
    #[serde(skip)]
    pub auth_token: Option<SmolStr>,
    /// Connection and execution timeout in seconds.
    #[serde(default = "default_timeout_secs")]
    pub timeout_secs: u64,
    /// Whether this remote environment is enabled.
    #[serde(default = "default_true")]
    pub enabled: bool,
}

impl std::fmt::Debug for RemoteEnvironmentConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RemoteEnvironmentConfig")
            .field("name", &self.name)
            .field("endpoint", &self.endpoint)
            .field("transport", &self.transport)
            .field("remote_cwd", &self.remote_cwd)
            .field("env", &self.env)
            .field(
                "auth_token",
                &self.auth_token.as_ref().map(|_| "<redacted>"),
            )
            .field("timeout_secs", &self.timeout_secs)
            .field("enabled", &self.enabled)
            .finish()
    }
}

fn default_timeout_secs() -> u64 {
    30
}

fn default_true() -> bool {
    true
}

impl RemoteEnvironmentConfig {
    pub fn new(name: impl Into<SmolStr>, endpoint: impl Into<SmolStr>) -> Self {
        Self {
            name: name.into(),
            endpoint: endpoint.into(),
            transport: RemoteTransport::default(),
            remote_cwd: None,
            env: HashMap::new(),
            auth_token: None,
            timeout_secs: default_timeout_secs(),
            enabled: true,
        }
    }

    pub fn with_transport(mut self, transport: RemoteTransport) -> Self {
        self.transport = transport;
        self
    }

    pub fn with_cwd(mut self, cwd: impl Into<SmolStr>) -> Self {
        self.remote_cwd = Some(cwd.into());
        self
    }

    pub fn with_auth_token(mut self, token: impl Into<SmolStr>) -> Self {
        self.auth_token = Some(token.into());
        self
    }

    /// Origin label formatted for status and history projection.
    pub fn origin_label(&self) -> SmolStr {
        SessionOrigin::Remote(self.name.clone()).origin_label()
    }
}

/// Structured origin label indicating where a session or process originated.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum SessionOrigin {
    /// Running locally on the daemon host.
    #[default]
    Local,
    /// Running in a configured remote environment.
    Remote(SmolStr),
}

impl SessionOrigin {
    pub fn origin_label(&self) -> SmolStr {
        match self {
            Self::Local => "local".into(),
            Self::Remote(name) => format!("remote:{name}").into(),
        }
    }
}

impl std::fmt::Display for SessionOrigin {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.origin_label())
    }
}

/// Registry and selector for configured remote environments.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct RemoteEnvironmentRegistry {
    pub environments: HashMap<SmolStr, RemoteEnvironmentConfig>,
    pub default_environment: Option<SmolStr>,
}

impl RemoteEnvironmentRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn register(&mut self, env: RemoteEnvironmentConfig) {
        self.environments.insert(env.name.clone(), env);
    }

    pub fn get(&self, name: &str) -> Option<&RemoteEnvironmentConfig> {
        self.environments.get(name)
    }

    pub fn list(&self) -> Vec<&RemoteEnvironmentConfig> {
        let mut list: Vec<&RemoteEnvironmentConfig> = self.environments.values().collect();
        list.sort_by(|a, b| a.name.cmp(&b.name));
        list
    }

    pub fn set_default(&mut self, name: impl Into<SmolStr>) -> Result<(), RemoteEnvironmentError> {
        let name = name.into();
        if !self.environments.contains_key(&name) {
            return Err(RemoteEnvironmentError::EnvironmentNotFound(name));
        }
        self.default_environment = Some(name);
        Ok(())
    }

    /// Resolve an origin label given an optional target environment name.
    pub fn resolve_origin_label(&self, target_env: Option<&str>) -> Result<SmolStr, RemoteEnvironmentError> {
        match target_env {
            Some(name) => {
                let env = self.get(name).ok_or_else(|| {
                    RemoteEnvironmentError::EnvironmentNotFound(name.into())
                })?;
                Ok(env.origin_label())
            }
            None => match &self.default_environment {
                Some(def) => {
                    let env = self.get(def.as_str()).ok_or_else(|| {
                        RemoteEnvironmentError::EnvironmentNotFound(def.clone())
                    })?;
                    Ok(env.origin_label())
                }
                None => Ok(SessionOrigin::Local.origin_label()),
            },
        }
    }
}

/// Safe file handling and path sanitization for remote environments.
pub struct RemoteFileSafety;

impl RemoteFileSafety {
    /// Validate that a remote file path is safe and does not attempt directory traversal (`..`).
    ///
    /// Checks are host-independent so absolute drive prefixes (e.g. `C:\`), UNC paths,
    /// leading root slashes (`/`), and home directory paths (`~`) are rejected uniformly
    /// across Windows, Linux, and macOS.
    pub fn validate_relative_path(path: &str) -> Result<String, RemoteEnvironmentError> {
        let trimmed = path.trim();
        if trimmed.is_empty() {
            return Err(RemoteEnvironmentError::SafeFileTransferRejected {
                file: path.into(),
                reason: "Path cannot be empty".into(),
            });
        }

        // Check for Windows drive letter prefix (e.g. "C:" or "c:")
        let bytes = trimmed.as_bytes();
        if bytes.len() >= 2 && bytes[0].is_ascii_alphabetic() && bytes[1] == b':' {
            return Err(RemoteEnvironmentError::SafeFileTransferRejected {
                file: path.into(),
                reason: "Absolute paths with drive prefix are not permitted".into(),
            });
        }

        // Check for leading root slash, backslash (UNC), or home directory tilde
        if trimmed.starts_with('/') || trimmed.starts_with('\\') || trimmed.starts_with('~') {
            return Err(RemoteEnvironmentError::SafeFileTransferRejected {
                file: path.into(),
                reason: "Absolute paths or home directory paths outside remote workspace root are not permitted".into(),
            });
        }

        // Normalize all backslashes to forward slashes
        let normalized = trimmed.replace('\\', "/");

        // Inspect each path component for directory traversal
        for comp in normalized.split('/') {
            if comp == ".." {
                return Err(RemoteEnvironmentError::SafeFileTransferRejected {
                    file: path.into(),
                    reason: "Path contains directory traversal component ('..')".into(),
                });
            }
        }

        Ok(normalized)
    }

    /// Validate file size limit for remote file transfer.
    pub fn validate_file_size(size_bytes: u64, max_bytes: u64) -> Result<(), RemoteEnvironmentError> {
        if size_bytes > max_bytes {
            return Err(RemoteEnvironmentError::SafeFileTransferRejected {
                file: format!("{size_bytes} bytes").into(),
                reason: format!("File exceeds maximum allowed transfer size of {max_bytes} bytes").into(),
            });
        }
        Ok(())
    }
}

/// Observable and safe failure modes for remote environment operations.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, thiserror::Error)]
pub enum RemoteEnvironmentError {
    #[error("remote environment not found: '{0}'")]
    EnvironmentNotFound(SmolStr),

    #[error("authentication failed for remote environment '{env}': {reason}")]
    AuthenticationFailed { env: SmolStr, reason: SmolStr },

    #[error("remote environment '{env}' at '{endpoint}' is unreachable: {error}")]
    Unreachable {
        env: SmolStr,
        endpoint: SmolStr,
        error: SmolStr,
    },

    #[error("remote execution in '{env}' timed out after {timeout_secs}s")]
    ExecutionTimeout { env: SmolStr, timeout_secs: u64 },

    #[error("remote file operation rejected for '{file}': {reason}")]
    SafeFileTransferRejected { file: SmolStr, reason: SmolStr },
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_remote_environment_config_defaults() {
        let config = RemoteEnvironmentConfig::new("staging-gpu", "10.0.0.12:8080")
            .with_transport(RemoteTransport::Gateway)
            .with_cwd("/workspace/agent")
            .with_auth_token("secret-token");

        assert_eq!(config.name.as_str(), "staging-gpu");
        assert_eq!(config.endpoint.as_str(), "10.0.0.12:8080");
        assert_eq!(config.transport, RemoteTransport::Gateway);
        assert_eq!(config.remote_cwd.as_deref(), Some("/workspace/agent"));
        assert_eq!(config.origin_label().as_str(), "remote:staging-gpu");
        assert!(config.enabled);

        let debug_str = format!("{config:?}");
        assert!(debug_str.contains("<redacted>"));
        assert!(!debug_str.contains("secret-token"));
    }

    #[test]
    fn test_registry_registration_and_defaults() {
        let mut registry = RemoteEnvironmentRegistry::new();
        let env1 = RemoteEnvironmentConfig::new("dev-vm", "dev.corp.net:22")
            .with_transport(RemoteTransport::Ssh);
        let env2 = RemoteEnvironmentConfig::new("prod-cluster", "prod.corp.net:9000")
            .with_transport(RemoteTransport::Gateway);

        registry.register(env1);
        registry.register(env2);

        assert_eq!(registry.list().len(), 2);
        assert!(registry.get("dev-vm").is_some());
        assert!(registry.get("unknown").is_none());

        assert_eq!(
            registry.resolve_origin_label(Some("dev-vm")).unwrap().as_str(),
            "remote:dev-vm"
        );
        assert_eq!(
            registry.resolve_origin_label(None).unwrap().as_str(),
            "local"
        );

        registry.set_default("prod-cluster").unwrap();
        assert_eq!(
            registry.resolve_origin_label(None).unwrap().as_str(),
            "remote:prod-cluster"
        );
    }

    #[test]
    fn test_remote_file_safety_host_independent() {
        assert!(RemoteFileSafety::validate_relative_path("safe/path/file.py").is_ok());
        assert_eq!(
            RemoteFileSafety::validate_relative_path("sub\\dir\\file.txt").unwrap(),
            "sub/dir/file.txt"
        );
        assert!(RemoteFileSafety::validate_relative_path("../secret/config.json").is_err());
        assert!(RemoteFileSafety::validate_relative_path("safe/../../escape.txt").is_err());
        assert!(RemoteFileSafety::validate_relative_path("/etc/passwd").is_err());
        assert!(RemoteFileSafety::validate_relative_path("C:\\Windows\\System32").is_err());
        assert!(RemoteFileSafety::validate_relative_path("C:/Windows/System32").is_err());
        assert!(RemoteFileSafety::validate_relative_path("~/.ssh/id_rsa").is_err());
        assert!(RemoteFileSafety::validate_relative_path("\\\\server\\share\\data").is_err());
    }

    #[test]
    fn test_remote_file_safety_size_limit() {
        assert!(RemoteFileSafety::validate_file_size(1024, 2048).is_ok());
        assert!(RemoteFileSafety::validate_file_size(5000, 2048).is_err());
    }

    #[test]
    fn test_session_origin_display() {
        assert_eq!(SessionOrigin::Local.origin_label().as_str(), "local");
        assert_eq!(SessionOrigin::Local.to_string(), "local");
        assert_eq!(
            SessionOrigin::Remote("cloud".into()).origin_label().as_str(),
            "remote:cloud"
        );
        assert_eq!(
            SessionOrigin::Remote("cloud".into()).to_string(),
            "remote:cloud"
        );
    }
}
