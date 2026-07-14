//! Request and response types for the VM Manager REST API.

use std::collections::HashMap;

use serde::{Deserialize, Serialize};

/// `POST /v1/environments` request body.
#[derive(Debug, Deserialize)]
pub struct CreateEnvironmentRequest {
    pub session_id: String,
    pub image: String,
    #[serde(default = "default_vcpus")]
    pub vcpus: u32,
    #[serde(default = "default_memory_mib")]
    pub memory_mib: u32,
    #[serde(default)]
    #[allow(dead_code)]
    pub files: Vec<FileEntry>,
    pub egress: EgressConfig,
    #[serde(default = "default_timeout_secs")]
    pub timeout_secs: u32,
}

fn default_vcpus() -> u32 {
    1
}
fn default_memory_mib() -> u32 {
    512
}
fn default_timeout_secs() -> u32 {
    3600
}

#[derive(Debug, Deserialize)]
#[allow(dead_code)]
pub struct FileEntry {
    pub guest_path: String,
    pub source: String, // "inline", "git", "path"
    #[serde(default)]
    pub content: Option<String>,
    #[serde(default)]
    #[serde(rename = "url")]
    pub url: Option<String>,
    #[serde(default)]
    #[serde(rename = "ref")]
    pub git_ref: Option<String>,
    #[serde(default)]
    pub path: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct EgressConfig {
    pub allowlist: Vec<EgressAllowlistEntry>,
}

#[derive(Debug, Deserialize)]
pub struct EgressAllowlistEntry {
    pub domain: String,
    #[serde(default)]
    pub inject_key: bool,
    #[serde(default)]
    pub credential_ref: Option<String>,
}

/// `POST /v1/environments` 201 response.
#[derive(Debug, Serialize)]
pub struct EnvironmentResponse {
    pub session_id: String,
    pub status: String,
    pub vm_ip: String,
    pub tap_interface: String,
    pub proxy_session: ProxySessionInfo,
    #[serde(skip_serializing_if = "HashMap::is_empty")]
    pub dummy_keys: HashMap<String, String>,
    pub serial_output_url: String,
    pub started_at: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct ProxySessionInfo {
    pub id: String,
    pub proxy_url: String,
}

/// `GET /v1/environments/{session_id}` 200 response.
#[derive(Debug, Serialize)]
pub struct EnvironmentStatusResponse {
    pub session_id: String,
    pub status: String,
    pub vm_ip: String,
    pub tap_interface: String,
    pub proxy_session_id: String,
    pub started_at: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<String>,
    pub uptime_secs: u64,
}

/// `GET /v1/environments` 200 response.
#[derive(Debug, Serialize)]
pub struct EnvironmentListResponse {
    pub environments: Vec<EnvironmentSummary>,
}

#[derive(Debug, Serialize)]
pub struct EnvironmentSummary {
    pub session_id: String,
    pub status: String,
    pub vm_ip: String,
    pub started_at: String,
    pub uptime_secs: u64,
}

/// `DELETE /v1/environments/{session_id}` 202 response.
#[derive(Debug, Serialize)]
pub struct DeleteResponse {
    pub session_id: String,
    pub status: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_create_environment_request_deserialize() {
        let json = r#"{
            "session_id": "sess_8f7a3b2c",
            "image": "alpine-3.20-pi",
            "vcpus": 1,
            "memory_mib": 512,
            "files": [],
            "egress": {
                "allowlist": [
                    {
                        "domain": "api.openai.com",
                        "inject_key": true,
                        "credential_ref": "vault://secret/data/agent-env/openai-key"
                    }
                ]
            },
            "timeout_secs": 3600
        }"#;
        let req: CreateEnvironmentRequest = serde_json::from_str(json).unwrap();
        assert_eq!(req.session_id, "sess_8f7a3b2c");
        assert_eq!(req.image, "alpine-3.20-pi");
        assert_eq!(req.vcpus, 1);
        assert_eq!(req.memory_mib, 512);
        assert_eq!(req.timeout_secs, 3600);
        assert_eq!(req.egress.allowlist.len(), 1);
        assert!(req.egress.allowlist[0].inject_key);
    }

    #[tokio::test]
    async fn test_create_environment_request_defaults() {
        let json = r#"{
            "session_id": "sess_8f7a3b2c",
            "image": "alpine-3.20-pi",
            "egress": {
                "allowlist": []
            }
        }"#;
        let req: CreateEnvironmentRequest = serde_json::from_str(json).unwrap();
        assert_eq!(req.vcpus, 1);
        assert_eq!(req.memory_mib, 512);
        assert_eq!(req.timeout_secs, 3600);
    }

    #[tokio::test]
    async fn test_environment_response_serialize() {
        let resp = EnvironmentResponse {
            session_id: "sess_8f7a3b2c".to_string(),
            status: "running".to_string(),
            vm_ip: "10.0.1.2".to_string(),
            tap_interface: "tap-sess_8f7a".to_string(),
            proxy_session: ProxySessionInfo {
                id: "sess_8f7a3b2c".to_string(),
                proxy_url: "http://10.0.1.1:9999".to_string(),
            },
            dummy_keys: HashMap::new(),
            serial_output_url: "/v1/environments/sess_8f7a3b2c/serial".to_string(),
            started_at: "2026-07-07T22:37:06Z".to_string(),
            expires_at: Some("2026-07-07T23:37:06Z".to_string()),
        };
        let json = serde_json::to_string(&resp).unwrap();
        assert!(json.contains("\"session_id\""));
        assert!(json.contains("\"running\""));
        assert!(json.contains("\"10.0.1.2\""));
    }
}
