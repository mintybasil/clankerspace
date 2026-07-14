//! Error types and helpers for the VM Manager REST API.

use bytes::Bytes;
use http_body_util::Full;
use hyper::StatusCode;
use serde::Serialize;

/// Error codes used in the standard error envelope.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ErrorCode {
    InvalidRequest,
    ImageNotFound,
    SessionExists,
    CredentialRefInvalid,
    VmLaunchFailed,
    ProxyUnavailable,
    InternalError,
}

impl ErrorCode {
    #[allow(dead_code)]
    pub fn status(&self) -> StatusCode {
        match self {
            Self::InvalidRequest => StatusCode::BAD_REQUEST,
            Self::ImageNotFound => StatusCode::NOT_FOUND,
            Self::SessionExists => StatusCode::CONFLICT,
            Self::CredentialRefInvalid => StatusCode::UNPROCESSABLE_ENTITY,
            Self::VmLaunchFailed => StatusCode::INTERNAL_SERVER_ERROR,
            Self::ProxyUnavailable => StatusCode::BAD_GATEWAY,
            Self::InternalError => StatusCode::INTERNAL_SERVER_ERROR,
        }
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            Self::InvalidRequest => "INVALID_REQUEST",
            Self::ImageNotFound => "IMAGE_NOT_FOUND",
            Self::SessionExists => "SESSION_EXISTS",
            Self::CredentialRefInvalid => "CREDENTIAL_REF_INVALID",
            Self::VmLaunchFailed => "VM_LAUNCH_FAILED",
            Self::ProxyUnavailable => "PROXY_UNAVAILABLE",
            Self::InternalError => "INTERNAL_ERROR",
        }
    }
}

/// Inner error detail for the standard error envelope.
#[derive(Debug, Serialize)]
struct ErrorDetail {
    code: String,
    message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    detail: Option<String>,
}

/// Standard error envelope: `{"error":{"code":"...","message":"...","detail":"..."}}`
#[derive(Debug, Serialize)]
pub struct ErrorResponse {
    error: ErrorDetail,
}

impl ErrorResponse {
    fn new(code: ErrorCode, message: impl Into<String>) -> Self {
        Self {
            error: ErrorDetail {
                code: code.as_str().to_string(),
                message: message.into(),
                detail: None,
            },
        }
    }

    fn with_detail(code: ErrorCode, message: impl Into<String>, detail: impl Into<String>) -> Self {
        Self {
            error: ErrorDetail {
                code: code.as_str().to_string(),
                message: message.into(),
                detail: Some(detail.into()),
            },
        }
    }
}

pub fn json_error(
    status: StatusCode,
    code: ErrorCode,
    message: impl Into<String>,
) -> hyper::Response<Full<Bytes>> {
    let body = serde_json::to_vec(&ErrorResponse::new(code, message)).unwrap_or_default();
    hyper::Response::builder()
        .status(status)
        .header("content-type", "application/json")
        .body(Full::new(Bytes::from(body)))
        .unwrap()
}

pub fn json_error_with_detail(
    status: StatusCode,
    code: ErrorCode,
    message: impl Into<String>,
    detail: impl Into<String>,
) -> hyper::Response<Full<Bytes>> {
    let body =
        serde_json::to_vec(&ErrorResponse::with_detail(code, message, detail)).unwrap_or_default();
    hyper::Response::builder()
        .status(status)
        .header("content-type", "application/json")
        .body(Full::new(Bytes::from(body)))
        .unwrap()
}

pub fn json_ok(status: StatusCode, body: &impl Serialize) -> hyper::Response<Full<Bytes>> {
    let json = serde_json::to_vec(body).unwrap_or_else(|_| b"{}".to_vec());
    hyper::Response::builder()
        .status(status)
        .header("content-type", "application/json")
        .body(Full::new(Bytes::from(json)))
        .unwrap()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_error_response_serialization() {
        let resp = ErrorResponse::new(ErrorCode::InvalidRequest, "bad request");
        let json = serde_json::to_string(&resp).unwrap();
        assert!(json.contains("\"INVALID_REQUEST\""));
        assert!(json.contains("\"bad request\""));
        assert!(!json.contains("\"detail\""));
    }

    #[test]
    fn test_error_response_with_detail() {
        let resp = ErrorResponse::with_detail(
            ErrorCode::VmLaunchFailed,
            "Firecracker failed",
            "exit code 1",
        );
        let json = serde_json::to_string(&resp).unwrap();
        assert!(json.contains("\"VM_LAUNCH_FAILED\""));
        assert!(json.contains("\"Firecracker failed\""));
        assert!(json.contains("\"exit code 1\""));
        assert!(json.contains("\"detail\""));
    }
}
