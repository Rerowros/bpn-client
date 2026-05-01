use thiserror::Error;

pub type BadVpnResult<T> = Result<T, BadVpnError>;

#[derive(Debug, Error)]
pub enum BadVpnError {
    #[error("agent is not installed")]
    AgentNotInstalled,

    #[error("subscription URL is empty")]
    EmptySubscriptionUrl,

    #[error("subscription URL must start with http:// or https://")]
    InvalidSubscriptionUrl,

    #[error("mihomo core is not configured")]
    MihomoNotConfigured,

    #[error("operation failed: {0}")]
    OperationFailed(String),
}
