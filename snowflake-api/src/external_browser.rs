//! External browser (SSO) authentication flow for Snowflake.
//!
//! Flow:
//! 1. Bind localhost TCP listener on a random port
//! 2. POST `session/authenticator-request` to get SSO URL + proof key
//! 3. Open browser to SSO URL (user authenticates with IdP)
//! 4. Accept callback on localhost, extract SAML token
//! 5. Return token + proof key for the login-request

use std::io::Write;
use std::net::TcpListener;

use serde::Deserialize;
use serde_json::json;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum ExternalBrowserError {
    #[error("HTTP request failed: {0}")]
    Http(#[from] reqwest::Error),

    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    #[error("Task join error: {0}")]
    Join(#[from] tokio::task::JoinError),

    #[error("Unexpected API response: {0}")]
    UnexpectedResponse(String),

    #[error("No token in SSO callback")]
    MissingToken,
}

/// Result of the external browser authentication flow.
pub(crate) struct ExternalBrowserResult {
    pub token: String,
    pub proof_key: Option<String>,
}

#[derive(Deserialize)]
struct AuthenticatorResponse {
    data: Option<AuthenticatorData>,
    message: Option<String>,
    success: bool,
}

#[derive(Deserialize)]
struct AuthenticatorData {
    #[serde(rename = "ssoUrl")]
    sso_url: String,
    #[serde(rename = "proofKey")]
    proof_key: Option<String>,
}

/// Run the external browser SSO flow and return the SAML token + proof key.
pub(crate) async fn run_external_browser_flow(
    account_identifier: &str,
    username: &str,
) -> Result<ExternalBrowserResult, ExternalBrowserError> {
    let http = reqwest::Client::builder().gzip(true).build()?;

    let base_url = format!(
        "https://{}.snowflakecomputing.com",
        account_identifier
    );

    // Step 1: Bind localhost listener
    let listener = TcpListener::bind("127.0.0.1:0")?;
    let redirect_port = listener.local_addr()?.port();
    log::debug!("SSO callback listener on port {}", redirect_port);

    // Step 2: Request authenticator → get SSO URL
    let auth_url = format!("{}/session/authenticator-request", base_url);
    let auth_body = json!({
        "data": {
            "ACCOUNT_NAME": account_identifier,
            "LOGIN_NAME": username,
            "AUTHENTICATOR": "EXTERNALBROWSER",
            "BROWSER_MODE_REDIRECT_PORT": redirect_port.to_string(),
        }
    });

    let resp = http.post(&auth_url).json(&auth_body).send().await?;
    let text = resp.text().await?;

    let auth_resp: AuthenticatorResponse = serde_json::from_str(&text)
        .map_err(|e| ExternalBrowserError::UnexpectedResponse(format!("parse error: {}", e)))?;

    if !auth_resp.success {
        return Err(ExternalBrowserError::UnexpectedResponse(
            auth_resp.message.unwrap_or_default(),
        ));
    }

    let auth_data = auth_resp
        .data
        .ok_or_else(|| ExternalBrowserError::UnexpectedResponse("missing data".to_string()))?;

    // Step 3: Open browser
    eprintln!(
        "Initiating login request with your identity provider. \
         A browser window should have opened for you to complete the login. \
         If you can't see it, check existing browser windows, or your OS settings. \
         Press CTRL+C to abort and try again..."
    );

    if let Err(e) = open::that(&auth_data.sso_url) {
        eprintln!(
            "Failed to open browser automatically: {}. Open this URL manually:\n{}",
            e, auth_data.sso_url
        );
    }

    // Step 4: Wait for callback
    let saml_token = tokio::task::spawn_blocking(move || -> Result<String, ExternalBrowserError> {
        let (mut stream, _) = listener.accept()?;

        let mut buf = [0u8; 16384];
        let n = std::io::Read::read(&mut stream, &mut buf)?;
        let request = String::from_utf8_lossy(&buf[..n]);

        let token = extract_token_from_request(&request)
            .ok_or(ExternalBrowserError::MissingToken)?;

        let response = "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n\
            <html><body><h1>Authentication successful</h1>\
            <p>You can close this window.</p></body></html>";
        let _ = stream.write_all(response.as_bytes());

        Ok(token)
    })
    .await??;

    log::info!("Received SAML token from browser callback");

    Ok(ExternalBrowserResult {
        token: saml_token,
        proof_key: auth_data.proof_key,
    })
}

fn extract_token_from_request(request: &str) -> Option<String> {
    let first_line = request.lines().next()?;
    let path = first_line.split_whitespace().nth(1)?;
    let url = url::Url::parse(&format!("http://localhost{}", path)).ok()?;
    for (key, value) in url.query_pairs() {
        if key == "token" {
            return Some(value.to_string());
        }
    }
    None
}
