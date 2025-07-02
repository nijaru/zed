use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{anyhow, Context as _, Result};
use base64::{Engine as _, engine::general_purpose};
use chrono::{DateTime, Utc};
use futures::AsyncReadExt;
use http_client::{AsyncBody, HttpClient, Method, Request as HttpRequest};
use rand::Rng;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::TcpListener;
use url::Url;


/// OAuth tokens for Anthropic API access
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OAuthTokens {
    pub access_token: String,
    pub refresh_token: String,
    pub expires_at: DateTime<Utc>,
    pub scope: String,
}

impl OAuthTokens {
    /// Check if the access token is expired or will expire within 5 minutes
    pub fn is_expired(&self) -> bool {
        let now = Utc::now();
        let expiry_buffer = chrono::Duration::minutes(5);
        self.expires_at <= now + expiry_buffer
    }
}

/// PKCE (Proof Key for Code Exchange) challenge and verifier
#[derive(Debug, Clone)]
pub struct PKCEChallenge {
    pub verifier: String,
    pub challenge: String,
}

/// OAuth configuration for Anthropic
#[derive(Debug, Clone)]
pub struct OAuthConfig {
    pub client_id: String,
    pub authorization_url: String,
    pub token_url: String,
    pub scope: String,
    pub redirect_uri: String,
}

impl Default for OAuthConfig {
    fn default() -> Self {
        Self {
            // Note: For production use, these would need to be registered with Anthropic
            client_id: "zed-editor".to_string(),
            authorization_url: "https://console.anthropic.com/oauth/authorize".to_string(),
            token_url: "https://api.anthropic.com/oauth/token".to_string(),
            scope: "read write".to_string(),
            redirect_uri: "http://localhost:8080/callback".to_string(),
        }
    }
}

/// Error types specific to OAuth operations
#[derive(Debug, Error)]
pub enum OAuthError {
    #[error("PKCE challenge generation failed: {0}")]
    PKCEGeneration(#[from] rand::Error),
    #[error("HTTP request failed: {0}")]
    HttpRequest(#[from] anyhow::Error),
    #[error("Invalid OAuth response: {0}")]
    InvalidResponse(String),
    #[error("Browser launch failed: {0}")]
    BrowserLaunch(String),
    #[error("Authorization callback timeout")]
    CallbackTimeout,
}

/// OAuth manager for Anthropic authentication
#[derive(Clone)]
pub struct AnthropicOAuthManager {
    config: OAuthConfig,
    client: Arc<dyn HttpClient>,
}

impl AnthropicOAuthManager {
    /// Create a new OAuth manager with default configuration
    pub fn new(client: Arc<dyn HttpClient>) -> Self {
        Self {
            config: OAuthConfig::default(),
            client,
        }
    }

    /// Create a new OAuth manager with custom configuration
    pub fn with_config(client: Arc<dyn HttpClient>, config: OAuthConfig) -> Self {
        Self { config, client }
    }

    /// Generate PKCE challenge and verifier
    fn generate_pkce() -> Result<PKCEChallenge> {
        // Generate a random 128-byte verifier
        let mut rng = rand::thread_rng();
        let verifier_bytes: Vec<u8> = (0..128).map(|_| rng.r#gen::<u8>()).collect();
        let verifier = general_purpose::URL_SAFE_NO_PAD.encode(&verifier_bytes);

        // Create SHA256 hash of the verifier for the challenge
        let mut hasher = Sha256::new();
        hasher.update(verifier.as_bytes());
        let challenge_bytes = hasher.finalize();
        let challenge = general_purpose::URL_SAFE_NO_PAD.encode(challenge_bytes);

        Ok(PKCEChallenge { verifier, challenge })
    }

    /// Build the authorization URL
    fn build_auth_url(&self, pkce: &PKCEChallenge, state: &str) -> Result<String> {
        let mut url = Url::parse(&self.config.authorization_url)
            .context("Invalid authorization URL")?;

        url.query_pairs_mut()
            .append_pair("response_type", "code")
            .append_pair("client_id", &self.config.client_id)
            .append_pair("redirect_uri", &self.config.redirect_uri)
            .append_pair("scope", &self.config.scope)
            .append_pair("state", state)
            .append_pair("code_challenge", &pkce.challenge)
            .append_pair("code_challenge_method", "S256");

        Ok(url.to_string())
    }

    /// Launch the system browser to the authorization URL
    async fn launch_browser(&self, auth_url: &str) -> Result<()> {
        #[cfg(target_os = "macos")]
        {
            tokio::process::Command::new("open")
                .arg(auth_url)
                .spawn()
                .context("Failed to launch browser on macOS")?;
        }

        #[cfg(target_os = "windows")]
        {
            tokio::process::Command::new("cmd")
                .args(["/C", "start", auth_url])
                .spawn()
                .context("Failed to launch browser on Windows")?;
        }

        #[cfg(target_os = "linux")]
        {
            tokio::process::Command::new("xdg-open")
                .arg(auth_url)
                .spawn()
                .context("Failed to launch browser on Linux")?;
        }

        Ok(())
    }

    /// Start a local server to receive the OAuth callback
    async fn start_callback_server(&self, expected_state: String) -> Result<String> {
        let listener = TcpListener::bind("127.0.0.1:8080").await
            .context("Failed to bind to callback port")?;

        // Set a timeout for the callback
        let timeout = Duration::from_secs(300); // 5 minutes
        let callback_future = async {
            loop {
                let (stream, _) = listener.accept().await?;
                let mut reader = BufReader::new(stream);
                let mut request_line = String::new();
                reader.read_line(&mut request_line).await?;

                if let Some(path) = request_line.split_whitespace().nth(1) {
                    if let Ok(url) = Url::parse(&format!("http://localhost{}", path)) {
                        let query: HashMap<String, String> = url.query_pairs()
                            .map(|(k, v)| (k.to_string(), v.to_string()))
                            .collect();

                        // Verify state parameter
                        if let Some(state) = query.get("state") {
                            if state != &expected_state {
                                return Err(anyhow!("Invalid state parameter in OAuth callback"));
                            }
                        } else {
                            return Err(anyhow!("Missing state parameter in OAuth callback"));
                        }

                        // Check for authorization code
                        if let Some(code) = query.get("code") {
                            // Send success response to browser
                            let response = "HTTP/1.1 200 OK\r\n\r\n<html><body><h1>Success!</h1><p>You can close this window.</p></body></html>";
                            let mut writer = reader.into_inner();
                            writer.write_all(response.as_bytes()).await?;
                            writer.flush().await?;
                            return Ok(code.clone());
                        } else if let Some(error) = query.get("error") {
                            return Err(anyhow!("OAuth authorization failed: {}", error));
                        }
                    }
                }
            }
        };

        tokio::time::timeout(timeout, callback_future).await
            .map_err(|_| anyhow!("OAuth callback timeout"))?
    }

    /// Exchange authorization code for access tokens
    async fn exchange_code_for_tokens(&self, code: &str, pkce: &PKCEChallenge) -> Result<OAuthTokens> {
        let token_request = TokenRequest {
            grant_type: "authorization_code".to_string(),
            client_id: self.config.client_id.clone(),
            code: code.to_string(),
            redirect_uri: self.config.redirect_uri.clone(),
            code_verifier: pkce.verifier.clone(),
        };

        let body = serde_json::to_vec(&token_request)
            .context("Failed to serialize token request")?;

        let request = HttpRequest::builder()
            .method(Method::POST)
            .uri(&self.config.token_url)
            .header("Content-Type", "application/json")
            .header("Accept", "application/json")
            .body(AsyncBody::from(body))?;

        let response = self.client.send(request).await
            .context("Failed to exchange authorization code")?;

        let status = response.status();
        if !status.is_success() {
            let mut body = String::new();
            let _ = response.into_body().read_to_string(&mut body).await;
            return Err(anyhow!("Token exchange failed with status {}: {}", status, body));
        }

        let mut body = String::new();
        response.into_body().read_to_string(&mut body).await
            .context("Failed to read token response")?;

        let token_response: TokenResponse = serde_json::from_str(&body)
            .context("Failed to parse token response")?;

        let expires_at = Utc::now() + chrono::Duration::seconds(token_response.expires_in as i64);

        Ok(OAuthTokens {
            access_token: token_response.access_token,
            refresh_token: token_response.refresh_token,
            expires_at,
            scope: token_response.scope.unwrap_or_else(|| self.config.scope.clone()),
        })
    }

    /// Start the OAuth authentication flow
    pub async fn authenticate(&self) -> Result<OAuthTokens> {
        // Generate PKCE challenge
        let pkce = Self::generate_pkce()
            .context("Failed to generate PKCE challenge")?;

        // Generate state parameter for CSRF protection
        let state: String = (0..32).map(|_| {
            let mut rng = rand::thread_rng();
            char::from(rng.r#gen_range(b'a'..=b'z'))
        }).collect();

        // Build authorization URL
        let auth_url = self.build_auth_url(&pkce, &state)
            .context("Failed to build authorization URL")?;

        // Start callback server
        let callback_future = self.start_callback_server(state.clone());

        // Launch browser
        self.launch_browser(&auth_url).await
            .context("Failed to launch browser")?;

        // Wait for callback with authorization code
        let authorization_code = callback_future.await
            .context("Failed to receive authorization callback")?;

        // Exchange code for tokens
        self.exchange_code_for_tokens(&authorization_code, &pkce).await
            .context("Failed to exchange authorization code for tokens")
    }

    /// Refresh access tokens using refresh token
    pub async fn refresh_tokens(&self, refresh_token: &str) -> Result<OAuthTokens> {
        let refresh_request = RefreshTokenRequest {
            grant_type: "refresh_token".to_string(),
            client_id: self.config.client_id.clone(),
            refresh_token: refresh_token.to_string(),
        };

        let body = serde_json::to_vec(&refresh_request)
            .context("Failed to serialize refresh request")?;

        let request = HttpRequest::builder()
            .method(Method::POST)
            .uri(&self.config.token_url)
            .header("Content-Type", "application/json")
            .header("Accept", "application/json")
            .body(AsyncBody::from(body))?;

        let response = self.client.send(request).await
            .context("Failed to refresh tokens")?;

        let status = response.status();
        if !status.is_success() {
            let mut body = String::new();
            let _ = response.into_body().read_to_string(&mut body).await;
            return Err(anyhow!("Token refresh failed with status {}: {}", status, body));
        }

        let mut body = String::new();
        response.into_body().read_to_string(&mut body).await
            .context("Failed to read refresh response")?;

        let token_response: TokenResponse = serde_json::from_str(&body)
            .context("Failed to parse refresh response")?;

        let expires_at = Utc::now() + chrono::Duration::seconds(token_response.expires_in as i64);

        Ok(OAuthTokens {
            access_token: token_response.access_token,
            refresh_token: token_response.refresh_token,
            expires_at,
            scope: token_response.scope.unwrap_or_else(|| self.config.scope.clone()),
        })
    }
}

#[derive(Debug, Serialize)]
struct TokenRequest {
    grant_type: String,
    client_id: String,
    code: String,
    redirect_uri: String,
    code_verifier: String,
}

#[derive(Debug, Serialize)]
struct RefreshTokenRequest {
    grant_type: String,
    client_id: String,
    refresh_token: String,
}

#[derive(Debug, Deserialize)]
struct TokenResponse {
    access_token: String,
    refresh_token: String,
    token_type: String,
    expires_in: u64,
    scope: Option<String>,
}