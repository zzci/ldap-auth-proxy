use crate::config::ApiConfig;
use anyhow::Result;
use reqwest::Client;
use serde_json::{json, Value};
use std::time::Duration;
use tracing::{debug, error, info};

pub struct ApiClient {
    client: Client,
    config: ApiConfig,
}

impl ApiClient {
    pub fn new(config: ApiConfig) -> Result<Self> {
        let client = Client::builder()
            .timeout(Duration::from_secs(config.timeout_secs))
            .build()?;

        Ok(Self { client, config })
    }

    /// Authenticate user against the remote API
    /// Returns true if authentication succeeds, false otherwise
    pub async fn authenticate(&self, username: &str, password: &str) -> Result<bool> {
        info!("Authenticating user: {}", username);

        let body = json!({
            &self.config.username_field: username,
            &self.config.password_field: password,
        });

        let mut request = match self.config.method.to_uppercase().as_str() {
            "POST" => self.client.post(&self.config.url).json(&body),
            "GET" => {
                // For GET requests, send as query parameters
                self.client
                    .get(&self.config.url)
                    .query(&[
                        (&self.config.username_field, username),
                        (&self.config.password_field, password),
                    ])
            }
            _ => {
                error!("Unsupported HTTP method: {}", self.config.method);
                return Ok(false);
            }
        };

        // Add API key header if configured
        if let (Some(header), Some(key)) = (&self.config.api_key_header, &self.config.api_key) {
            request = request.header(header.as_str(), key.as_str());
        }

        let response = match request.send().await {
            Ok(resp) => resp,
            Err(e) => {
                error!("Failed to send authentication request: {}", e);
                return Ok(false);
            }
        };

        let status = response.status();
        debug!("API response status: {}", status);

        if !status.is_success() {
            info!(
                "Authentication failed for user {}: HTTP {}",
                username, status
            );
            return Ok(false);
        }

        // Parse response body
        let body: Value = match response.json().await {
            Ok(b) => b,
            Err(e) => {
                // If we can't parse JSON but got 2xx, consider it success
                debug!("Could not parse response as JSON: {}", e);
                return Ok(true);
            }
        };

        debug!("API response body: {:?}", body);

        // Check success field if configured
        if let Some(success_field) = &self.config.success_field {
            let actual_value = body.get(success_field);

            if let Some(expected_value) = &self.config.success_value {
                // Check if the field matches the expected value
                let matches = actual_value.map(|v| v == expected_value).unwrap_or(false);
                if matches {
                    info!("Authentication successful for user: {}", username);
                    return Ok(true);
                } else {
                    info!(
                        "Authentication failed for user {}: field '{}' = {:?}, expected {:?}",
                        username, success_field, actual_value, expected_value
                    );
                    return Ok(false);
                }
            } else {
                // Just check if the field exists and is truthy
                let success = actual_value
                    .map(|v| match v {
                        Value::Bool(b) => *b,
                        Value::Number(n) => n.as_i64().map(|i| i != 0).unwrap_or(false),
                        Value::String(s) => !s.is_empty() && s != "false" && s != "0",
                        Value::Null => false,
                        _ => true,
                    })
                    .unwrap_or(false);

                if success {
                    info!("Authentication successful for user: {}", username);
                } else {
                    info!("Authentication failed for user: {}", username);
                }
                return Ok(success);
            }
        }

        // No success field configured, 2xx status means success
        info!("Authentication successful for user: {}", username);
        Ok(true)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_api_client_creation() {
        let config = ApiConfig {
            url: "http://localhost:8080/auth".to_string(),
            method: "POST".to_string(),
            timeout_secs: 30,
            api_key_header: None,
            api_key: None,
            username_field: "username".to_string(),
            password_field: "password".to_string(),
            success_field: Some("success".to_string()),
            success_value: Some(Value::Bool(true)),
        };

        let client = ApiClient::new(config);
        assert!(client.is_ok());
    }
}
