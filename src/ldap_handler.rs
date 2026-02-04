use crate::api_client::ApiClient;
use anyhow::{anyhow, Result};
use bytes::{Buf, BytesMut};
use rasn_ldap::{
    BindRequest, BindResponse, LdapMessage, LdapResult as LdapResultType, LdapString, MessageId,
    ProtocolOp, ResultCode, SearchRequest, SearchResultDone,
};
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tracing::{debug, error, info, warn};

pub struct LdapHandler {
    api_client: Arc<ApiClient>,
}

impl LdapHandler {
    pub fn new(api_client: Arc<ApiClient>) -> Self {
        Self { api_client }
    }

    pub async fn handle_connection(&self, mut stream: TcpStream, addr: std::net::SocketAddr) {
        info!("New LDAP connection from: {}", addr);

        let mut buffer = BytesMut::with_capacity(4096);

        loop {
            // Read data from the stream
            match stream.read_buf(&mut buffer).await {
                Ok(0) => {
                    info!("Connection closed by client: {}", addr);
                    break;
                }
                Ok(n) => {
                    debug!("Received {} bytes from {}", n, addr);
                }
                Err(e) => {
                    error!("Error reading from {}: {}", addr, e);
                    break;
                }
            }

            // Try to parse LDAP messages from the buffer
            loop {
                match self.try_parse_message(&mut buffer) {
                    Ok(Some(message)) => {
                        debug!("Parsed LDAP message: {:?}", message.message_id);

                        let response = self.handle_message(message).await;

                        if let Some(resp_msg) = response {
                            // Check if this is an unbind (we should close after sending response)
                            let is_unbind =
                                matches!(resp_msg.protocol_op, ProtocolOp::UnbindRequest(_));

                            if let Err(e) = self.send_response(&mut stream, resp_msg).await {
                                error!("Error sending response to {}: {}", addr, e);
                                return;
                            }

                            if is_unbind {
                                info!("Unbind request received, closing connection: {}", addr);
                                return;
                            }
                        }
                    }
                    Ok(None) => {
                        // Need more data
                        break;
                    }
                    Err(e) => {
                        error!("Error parsing LDAP message from {}: {}", addr, e);
                        // Send a protocol error and close
                        break;
                    }
                }
            }
        }
    }

    fn try_parse_message(&self, buffer: &mut BytesMut) -> Result<Option<LdapMessage>> {
        if buffer.is_empty() {
            return Ok(None);
        }

        // Try to decode an LDAP message
        let data = buffer.chunk();

        match rasn::ber::decode::<LdapMessage>(data) {
            Ok(message) => {
                // Calculate how many bytes were consumed
                // We need to re-encode to find the exact length
                let encoded =
                    rasn::ber::encode(&message).map_err(|e| anyhow!("Encode error: {:?}", e))?;
                let consumed = encoded.len();
                buffer.advance(consumed);
                Ok(Some(message))
            }
            Err(e) => {
                // Check if this might be incomplete data
                if data.len() < 2 {
                    return Ok(None);
                }

                // Try to determine if we have a complete message
                // BER/DER length encoding check
                if let Some(total_len) = self.get_ber_message_length(data) {
                    if data.len() < total_len {
                        // Need more data
                        return Ok(None);
                    }
                }

                Err(anyhow!("Failed to decode LDAP message: {:?}", e))
            }
        }
    }

    fn get_ber_message_length(&self, data: &[u8]) -> Option<usize> {
        if data.len() < 2 {
            return None;
        }

        // BER/DER encoding: first byte is tag, then length
        let length_byte = data[1];

        if length_byte & 0x80 == 0 {
            // Short form: length is in the byte itself
            Some(2 + length_byte as usize)
        } else {
            // Long form: lower 7 bits indicate number of length bytes
            let num_length_bytes = (length_byte & 0x7f) as usize;
            if data.len() < 2 + num_length_bytes {
                return None;
            }

            let mut length: usize = 0;
            for i in 0..num_length_bytes {
                length = (length << 8) | data[2 + i] as usize;
            }

            Some(2 + num_length_bytes + length)
        }
    }

    async fn handle_message(&self, message: LdapMessage) -> Option<LdapMessage> {
        let message_id = message.message_id;

        match message.protocol_op {
            ProtocolOp::BindRequest(bind_req) => {
                let response = self.handle_bind(message_id, bind_req).await;
                Some(response)
            }
            ProtocolOp::UnbindRequest(_) => {
                info!("Received unbind request");
                None
            }
            ProtocolOp::SearchRequest(search_req) => {
                let response = self.handle_search(message_id, search_req);
                Some(response)
            }
            _ => {
                warn!("Unsupported LDAP operation: {:?}", message.protocol_op);
                Some(self.create_unsupported_response(message_id))
            }
        }
    }

    async fn handle_bind(&self, message_id: MessageId, bind_req: BindRequest) -> LdapMessage {
        // LdapString implements Deref to String, so we can use as_str()
        let dn = bind_req.name.as_str();
        info!("Bind request for DN: {}", dn);

        // Extract username from DN
        let username = self.extract_username_from_dn(dn);

        // Extract password from authentication choice
        let password = match &bind_req.authentication {
            rasn_ldap::AuthenticationChoice::Simple(pwd) => {
                String::from_utf8_lossy(pwd).to_string()
            }
            _ => {
                warn!("Unsupported authentication mechanism");
                return self.create_bind_response(
                    message_id,
                    ResultCode::AuthMethodNotSupported,
                    "Only simple authentication is supported",
                );
            }
        };

        // Allow anonymous bind (empty username and password)
        if username.is_empty() && password.is_empty() {
            info!("Anonymous bind successful");
            return self.create_bind_response(message_id, ResultCode::Success, "");
        }

        // Authenticate against API
        match self.api_client.authenticate(&username, &password).await {
            Ok(true) => {
                info!("Bind successful for user: {}", username);
                self.create_bind_response(message_id, ResultCode::Success, "")
            }
            Ok(false) => {
                info!("Bind failed for user: {}", username);
                self.create_bind_response(
                    message_id,
                    ResultCode::InvalidCredentials,
                    "Invalid username or password",
                )
            }
            Err(e) => {
                error!("Authentication error for user {}: {}", username, e);
                self.create_bind_response(
                    message_id,
                    ResultCode::Other,
                    "Authentication service unavailable",
                )
            }
        }
    }

    fn handle_search(&self, message_id: MessageId, search_req: SearchRequest) -> LdapMessage {
        let base_dn = search_req.base_object.as_str();
        debug!("Search request for base DN: {}", base_dn);

        // We don't support search operations - just return done with no results
        // This is sufficient for authentication-only use cases
        self.create_search_done_response(message_id, ResultCode::Success, "")
    }

    fn create_bind_response(
        &self,
        message_id: MessageId,
        result_code: ResultCode,
        message: &str,
    ) -> LdapMessage {
        let bind_response = BindResponse::new(
            result_code,
            LdapString::from(""),
            LdapString::from(message),
            None,
            None,
        );

        LdapMessage::new(message_id, ProtocolOp::BindResponse(bind_response))
    }

    fn create_search_done_response(
        &self,
        message_id: MessageId,
        result_code: ResultCode,
        message: &str,
    ) -> LdapMessage {
        let ldap_result = LdapResultType::new(
            result_code,
            LdapString::from(""),
            LdapString::from(message),
        );
        let search_done = SearchResultDone(ldap_result);

        LdapMessage::new(message_id, ProtocolOp::SearchResDone(search_done))
    }

    fn create_unsupported_response(&self, message_id: MessageId) -> LdapMessage {
        self.create_bind_response(
            message_id,
            ResultCode::UnwillingToPerform,
            "Operation not supported",
        )
    }

    fn extract_username_from_dn(&self, dn: &str) -> String {
        // Parse DN to extract username
        // Common formats:
        // - uid=username,ou=users,dc=example,dc=com
        // - cn=username,ou=users,dc=example,dc=com
        // - username@domain.com
        // - just username

        if dn.is_empty() {
            return String::new();
        }

        // Check for email format
        if dn.contains('@') && !dn.contains('=') {
            return dn.split('@').next().unwrap_or(dn).to_string();
        }

        // Parse DN components
        for component in dn.split(',') {
            let component = component.trim();
            if let Some((attr, value)) = component.split_once('=') {
                let attr_lower = attr.to_lowercase();
                if attr_lower == "uid" || attr_lower == "cn" || attr_lower == "samaccountname" {
                    return value.to_string();
                }
            }
        }

        // If no standard attribute found, return the whole DN as username
        dn.to_string()
    }

    async fn send_response(&self, stream: &mut TcpStream, message: LdapMessage) -> Result<()> {
        let encoded =
            rasn::ber::encode(&message).map_err(|e| anyhow!("Encode error: {:?}", e))?;

        stream.write_all(&encoded).await?;
        stream.flush().await?;

        debug!("Sent response for message {}", message.message_id);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::ApiConfig;

    fn create_test_handler() -> LdapHandler {
        let config = ApiConfig {
            url: "http://localhost:8080/auth".to_string(),
            method: "POST".to_string(),
            timeout_secs: 30,
            api_key_header: None,
            api_key: None,
            username_field: "username".to_string(),
            password_field: "password".to_string(),
            success_field: Some("success".to_string()),
            success_value: Some(serde_json::Value::Bool(true)),
        };

        let api_client = Arc::new(ApiClient::new(config).unwrap());
        LdapHandler::new(api_client)
    }

    #[test]
    fn test_extract_username_from_uid() {
        let handler = create_test_handler();
        let username = handler.extract_username_from_dn("uid=testuser,ou=users,dc=example,dc=com");
        assert_eq!(username, "testuser");
    }

    #[test]
    fn test_extract_username_from_cn() {
        let handler = create_test_handler();
        let username = handler.extract_username_from_dn("cn=testuser,ou=users,dc=example,dc=com");
        assert_eq!(username, "testuser");
    }

    #[test]
    fn test_extract_username_from_email() {
        let handler = create_test_handler();
        let username = handler.extract_username_from_dn("testuser@example.com");
        assert_eq!(username, "testuser");
    }

    #[test]
    fn test_extract_username_plain() {
        let handler = create_test_handler();
        let username = handler.extract_username_from_dn("testuser");
        assert_eq!(username, "testuser");
    }
}
