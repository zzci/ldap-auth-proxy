//! A simple mock authentication API server for testing the LDAP proxy
//!
//! Run with: cargo run --example mock_api_server
//!
//! This server accepts POST requests to /api/auth with JSON body:
//! { "username": "...", "password": "..." }
//!
//! Valid credentials: admin/admin123, user/user123, test/test123

use std::convert::Infallible;
use std::net::SocketAddr;

use http_body_util::Full;
use hyper::body::Bytes;
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper::{body::Incoming, Method, Request, Response, StatusCode};
use hyper_util::rt::TokioIo;
use serde::{Deserialize, Serialize};
use tokio::net::TcpListener;

#[derive(Debug, Deserialize)]
struct AuthRequest {
    username: String,
    password: String,
}

#[derive(Debug, Serialize)]
struct AuthResponse {
    success: bool,
    message: String,
}

// Valid users for testing
const VALID_USERS: &[(&str, &str)] = &[
    ("admin", "admin123"),
    ("user", "user123"),
    ("test", "test123"),
];

async fn handle_request(
    req: Request<Incoming>,
) -> Result<Response<Full<Bytes>>, Infallible> {
    let (parts, body) = req.into_parts();

    // Only handle POST /api/auth
    if parts.method != Method::POST || parts.uri.path() != "/api/auth" {
        let response = AuthResponse {
            success: false,
            message: "Not found".to_string(),
        };
        let body = serde_json::to_string(&response).unwrap();
        return Ok(Response::builder()
            .status(StatusCode::NOT_FOUND)
            .header("Content-Type", "application/json")
            .body(Full::new(Bytes::from(body)))
            .unwrap());
    }

    // Read body
    let body_bytes = match http_body_util::BodyExt::collect(body).await {
        Ok(collected) => collected.to_bytes(),
        Err(_) => {
            let response = AuthResponse {
                success: false,
                message: "Failed to read request body".to_string(),
            };
            let body = serde_json::to_string(&response).unwrap();
            return Ok(Response::builder()
                .status(StatusCode::BAD_REQUEST)
                .header("Content-Type", "application/json")
                .body(Full::new(Bytes::from(body)))
                .unwrap());
        }
    };

    // Parse JSON
    let auth_req: AuthRequest = match serde_json::from_slice(&body_bytes) {
        Ok(req) => req,
        Err(e) => {
            let response = AuthResponse {
                success: false,
                message: format!("Invalid JSON: {}", e),
            };
            let body = serde_json::to_string(&response).unwrap();
            return Ok(Response::builder()
                .status(StatusCode::BAD_REQUEST)
                .header("Content-Type", "application/json")
                .body(Full::new(Bytes::from(body)))
                .unwrap());
        }
    };

    println!(
        "Authentication request: username={}, password={}",
        auth_req.username,
        "*".repeat(auth_req.password.len())
    );

    // Check credentials
    let is_valid = VALID_USERS
        .iter()
        .any(|(u, p)| *u == auth_req.username && *p == auth_req.password);

    let response = if is_valid {
        println!("  -> Authentication successful");
        AuthResponse {
            success: true,
            message: "Authentication successful".to_string(),
        }
    } else {
        println!("  -> Authentication failed");
        AuthResponse {
            success: false,
            message: "Invalid credentials".to_string(),
        }
    };

    let body = serde_json::to_string(&response).unwrap();
    Ok(Response::builder()
        .status(StatusCode::OK)
        .header("Content-Type", "application/json")
        .body(Full::new(Bytes::from(body)))
        .unwrap())
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let addr = SocketAddr::from(([127, 0, 0, 1], 8080));

    let listener = TcpListener::bind(addr).await?;
    println!("Mock authentication API server listening on http://{}", addr);
    println!();
    println!("Valid credentials:");
    for (user, pass) in VALID_USERS {
        println!("  - {}:{}", user, pass);
    }
    println!();

    loop {
        let (stream, _) = listener.accept().await?;
        let io = TokioIo::new(stream);

        tokio::task::spawn(async move {
            if let Err(err) = http1::Builder::new()
                .serve_connection(io, service_fn(handle_request))
                .await
            {
                eprintln!("Error serving connection: {:?}", err);
            }
        });
    }
}
