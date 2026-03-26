pub mod inject;
pub mod rate_limit;
pub mod strip;

use std::sync::Arc;

use axum::body::Body;
use axum::extract::State;
use axum::http::{HeaderMap, HeaderValue, Request, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::any;
use axum::Router;
use tokio::sync::RwLock;

use crate::config::WardenConfig;
use crate::vault::Vault;
use crate::WardenError;
use rate_limit::RateLimiter;

/// Shared state for the proxy server.
pub struct ProxyState {
    pub vault: Arc<RwLock<Vault>>,
    pub rate_limiter: Arc<tokio::sync::Mutex<RateLimiter>>,
    pub config: WardenConfig,
    pub http_client: reqwest::Client,
}

const AGENT_HEADER: &str = "x-warden-agent";

/// Generate a short unique request ID for audit trail correlation.
fn generate_request_id() -> String {
    use rand::Rng;
    let bytes: [u8; 6] = rand::thread_rng().gen();
    hex::encode(bytes)
}

/// Build the proxy router.
pub fn build_router(state: Arc<ProxyState>) -> Router {
    Router::new()
        .route("/health", axum::routing::get(health_handler))
        .fallback(any(proxy_handler))
        .with_state(state)
}

async fn health_handler() -> impl IntoResponse {
    (StatusCode::OK, "ok")
}

async fn proxy_handler(
    State(state): State<Arc<ProxyState>>,
    req: Request<Body>,
) -> Response {
    match handle_proxy_request(state, req).await {
        Ok(response) => response,
        Err(e) => {
            tracing::warn!(error = %e, "proxy request failed");
            error_response(e)
        }
    }
}

async fn handle_proxy_request(
    state: Arc<ProxyState>,
    req: Request<Body>,
) -> crate::Result<Response> {
    let request_id = generate_request_id();

    // 1. Extract agent identity from X-Warden-Agent header
    let agent_id = req
        .headers()
        .get(AGENT_HEADER)
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string())
        .unwrap_or_else(|| "anonymous".to_string());

    // 2. Extract destination from Host header or URL
    let host = req
        .headers()
        .get("host")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string())
        .unwrap_or_default();

    let domain = host.split(':').next().unwrap_or(&host).to_string();
    let method = req.method().to_string();
    let path = req.uri().path().to_string();

    tracing::info!(
        request_id = %request_id,
        agent = %agent_id,
        method = %method,
        domain = %domain,
        path = %path,
        "proxy request received"
    );

    // 3. Read the request parts
    let (mut parts, body) = req.into_parts();
    let body_bytes = axum::body::to_bytes(body, 10 * 1024 * 1024) // 10MB limit
        .await
        .map_err(|e| WardenError::Io(std::io::Error::other(e)))?;

    // 4. Strip X-Warden-Agent header (must not reach upstream)
    parts.headers.remove(AGENT_HEADER);

    // 5. Inject credentials into headers
    let vault = state.vault.read().await;
    let mut all_injected = Vec::new();

    let mut new_headers = HeaderMap::new();
    for (name, value) in parts.headers.iter() {
        let value_str = value.to_str().unwrap_or_default();
        let (injected_value, injected_creds) =
            inject::inject_header_value(value_str, &agent_id, &domain, &vault)?;
        all_injected.extend(injected_creds);
        if let Ok(hv) = HeaderValue::from_str(&injected_value) {
            new_headers.insert(name.clone(), hv);
        }
    }
    parts.headers = new_headers;

    // 6. Inject credentials into body
    let (injected_body, body_injected) =
        inject::inject_body(&body_bytes, &agent_id, &domain, &vault)?;
    all_injected.extend(body_injected);

    // Log credential injection events
    for cred_name in &all_injected {
        tracing::info!(
            request_id = %request_id,
            agent = %agent_id,
            credential = %cred_name,
            domain = %domain,
            "credential injected"
        );
    }

    // 7. Rate limit check for each injected credential
    {
        let mut rl = state.rate_limiter.lock().await;
        for cred_name in &all_injected {
            if let Err(retry_after) = rl.check(cred_name, &agent_id) {
                tracing::warn!(
                    request_id = %request_id,
                    agent = %agent_id,
                    credential = %cred_name,
                    retry_after_seconds = %retry_after,
                    "rate limit exceeded"
                );
                return Err(WardenError::RateLimitExceeded {
                    credential: cred_name.clone(),
                    agent_id: agent_id.clone(),
                    retry_after_seconds: retry_after,
                });
            }
        }
    }

    drop(vault); // release read lock before forwarding

    // 8. Build upstream URL
    let uri = parts.uri.clone();
    let scheme = uri.scheme_str().unwrap_or("https");
    let path_and_query = uri
        .path_and_query()
        .map(|pq| pq.as_str())
        .unwrap_or("/");
    let upstream_url = format!("{scheme}://{host}{path_and_query}");

    // 9. Forward request to upstream
    let method = match parts.method {
        axum::http::Method::GET => reqwest::Method::GET,
        axum::http::Method::POST => reqwest::Method::POST,
        axum::http::Method::PUT => reqwest::Method::PUT,
        axum::http::Method::DELETE => reqwest::Method::DELETE,
        axum::http::Method::PATCH => reqwest::Method::PATCH,
        axum::http::Method::HEAD => reqwest::Method::HEAD,
        axum::http::Method::OPTIONS => reqwest::Method::OPTIONS,
        _ => reqwest::Method::GET,
    };

    let mut upstream_req = state.http_client.request(method, &upstream_url);

    // Copy headers (skip host — reqwest sets it)
    let mut reqwest_headers = reqwest::header::HeaderMap::new();
    for (name, value) in parts.headers.iter() {
        if name.as_str() == "host" {
            continue;
        }
        if let Ok(rn) = reqwest::header::HeaderName::from_bytes(name.as_str().as_bytes()) {
            if let Ok(rv) = reqwest::header::HeaderValue::from_bytes(value.as_bytes()) {
                reqwest_headers.insert(rn, rv);
            }
        }
    }
    upstream_req = upstream_req.headers(reqwest_headers);
    upstream_req = upstream_req.body(injected_body);

    let upstream_resp = upstream_req
        .send()
        .await
        .map_err(|e| WardenError::Io(std::io::Error::other(e)))?;

    // 10. Read upstream response
    let resp_status = upstream_resp.status();
    let resp_headers = upstream_resp.headers().clone();
    let resp_body = upstream_resp
        .bytes()
        .await
        .map_err(|e| WardenError::Io(std::io::Error::other(e)))?;

    // 11. Strip credentials from response
    let vault = state.vault.read().await;
    let (stripped_body, strip_info) =
        strip::strip_body(&resp_body, &agent_id, &all_injected, &vault);
    drop(vault);

    if strip_info.stripped_count > 0 {
        tracing::info!(
            request_id = %request_id,
            agent = %agent_id,
            stripped_count = %strip_info.stripped_count,
            credentials = ?strip_info.stripped_credentials,
            "credentials stripped from response"
        );
    }

    tracing::info!(
        request_id = %request_id,
        agent = %agent_id,
        upstream_status = %resp_status.as_u16(),
        credentials_injected = %all_injected.len(),
        credentials_stripped = %strip_info.stripped_count,
        "proxy request completed"
    );

    // 12. Build response
    let mut response = Response::builder().status(StatusCode::from_u16(resp_status.as_u16()).unwrap_or(StatusCode::BAD_GATEWAY));

    // Copy response headers
    for (name, value) in resp_headers.iter() {
        let name_str = name.as_str();
        // Strip credentials from response headers too
        let vault = state.vault.read().await;
        let (stripped_value, _) = strip::strip_header_value(
            value.to_str().unwrap_or_default(),
            &agent_id,
            &all_injected,
            &vault,
        );
        drop(vault);
        if let Ok(hv) = HeaderValue::from_str(&stripped_value) {
            response = response.header(name_str, hv);
        }
    }

    // Add Warden metadata headers
    if strip_info.stripped_count > 0 {
        if let Ok(hv) = HeaderValue::from_str(&strip_info.stripped_count.to_string()) {
            response = response.header("x-warden-stripped", hv);
        }
    }

    response
        .body(Body::from(stripped_body))
        .map_err(|e| WardenError::Io(std::io::Error::other(e)))
}

fn error_response(err: WardenError) -> Response {
    let (status, body) = match &err {
        WardenError::Unauthorized { agent_id, credential } => (
            StatusCode::FORBIDDEN,
            serde_json::json!({
                "error": "unauthorized",
                "agent": agent_id,
                "credential": credential,
            }),
        ),
        WardenError::DomainNotAllowed { domain, credential } => (
            StatusCode::FORBIDDEN,
            serde_json::json!({
                "error": "domain_not_allowed",
                "domain": domain,
                "credential": credential,
            }),
        ),
        WardenError::RateLimitExceeded {
            credential,
            agent_id,
            retry_after_seconds,
        } => (
            StatusCode::TOO_MANY_REQUESTS,
            serde_json::json!({
                "error": "rate_limit_exceeded",
                "credential": credential,
                "agent": agent_id,
                "retry_after_seconds": retry_after_seconds,
            }),
        ),
        _ => (
            StatusCode::BAD_GATEWAY,
            serde_json::json!({
                "error": "proxy_error",
                "message": err.to_string(),
            }),
        ),
    };

    Response::builder()
        .status(status)
        .header("content-type", "application/json")
        .body(Body::from(serde_json::to_vec(&body).unwrap_or_default()))
        .unwrap_or_else(|_| {
            Response::builder()
                .status(StatusCode::INTERNAL_SERVER_ERROR)
                .body(Body::empty())
                .unwrap()
        })
}
