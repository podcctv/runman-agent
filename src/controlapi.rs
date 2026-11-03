//! Root-only local HTTP-over-Unix-socket APIs used by Podman Watcher.
//!
//! The compatibility paths intentionally match the Go agent contracts so a
//! fresh Rust node can be managed by the same Watcher without exposing a TCP
//! control port.

use std::future::Future;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result, bail};
use serde::Deserialize;
use serde_json::{Value, json};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{UnixListener, UnixStream};
use tokio::time::timeout;
use tracing::warn;

const CONNLIMIT_SOCKET: &str = "/run/narwhal-agent/connlimit.sock";
const FIREWALL_SOCKET: &str = "/run/narwhal-agent/firewall.sock";
const MAX_HEADER: usize = 16 * 1024;
const MAX_BODY: usize = 128 * 1024;

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ConnLimitRequest {
    action: String,
    policy_id: String,
    container_name: String,
    project: String,
    #[serde(default)]
    instance_id: String,
    #[serde(default)]
    max_connections: u32,
    #[serde(default)]
    expires_at: i64,
}

#[derive(Debug)]
struct HttpRequest {
    method: String,
    target: String,
    body: Vec<u8>,
}

struct SocketCleanup(&'static str);

impl Drop for SocketCleanup {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(self.0);
    }
}

pub async fn serve_connlimit<F, Fut, I, IFut>(
    manager: Arc<crate::connlimit::Manager>,
    resolve: F,
    inventory: I,
) -> Result<()>
where
    F: Fn(String) -> Fut + Clone + Send + Sync + 'static,
    Fut: Future<Output = Result<crate::connlimit::Target>> + Send + 'static,
    I: Fn() -> IFut + Clone + Send + Sync + 'static,
    IFut: Future<Output = Result<Value>> + Send + 'static,
{
    let listener = bind(CONNLIMIT_SOCKET).await?;
    let _cleanup = SocketCleanup(CONNLIMIT_SOCKET);
    loop {
        let (stream, _) = listener
            .accept()
            .await
            .context("accept connection-limit socket")?;
        let manager = manager.clone();
        let resolve = resolve.clone();
        let inventory = inventory.clone();
        tokio::spawn(async move {
            if let Err(e) = timeout(Duration::from_secs(10), async move {
                handle_connlimit(stream, manager, resolve, inventory).await
            })
            .await
            .context("connection-limit control request timed out")
            .and_then(|r| r)
            {
                warn!("connection-limit local API: {e:#}");
            }
        });
    }
}

pub async fn serve_firewall(manager: Arc<crate::hostpolicy::Manager>) -> Result<()> {
    let listener = bind(FIREWALL_SOCKET).await?;
    let _cleanup = SocketCleanup(FIREWALL_SOCKET);
    loop {
        let (stream, _) = listener.accept().await.context("accept firewall socket")?;
        let manager = manager.clone();
        tokio::spawn(async move {
            if let Err(e) = timeout(Duration::from_secs(10), handle_firewall(stream, manager))
                .await
                .context("firewall control request timed out")
                .and_then(|r| r)
            {
                warn!("firewall local API: {e:#}");
            }
        });
    }
}

async fn handle_connlimit<F, Fut, I, IFut>(
    mut stream: UnixStream,
    manager: Arc<crate::connlimit::Manager>,
    resolve: F,
    inventory: I,
) -> Result<()>
where
    F: Fn(String) -> Fut,
    Fut: Future<Output = Result<crate::connlimit::Target>>,
    I: Fn() -> IFut,
    IFut: Future<Output = Result<Value>>,
{
    let request = match read_request(&mut stream, 8192).await {
        Ok(request) => request,
        Err(e) => return respond_error(&mut stream, 400, &format!("invalid request: {e:#}")).await,
    };
    let (path, query) = request
        .target
        .split_once('?')
        .unwrap_or((&request.target, ""));
    if request.method == "GET" && path == "/v1/inventory" {
        return match inventory().await {
            Ok(report) => respond_json(&mut stream, 200, &report).await,
            Err(e) => {
                respond_error(&mut stream, 503, &format!("inventory unavailable: {e:#}")).await
            }
        };
    }
    if request.method == "GET" && path == "/v1/connlimit/target" {
        if query_value(query, "project")
            .as_deref()
            .unwrap_or("default")
            != "default"
        {
            return respond_error(&mut stream, 400, "only the default project is supported").await;
        }
        let Some(raw_id) = query_value(query, "container_name") else {
            return respond_error(&mut stream, 400, "container_name is required").await;
        };
        let id = match crate::model::VmId::parse(&raw_id) {
            Ok(id) => id.as_str().to_owned(),
            Err(_) => {
                return respond_error(
                    &mut stream,
                    400,
                    "container_name must be the managed Runman VM UUID",
                )
                .await;
            }
        };
        return match resolve(id.clone()).await {
            Ok(target) => {
                let report = match inventory().await {
                    Ok(report) => report,
                    Err(e) => {
                        return respond_error(
                            &mut stream,
                            503,
                            &format!("fresh Runman connection evidence unavailable: {e:#}"),
                        )
                        .await;
                    }
                };
                let item = report
                    .get("items")
                    .and_then(Value::as_array)
                    .and_then(|items| {
                        items.iter().find(|item| {
                            item.get("id").and_then(Value::as_str) == Some(id.as_str())
                        })
                    });
                let metrics = item
                    .and_then(|item| item.get("connection_metrics"))
                    .cloned()
                    .unwrap_or_else(|| json!({"schema": 1, "valid": false}));
                respond_json(
                    &mut stream,
                    200,
                    &json!({
                        "managed": target.managed,
                        "running": target.running,
                        "instance_id": target.instance_id,
                        "ips": target.ips,
                        "connection_metrics": metrics,
                    }),
                )
                .await
            }
            Err(_) => {
                respond_json(
                    &mut stream,
                    404,
                    &json!({"managed": false, "running": false}),
                )
                .await
            }
        };
    }
    if request.method != "POST" || path != "/v1/connlimit" {
        return respond_error(&mut stream, 404, "not found").await;
    }
    let req: ConnLimitRequest = match serde_json::from_slice(&request.body) {
        Ok(value) => value,
        Err(_) => return respond_error(&mut stream, 400, "invalid JSON request").await,
    };
    if req.project != "default" || req.container_name.is_empty() {
        return respond_error(
            &mut stream,
            400,
            "only a named default-project Runman instance is supported",
        )
        .await;
    }
    let vm_id = match crate::model::VmId::parse(&req.container_name) {
        Ok(id) => id.as_str().to_owned(),
        Err(_) => {
            return respond_error(
                &mut stream,
                400,
                "container_name must be the managed Runman VM UUID",
            )
            .await;
        }
    };
    match req.action.as_str() {
        "apply" => {
            let target = match resolve(vm_id.clone()).await {
                Ok(target) => target,
                Err(e) => {
                    return respond_error(
                        &mut stream,
                        409,
                        &format!("managed Runman target could not be verified: {e:#}"),
                    )
                    .await;
                }
            };
            let instance_id = if req.instance_id.is_empty() {
                target.instance_id.clone()
            } else {
                req.instance_id
            };
            let policy = crate::connlimit::Policy {
                id: req.policy_id,
                vm_id,
                instance_id: instance_id.clone(),
                max_connections: req.max_connections,
                expires_at: req.expires_at,
                ips: Vec::new(),
                remove_only: false,
            };
            return match manager.apply(policy, &target).await {
                Ok(()) => {
                    respond_json(
                        &mut stream,
                        200,
                        &json!({
                            "ok": true,
                            "message": "temporary per-instance TCP connection limit applied",
                            "instance_id": instance_id,
                            "ips": target.ips,
                        }),
                    )
                    .await
                }
                Err(e) => {
                    respond_json(
                        &mut stream,
                        409,
                        &json!({"ok": false, "message": format!("{e:#}")}),
                    )
                    .await
                }
            };
        }
        "release" => {
            return match manager
                .release(&req.policy_id, &vm_id, &req.instance_id)
                .await
            {
                Ok(()) => respond_json(
                    &mut stream,
                    200,
                    &json!({"ok": true, "message": "per-instance TCP connection limit released"}),
                )
                .await,
                Err(e) => {
                    respond_json(
                        &mut stream,
                        409,
                        &json!({"ok": false, "message": format!("{e:#}")}),
                    )
                    .await
                }
            };
        }
        _ => return respond_error(&mut stream, 400, "action must be apply or release").await,
    }
}

async fn handle_firewall(
    mut stream: UnixStream,
    manager: Arc<crate::hostpolicy::Manager>,
) -> Result<()> {
    let request = match read_request(&mut stream, MAX_BODY).await {
        Ok(request) => request,
        Err(e) => return respond_error(&mut stream, 400, &format!("invalid request: {e:#}")).await,
    };
    let (path, query) = request
        .target
        .split_once('?')
        .unwrap_or((&request.target, ""));
    match (request.method.as_str(), path) {
        ("GET", "/v1/firewall/readback") => match manager.readback().await {
            Ok(body) => respond_json(&mut stream, 200, &serde_json::to_value(body)?).await,
            Err(_) => {
                respond_error(&mut stream, 503, "RFW live rule readback is unavailable").await
            }
        },
        ("GET", "/v1/firewall/events") => {
            let cursor = query_value(query, "cursor").unwrap_or_default();
            let limit = query_value(query, "limit").unwrap_or_default();
            let limit = if limit.is_empty() {
                100
            } else {
                match limit.parse::<usize>() {
                    Ok(v) if (1..=100).contains(&v) => v,
                    _ => {
                        return respond_error(
                            &mut stream,
                            400,
                            "firewall event limit must be between 1 and 100",
                        )
                        .await;
                    }
                }
            };
            if cursor.len() > 160 {
                return respond_error(&mut stream, 400, "invalid firewall event cursor").await;
            }
            match manager.events(&cursor, limit).await {
                Ok(page) => respond_json(&mut stream, 200, &serde_json::to_value(page)?).await,
                Err(e) if e.to_string().contains("not supported") => {
                    respond_error(&mut stream, 404, "RFW build does not expose an events API").await
                }
                Err(_) => {
                    respond_error(&mut stream, 503, "RFW event telemetry is unavailable").await
                }
            }
        }
        // The Watcher capability probe intentionally GETs this known path:
        // Go's ServeMux returns 405 for the existing POST route, while 404
        // means the Runman firewall control API is not installed.
        ("GET", "/v1/firewall/policy") => respond_error(&mut stream, 405, "POST required").await,
        ("POST", "/v1/firewall/policy") => {
            if request.body.len() > MAX_BODY {
                return respond_error(&mut stream, 400, "invalid or oversized policy request")
                    .await;
            }
            let policy: crate::hostpolicy::Policy = match serde_json::from_slice(&request.body) {
                Ok(policy) => policy,
                Err(_) => {
                    return respond_error(&mut stream, 400, "invalid firewall policy JSON").await;
                }
            };
            match manager.apply(policy).await {
                Ok(message) => {
                    respond_json(&mut stream, 200, &json!({"ok": true, "message": message})).await
                }
                Err(e) => {
                    respond_json(
                        &mut stream,
                        409,
                        &json!({"ok": false, "message": format!("{e:#}")}),
                    )
                    .await
                }
            }
        }
        ("DELETE", _) if path.starts_with("/v1/firewall/rules/") => {
            let id = match path
                .trim_start_matches("/v1/firewall/rules/")
                .parse::<i32>()
            {
                Ok(id) if id > 0 => id,
                _ => return respond_error(&mut stream, 400, "invalid RFW rule ID").await,
            };
            let expected: crate::hostpolicy::RuleReadback =
                match serde_json::from_slice(&request.body) {
                    Ok(expected) => expected,
                    Err(_) => {
                        return respond_error(&mut stream, 400, "invalid RFW rule identity JSON")
                            .await;
                    }
                };
            if expected.id != id {
                return respond_error(
                    &mut stream,
                    400,
                    "RFW rule ID does not match the requested path",
                )
                .await;
            }
            match manager.delete_manual_rule(expected).await {
                Ok(()) => respond_json(
                    &mut stream,
                    200,
                    &json!({"ok": true, "message": "RFW manual rule deleted or already absent"}),
                )
                .await,
                Err(e) => {
                    respond_json(
                        &mut stream,
                        409,
                        &json!({"ok": false, "message": format!("{e:#}")}),
                    )
                    .await
                }
            }
        }
        _ => respond_error(&mut stream, 404, "not found").await,
    }
}

fn query_value(query: &str, key: &str) -> Option<String> {
    query
        .split('&')
        .filter_map(|item| item.split_once('='))
        .find_map(|(k, v)| {
            (percent_decode(k).ok()?.as_str() == key)
                .then(|| percent_decode(v).ok())
                .flatten()
        })
}

fn percent_decode(value: &str) -> Result<String> {
    let bytes = value.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' {
            if i + 2 >= bytes.len() {
                bail!("bad URL escape")
            }
            let hi = (bytes[i + 1] as char)
                .to_digit(16)
                .context("bad URL escape")? as u8;
            let lo = (bytes[i + 2] as char)
                .to_digit(16)
                .context("bad URL escape")? as u8;
            out.push((hi << 4) | lo);
            i += 3;
        } else if bytes[i] == b'+' {
            out.push(b' ');
            i += 1;
        } else {
            out.push(bytes[i]);
            i += 1;
        }
    }
    Ok(String::from_utf8(out)?)
}

async fn bind(path: &str) -> Result<UnixListener> {
    let path_ref = Path::new(path);
    let parent = path_ref
        .parent()
        .context("socket path has no parent directory")?;
    std::fs::create_dir_all(parent)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(parent, std::fs::Permissions::from_mode(0o700))?;
    }
    if let Ok(meta) = std::fs::symlink_metadata(path_ref) {
        use std::os::unix::fs::FileTypeExt;
        if !meta.file_type().is_socket() {
            bail!("refusing to replace non-socket control path {path:?}");
        }
        match timeout(Duration::from_millis(250), UnixStream::connect(path)).await {
            Ok(Ok(_)) => bail!("local control socket is already active: {path}"),
            _ => std::fs::remove_file(path_ref).context("remove stale control socket")?,
        }
    }
    let listener = UnixListener::bind(path_ref).with_context(|| format!("listen on {path}"))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path_ref, std::fs::Permissions::from_mode(0o600))?;
    }
    Ok(listener)
}

async fn read_request(stream: &mut UnixStream, body_limit: usize) -> Result<HttpRequest> {
    let mut bytes = Vec::new();
    let mut chunk = [0u8; 4096];
    let header_end = loop {
        if let Some(pos) = bytes.windows(4).position(|w| w == b"\r\n\r\n") {
            break pos + 4;
        }
        if bytes.len() >= MAX_HEADER {
            bail!("HTTP headers are too large");
        }
        let n = stream.read(&mut chunk).await?;
        if n == 0 {
            bail!("connection closed before headers");
        }
        bytes.extend_from_slice(&chunk[..n]);
        if bytes.len() > MAX_HEADER + body_limit {
            bail!("HTTP request is too large");
        }
    };
    if header_end > MAX_HEADER {
        bail!("HTTP headers are too large");
    }
    let headers = std::str::from_utf8(&bytes[..header_end])?;
    let mut lines = headers.split("\r\n");
    let (method, target) = parse_request_line(lines.next().unwrap_or_default())?;
    let mut length = 0usize;
    let mut saw_length = false;
    for line in lines {
        if line.is_empty() {
            continue;
        }
        let Some((name, value)) = line.split_once(':') else {
            bail!("invalid HTTP header")
        };
        if name.eq_ignore_ascii_case("transfer-encoding") {
            bail!("transfer encoding is not supported");
        }
        if name.eq_ignore_ascii_case("content-length") {
            if saw_length {
                bail!("duplicate content length");
            }
            length = value.trim().parse().context("invalid content length")?;
            saw_length = true;
        }
    }
    if length > body_limit {
        bail!("HTTP body is too large");
    }
    while bytes.len() - header_end < length {
        let n = stream.read(&mut chunk).await?;
        if n == 0 {
            bail!("connection closed before request body");
        }
        bytes.extend_from_slice(&chunk[..n]);
        if bytes.len() > header_end + length + 4096 {
            bail!("unexpected trailing request data");
        }
    }
    Ok(HttpRequest {
        method,
        target,
        body: bytes[header_end..header_end + length].to_vec(),
    })
}

fn parse_request_line(raw: &str) -> Result<(String, String)> {
    let mut fields = raw.split_whitespace();
    let method = fields.next().context("missing HTTP method")?;
    let target = fields.next().context("missing HTTP target")?;
    let version = fields.next().context("missing HTTP version")?;
    if !matches!(version, "HTTP/1.0" | "HTTP/1.1") || fields.next().is_some() {
        bail!("invalid HTTP request line");
    }
    Ok((method.to_owned(), target.to_owned()))
}

async fn respond_error(stream: &mut UnixStream, status: u16, message: &str) -> Result<()> {
    respond_json(stream, status, &json!({"ok": false, "message": message})).await
}

async fn respond_json(stream: &mut UnixStream, status: u16, value: &Value) -> Result<()> {
    let body = serde_json::to_vec(value)?;
    let label = match status {
        200 => "OK",
        400 => "Bad Request",
        404 => "Not Found",
        409 => "Conflict",
        503 => "Service Unavailable",
        _ => "Error",
    };
    let header = format!(
        "HTTP/1.1 {status} {label}\r\nContent-Type: application/json\r\nCache-Control: no-store\r\nConnection: close\r\nContent-Length: {}\r\n\r\n",
        body.len()
    );
    stream.write_all(header.as_bytes()).await?;
    stream.write_all(&body).await?;
    stream.shutdown().await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::parse_request_line;

    #[test]
    fn accepts_standard_http_1_request_lines() {
        assert_eq!(
            parse_request_line("GET /v1/inventory HTTP/1.1").unwrap(),
            ("GET".to_owned(), "/v1/inventory".to_owned())
        );
        assert_eq!(
            parse_request_line("POST /v1/firewall/policy HTTP/1.0").unwrap(),
            ("POST".to_owned(), "/v1/firewall/policy".to_owned())
        );
    }

    #[test]
    fn rejects_malformed_or_unsupported_http_request_lines() {
        assert!(parse_request_line("GET /v1/inventory").is_err());
        assert!(parse_request_line("GET /v1/inventory HTTP/2").is_err());
        assert!(parse_request_line("GET /v1/inventory HTTP/1.1 extra").is_err());
    }
}
