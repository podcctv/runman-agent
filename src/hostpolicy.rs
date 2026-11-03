//! Watcher-facing host firewall policy controller.
//!
//! Desired RFW rules are persisted with their ownership IDs, reconciled
//! against RFW's loopback API, and never claim or delete manually-created
//! rules. Container abuse rules are restricted to explicitly named Linux
//! bridges and an agent-owned firewall chain.

use std::collections::{BTreeMap, BTreeSet};
use std::net::{IpAddr, SocketAddr};
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result, bail};
use axum::body::{Body, to_bytes};
use hyper_util::client::legacy::Client;
use hyper_util::client::legacy::connect::HttpConnector;
use hyper_util::rt::TokioExecutor;
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value, json};
use tokio::process::Command;
use tracing::warn;

const MAX_RULES: usize = 64;
const ABUSE_CHAIN: &str = "RUNMAN_RS_RFW_ABUSE";
const ABUSE_MARKER: &str = "runman-agent-rs-v2-abuse";
const SUPPORTED_V010: &[&str] = &[
    "all",
    "tcp",
    "udp",
    "http",
    "tls",
    "socks",
    "ssh",
    "fet",
    "wireguard",
    "openvpn",
    "quic",
];

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Policy {
    pub revision: i64,
    #[serde(default)]
    pub rules: Vec<Rule>,
    #[serde(default)]
    pub abuse: AbusePolicy,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Rule {
    pub key: String,
    pub priority: i32,
    pub direction: String,
    pub protocol: String,
    pub action: String,
    pub enabled: bool,
    pub port_start: u16,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub port_end: Option<u16>,
    pub ip_type: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub ip: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub countries: Vec<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct AbusePolicy {
    #[serde(default)]
    pub speedtest: bool,
    #[serde(default)]
    pub mining: bool,
    #[serde(default)]
    pub bt: bool,
    #[serde(default)]
    pub interfaces: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Event {
    pub sequence: u64,
    pub cursor: String,
    pub observed_at: i64,
    pub source_ip: String,
    pub source_port: u16,
    pub destination_ip: String,
    pub destination_port: u16,
    pub transport: String,
    pub app_protocol: String,
    pub direction: String,
    pub action: String,
    pub rule_index: u8,
    pub rule_id: Option<u64>,
    pub rule_protocol: Option<String>,
    pub rule_action: Option<String>,
    #[serde(default)]
    pub rule_countries: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EventPage {
    pub instance_id: String,
    pub next_cursor: String,
    pub cursor_reset: bool,
    pub dropped: u64,
    pub dropped_total: u64,
    pub events: Vec<Event>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct RuleReadback {
    pub id: i32,
    pub priority: i32,
    pub direction: String,
    pub protocol: String,
    pub action: String,
    pub enabled: bool,
    pub port_start: u16,
    pub port_end: u16,
    pub ip_type: String,
    #[serde(default)]
    pub ip: String,
    #[serde(default)]
    pub countries: Vec<String>,
    pub origin: String,
    #[serde(default)]
    pub managed_key: String,
    pub sync_state: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExpectedRuleReadback {
    pub key: String,
    pub id: i32,
    pub sync_state: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Readback {
    pub status: String,
    pub observed_at: i64,
    #[serde(default)]
    pub rfw_api_version: String,
    pub capabilities_known: bool,
    pub supported_protocols: Vec<String>,
    pub policy_revision: i64,
    pub rule_count: usize,
    pub managed_rule_count: usize,
    pub drift_count: usize,
    pub missing_count: usize,
    pub rules: Vec<RuleReadback>,
    pub expected_rules: Vec<ExpectedRuleReadback>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct RawRule {
    id: i32,
    priority: i32,
    direction: String,
    protocol: String,
    action: String,
    enabled: bool,
    port_start: u16,
    #[serde(default)]
    port_end: u16,
    ip_type: String,
    #[serde(default)]
    ip: String,
    #[serde(default)]
    countries: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct ManagedRule {
    key: String,
    id: i32,
    fingerprint: String,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
struct State {
    #[serde(default)]
    revision: i64,
    #[serde(default)]
    policy: Policy,
    #[serde(default)]
    managed_rules: Vec<ManagedRule>,
}

pub struct Manager {
    path: PathBuf,
    base_url: String,
    client: Client<HttpConnector, Body>,
    state: tokio::sync::Mutex<State>,
}

impl Manager {
    pub fn new(path: PathBuf, addr: &str) -> Result<Self> {
        let socket: SocketAddr = addr
            .parse()
            .context("RFW address must be a loopback ip:port")?;
        if !socket.ip().is_loopback() || socket.port() == 0 {
            bail!("RFW API must use a loopback address and a valid port");
        }
        let state = load_state(&path)?;
        Ok(Self {
            path,
            base_url: format!("http://{socket}"),
            client: Client::builder(TokioExecutor::new()).build_http(),
            state: tokio::sync::Mutex::new(state),
        })
    }

    pub async fn apply(&self, requested: Policy) -> Result<String> {
        let policy = normalize_policy(requested)?;
        verify_bridges(&policy.abuse)?;
        let mut state = self.state.lock().await;
        if policy.revision < state.revision {
            bail!(
                "stale firewall policy revision {}; current revision is {}",
                policy.revision,
                state.revision
            );
        }
        if policy.revision == state.revision {
            if serde_json::to_vec(&policy)? != serde_json::to_vec(&state.policy)? {
                bail!("firewall policy changed without advancing its revision");
            }
        } else {
            state.revision = policy.revision;
            state.policy = policy;
            self.save(&state)?;
        }
        self.reconcile_rfw(&mut state).await?;
        apply_abuse(&state.policy.abuse).await?;
        Ok(summary(&state))
    }

    pub async fn reconcile(&self) -> Result<()> {
        let mut state = self.state.lock().await;
        if state.revision == 0 {
            return Ok(());
        }
        if let Err(e) = verify_bridges(&state.policy.abuse) {
            if let Err(cleanup) = apply_abuse(&AbusePolicy::default()).await {
                return Err(e.context(format!("remove stale abuse rules: {cleanup:#}")));
            }
            return Err(e);
        }
        self.reconcile_rfw(&mut state).await?;
        apply_abuse(&state.policy.abuse).await
    }

    pub async fn readback(&self) -> Result<Readback> {
        let state = self.state.lock().await;
        let rows = self.list_rules().await?;
        let (api_version, protocols, known) = self.capabilities().await.unwrap_or_default();
        let managed: BTreeMap<i32, &ManagedRule> =
            state.managed_rules.iter().map(|r| (r.id, r)).collect();
        let desired: BTreeMap<&str, &Rule> = state
            .policy
            .rules
            .iter()
            .map(|r| (r.key.as_str(), r))
            .collect();
        let actual: BTreeMap<i32, &RawRule> = rows.iter().map(|r| (r.id, r)).collect();
        let mut result = Readback {
            status: "in_sync".into(),
            observed_at: now(),
            rfw_api_version: api_version,
            capabilities_known: known,
            supported_protocols: protocols.into_iter().collect(),
            policy_revision: state.revision,
            rule_count: rows.len(),
            managed_rule_count: 0,
            drift_count: 0,
            missing_count: 0,
            rules: Vec::new(),
            expected_rules: Vec::new(),
        };
        for row in &rows {
            let mut item = readback_rule(row);
            if let Some(owner) = managed.get(&row.id) {
                item.origin = "platform".into();
                item.managed_key = owner.key.clone();
                item.sync_state = "orphaned".into();
                result.managed_rule_count += 1;
                if let Some(want) = desired.get(owner.key.as_str()) {
                    let expected = fingerprint(want)?;
                    if owner.fingerprint == expected && raw_matches(row, want) {
                        item.sync_state = "in_sync".into();
                    } else {
                        item.sync_state = "drifted".into();
                    }
                }
                if item.sync_state != "in_sync" {
                    result.drift_count += 1;
                    result.status = "drifted".into();
                }
            }
            result.rules.push(item);
        }
        for want in &state.policy.rules {
            let owner = state.managed_rules.iter().find(|r| r.key == want.key);
            let id = owner.map_or(0, |r| r.id);
            let want_fingerprint = fingerprint(want)?;
            let sync_state = match owner.and_then(|r| actual.get(&r.id).map(|actual| (r, *actual)))
            {
                None => "missing",
                Some((owner, actual))
                    if owner.fingerprint == want_fingerprint && raw_matches(actual, want) =>
                {
                    "in_sync"
                }
                Some(_) => "drifted",
            };
            if sync_state == "missing" {
                result.missing_count += 1;
                result.status = "drifted".into();
            } else if sync_state == "drifted" {
                result.drift_count += 1;
                result.status = "drifted".into();
            }
            result.expected_rules.push(ExpectedRuleReadback {
                key: want.key.clone(),
                id,
                sync_state: sync_state.into(),
            });
        }
        Ok(result)
    }

    pub async fn delete_manual_rule(&self, expected: RuleReadback) -> Result<()> {
        if expected.id < 1
            || expected.origin != "manual"
            || expected.sync_state != "manual"
            || !expected.managed_key.is_empty()
        {
            bail!("only a confirmed manual RFW rule can be deleted directly");
        }
        let state = self.state.lock().await;
        if state.managed_rules.iter().any(|r| r.id == expected.id) {
            bail!("platform-managed RFW rules must be removed from the desired policy");
        }
        let rows = self.list_rules().await?;
        let Some(current) = rows.iter().find(|r| r.id == expected.id) else {
            return Ok(());
        };
        if !same_readback(current, &expected) {
            bail!("manual RFW rule changed since readback; refresh before deleting");
        }
        let (body, status) = self
            .request("DELETE", &format!("/api/rules/{}", expected.id), None)
            .await?;
        if status != 200 && status != 204 && status != 404 {
            bail!("RFW delete returned HTTP {status}: {}", short_body(&body));
        }
        Ok(())
    }

    pub async fn events(&self, cursor: &str, limit: usize) -> Result<EventPage> {
        if cursor.len() > 160 || !(1..=100).contains(&limit) {
            bail!("invalid RFW event cursor or page size");
        }
        let (body, status) = self
            .request(
                "GET",
                &format!("/api/events?cursor={}&limit={limit}", url_encode(cursor)),
                None,
            )
            .await?;
        if status == 404 {
            bail!("RFW event API is not supported by this firewall build");
        }
        if status != 200 {
            bail!("RFW events returned HTTP {status}: {}", short_body(&body));
        }
        let page: EventPage = serde_json::from_slice(&body).context("decode RFW event page")?;
        if page.instance_id.is_empty()
            || page.instance_id.len() > 80
            || page.next_cursor.len() > 160
            || page.events.len() > limit
        {
            bail!("RFW event page exceeded its bounds");
        }
        for e in &page.events {
            if e.sequence == 0
                || e.observed_at <= 0
                || e.cursor.len() > 160
                || e.source_ip.parse::<IpAddr>().is_err()
                || e.destination_ip.parse::<IpAddr>().is_err()
                || !matches!(e.direction.as_str(), "in" | "out")
                || !matches!(e.action.as_str(), "pass" | "block")
                || !matches!(e.transport.as_str(), "tcp" | "udp" | "unknown")
                || e.rule_countries.len() > 30
            {
                bail!("RFW event has an invalid or unbounded field");
            }
        }
        Ok(page)
    }

    pub async fn summary(&self) -> String {
        let guard = self.state.lock().await;
        let state: &State = &guard;
        summary(state)
    }

    async fn reconcile_rfw(&self, state: &mut State) -> Result<()> {
        if state.policy.rules.is_empty() && state.managed_rules.is_empty() {
            return Ok(());
        }
        let (_, supported, known) = self.capabilities().await.unwrap_or_default();
        for rule in &state.policy.rules {
            if (known && !supported.contains(&rule.protocol))
                || (!known && rule.protocol == "mtproto")
            {
                bail!("RFW does not support protocol {:?}", rule.protocol);
            }
        }
        let mut actual = self.list_rules().await?;
        let mut selected = BTreeSet::new();
        for desired in &state.policy.rules {
            let fp = fingerprint(desired)?;
            let kept = state.managed_rules.iter().find(|owned| {
                !selected.contains(&owned.id)
                    && owned.key == desired.key
                    && owned.fingerprint == fp
                    && actual
                        .iter()
                        .any(|row| row.id == owned.id && raw_matches(row, desired))
            });
            if let Some(owned) = kept {
                selected.insert(owned.id);
                continue;
            }
            let body = serde_json::to_vec(&rfw_payload(desired))?;
            let (response, status) = self.request("POST", "/api/rules", Some(body)).await?;
            if !(200..300).contains(&status) {
                bail!(
                    "create RFW rule {:?} returned HTTP {status}: {}",
                    desired.key,
                    short_body(&response)
                );
            }
            let id = serde_json::from_slice::<Value>(&response)?
                .get("id")
                .and_then(Value::as_i64)
                .unwrap_or_default() as i32;
            if id < 1 {
                bail!("RFW create response did not include a valid rule ID");
            }
            state.managed_rules.push(ManagedRule {
                key: desired.key.clone(),
                id,
                fingerprint: fp,
            });
            selected.insert(id);
            actual.push(RawRule {
                id,
                priority: desired.priority,
                direction: desired.direction.clone(),
                protocol: desired.protocol.clone(),
                action: desired.action.clone(),
                enabled: desired.enabled,
                port_start: desired.port_start,
                port_end: desired.port_end.unwrap_or(0),
                ip_type: desired.ip_type.clone(),
                ip: desired.ip.clone(),
                countries: desired.countries.clone(),
            });
            self.save(state)?;
        }
        let mut i = 0;
        while i < state.managed_rules.len() {
            let owned = state.managed_rules[i].clone();
            if selected.contains(&owned.id) {
                i += 1;
                continue;
            }
            if actual.iter().any(|row| row.id == owned.id) {
                let (body, status) = self
                    .request("DELETE", &format!("/api/rules/{}", owned.id), None)
                    .await?;
                if status != 200 && status != 204 && status != 404 {
                    bail!(
                        "remove obsolete managed RFW rule {} returned HTTP {status}: {}",
                        owned.id,
                        short_body(&body)
                    );
                }
            }
            state.managed_rules.remove(i);
            self.save(state)?;
        }
        Ok(())
    }

    async fn list_rules(&self) -> Result<Vec<RawRule>> {
        let (body, status) = self.request("GET", "/api/rules", None).await?;
        if status != 200 {
            bail!("RFW list returned HTTP {status}: {}", short_body(&body));
        }
        let rows: Vec<RawRule> = serde_json::from_slice(&body).context("decode RFW rule list")?;
        if rows.len() > 256 {
            bail!("RFW rule list exceeds the 256-rule readback limit");
        }
        let mut ids = BTreeSet::new();
        if rows.iter().any(|row| row.id < 1 || !ids.insert(row.id)) {
            bail!("RFW rule list contains an invalid or duplicate ID");
        }
        Ok(rows)
    }

    async fn capabilities(&self) -> Result<(String, BTreeSet<String>, bool)> {
        let (body, status) = self.request("GET", "/api/status", None).await?;
        if status != 200 {
            return Ok((String::new(), BTreeSet::new(), false));
        }
        let value: Value = serde_json::from_slice(&body).context("decode RFW status")?;
        let version = value
            .get("api_version")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .trim()
            .to_owned();
        if version.is_empty() || version.len() > 64 {
            return Ok((version, BTreeSet::new(), false));
        }
        if let Some(protocols) = value.get("supported_protocols").and_then(Value::as_array) {
            let parsed: BTreeSet<String> = protocols
                .iter()
                .filter_map(Value::as_str)
                .map(str::to_ascii_lowercase)
                .collect();
            if parsed.is_empty() || parsed.len() > 32 {
                return Ok((version, parsed, false));
            }
            return Ok((version, parsed, true));
        }
        if version == "0.1.0" {
            return Ok((
                version,
                SUPPORTED_V010.iter().map(|p| (*p).to_owned()).collect(),
                true,
            ));
        }
        Ok((version, BTreeSet::new(), false))
    }

    async fn request(
        &self,
        method: &str,
        path: &str,
        body: Option<Vec<u8>>,
    ) -> Result<(Vec<u8>, u16)> {
        let uri = format!("{}{}", self.base_url, path);
        let mut builder = axum::http::Request::builder().method(method).uri(uri);
        if body.is_some() {
            builder = builder.header("content-type", "application/json");
        }
        let req = builder.body(Body::from(body.unwrap_or_default()))?;
        let response = tokio::time::timeout(Duration::from_secs(5), self.client.request(req))
            .await
            .context("RFW API timed out")??;
        let status = response.status().as_u16();
        let bytes = to_bytes(Body::new(response.into_body()), 64 * 1024)
            .await
            .context("read RFW response")?;
        Ok((bytes.to_vec(), status))
    }

    fn save(&self, state: &State) -> Result<()> {
        save_state(&self.path, state)
    }
}

pub async fn reconcile_loop(manager: std::sync::Arc<Manager>) {
    let mut tick = tokio::time::interval(Duration::from_secs(30));
    tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    loop {
        tick.tick().await;
        if let Err(e) = manager.reconcile().await {
            warn!("host firewall reconciliation incomplete: {e:#}");
        }
    }
}

fn normalize_policy(mut policy: Policy) -> Result<Policy> {
    if policy.revision < 1 || policy.rules.len() > MAX_RULES {
        bail!("policy revision must be positive and at most {MAX_RULES} RFW rules are allowed");
    }
    let mut keys = BTreeSet::new();
    for rule in &mut policy.rules {
        if rule.key.is_empty()
            || rule.key.len() > 80
            || !rule
                .key
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'-'))
            || !keys.insert(rule.key.clone())
        {
            bail!("RFW rule has a missing, invalid, or duplicate key");
        }
        rule.protocol = rule.protocol.to_ascii_lowercase();
        rule.ip_type = rule.ip_type.to_ascii_lowercase();
        if !(0..=100_000).contains(&rule.priority)
            || !matches!(rule.direction.as_str(), "in" | "out")
            || !matches!(rule.action.as_str(), "block" | "pass")
            || !matches!(
                rule.protocol.as_str(),
                "all"
                    | "tcp"
                    | "udp"
                    | "http"
                    | "tls"
                    | "socks"
                    | "ssh"
                    | "fet"
                    | "wireguard"
                    | "openvpn"
                    | "quic"
                    | "mtproto"
            )
            || (rule.direction == "out"
                && !matches!(
                    rule.protocol.as_str(),
                    "all" | "tcp" | "udp" | "socks" | "fet" | "wireguard" | "mtproto"
                ))
            || rule.port_end.is_some_and(|end| end < rule.port_start)
        {
            bail!(
                "RFW rule {:?} has invalid direction, protocol, action, priority, or port range",
                rule.key
            );
        }
        if rule.port_end == Some(rule.port_start) {
            rule.port_end = None;
        }
        match rule.ip_type.as_str() {
            "any" => {
                rule.ip.clear();
                rule.countries.clear();
            }
            "cidr" => {
                rule.ip = normalize_cidr(&rule.ip)?;
                rule.countries.clear();
            }
            "geoip" => {
                if rule.countries.is_empty() || rule.countries.len() > 30 {
                    bail!("RFW geoip rule requires 1 to 30 country codes");
                }
                let mut countries = BTreeSet::new();
                for c in &rule.countries {
                    let c = c.trim().to_ascii_uppercase();
                    if c.len() != 2 || !c.bytes().all(|b| b.is_ascii_uppercase()) {
                        bail!("RFW rule {:?} has an invalid country code", rule.key);
                    }
                    countries.insert(c);
                }
                rule.countries = countries.into_iter().collect();
                rule.ip.clear();
            }
            _ => bail!("RFW rule {:?} has an unsupported IP type", rule.key),
        }
    }
    if policy.abuse.interfaces.len() > 16 {
        bail!("at most 16 container bridge interfaces are allowed");
    }
    let mut interfaces = BTreeSet::new();
    for iface in &policy.abuse.interfaces {
        if iface.is_empty()
            || iface.len() > 15
            || !iface
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'-' | b'.'))
        {
            bail!("invalid container bridge interface {iface:?}");
        }
        interfaces.insert(iface.clone());
    }
    policy.abuse.interfaces = interfaces.into_iter().collect();
    if (policy.abuse.speedtest || policy.abuse.mining || policy.abuse.bt)
        && policy.abuse.interfaces.is_empty()
    {
        bail!("container abuse rules require an explicit bridge interface");
    }
    Ok(policy)
}

fn verify_bridges(policy: &AbusePolicy) -> Result<()> {
    if !(policy.speedtest || policy.mining || policy.bt) {
        return Ok(());
    }
    for iface in &policy.interfaces {
        if !Path::new("/sys/class/net")
            .join(iface)
            .join("bridge")
            .exists()
        {
            bail!("{iface:?} is not an existing Linux bridge; no host firewall changes were made");
        }
    }
    Ok(())
}

fn rfw_payload(rule: &Rule) -> Value {
    let mut m = Map::new();
    m.insert("priority".into(), json!(rule.priority));
    m.insert("direction".into(), json!(rule.direction));
    m.insert("protocol".into(), json!(rule.protocol));
    m.insert("action".into(), json!(rule.action));
    m.insert("enabled".into(), json!(rule.enabled));
    m.insert("port_start".into(), json!(rule.port_start));
    m.insert("ip_type".into(), json!(rule.ip_type));
    if let Some(end) = rule.port_end {
        m.insert("port_end".into(), json!(end));
    }
    if rule.ip_type == "cidr" {
        m.insert("ip".into(), json!(rule.ip));
    }
    if rule.ip_type == "geoip" {
        m.insert("countries".into(), json!(rule.countries));
    }
    Value::Object(m)
}

fn fingerprint(rule: &Rule) -> Result<String> {
    Ok(serde_json::to_string(&rfw_payload(rule))?)
}

fn raw_matches(raw: &RawRule, want: &Rule) -> bool {
    let raw_countries: BTreeSet<String> = raw
        .countries
        .iter()
        .map(|country| country.trim().to_ascii_uppercase())
        .collect();
    let wanted_countries: BTreeSet<String> = want
        .countries
        .iter()
        .map(|country| country.trim().to_ascii_uppercase())
        .collect();
    raw.priority == want.priority
        && raw.direction.eq_ignore_ascii_case(&want.direction)
        && raw.protocol.eq_ignore_ascii_case(&want.protocol)
        && raw.action.eq_ignore_ascii_case(&want.action)
        && raw.enabled == want.enabled
        && raw.port_start == want.port_start
        && (if raw.port_end == raw.port_start {
            want.port_end.is_none() || want.port_end == Some(want.port_start)
        } else {
            want.port_end == Some(raw.port_end)
        })
        && raw.ip_type.eq_ignore_ascii_case(&want.ip_type)
        && (want.ip_type != "cidr" || raw.ip.trim() == want.ip)
        && (want.ip_type != "geoip" || raw_countries == wanted_countries)
}

fn readback_rule(raw: &RawRule) -> RuleReadback {
    RuleReadback {
        id: raw.id,
        priority: raw.priority,
        direction: raw.direction.to_ascii_lowercase(),
        protocol: raw.protocol.to_ascii_lowercase(),
        action: raw.action.to_ascii_lowercase(),
        enabled: raw.enabled,
        port_start: raw.port_start,
        port_end: raw.port_end,
        ip_type: raw.ip_type.to_ascii_lowercase(),
        ip: raw.ip.clone(),
        countries: raw.countries.clone(),
        origin: "manual".into(),
        managed_key: String::new(),
        sync_state: "manual".into(),
    }
}

fn same_readback(raw: &RawRule, expected: &RuleReadback) -> bool {
    let current = readback_rule(raw);
    current.id == expected.id
        && current.priority == expected.priority
        && current.direction == expected.direction
        && current.protocol == expected.protocol
        && current.action == expected.action
        && current.enabled == expected.enabled
        && current.port_start == expected.port_start
        && current.port_end == expected.port_end
        && current.ip_type == expected.ip_type
        && current.ip == expected.ip
        && current.countries == expected.countries
}

fn summary(state: &State) -> String {
    let mut enabled = Vec::new();
    if state.policy.abuse.speedtest {
        enabled.push("speedtest");
    }
    if state.policy.abuse.mining {
        enabled.push("mining");
    }
    if state.policy.abuse.bt {
        enabled.push("bt");
    }
    format!(
        "policy_revision={}; managed_rfw_rules={}; abuse_ports={}",
        state.revision,
        state.policy.rules.len(),
        if enabled.is_empty() {
            "none".into()
        } else {
            enabled.join(",")
        }
    )
}

async fn apply_abuse(policy: &AbusePolicy) -> Result<()> {
    apply_abuse_family("iptables", policy).await?;
    if std::fs::read_to_string("/proc/sys/net/ipv6/conf/all/disable_ipv6")
        .is_ok_and(|s| s.trim() != "1")
    {
        apply_abuse_family("ip6tables", policy).await?;
    }
    Ok(())
}

async fn apply_abuse_family(tool: &str, policy: &AbusePolicy) -> Result<()> {
    let enabled = policy.speedtest || policy.mining || policy.bt;
    let existing = fw_output(tool, &["-S", ABUSE_CHAIN]).await;
    if let Ok(lines) = &existing {
        if !lines.contains(ABUSE_MARKER) {
            bail!("refusing to modify an existing unowned firewall chain");
        }
    }
    if !enabled {
        if existing.is_err() {
            return Ok(());
        }
        while fw_command(tool, &["-C", "FORWARD", "-j", ABUSE_CHAIN])
            .await
            .is_ok()
        {
            fw_command(tool, &["-D", "FORWARD", "-j", ABUSE_CHAIN]).await?;
        }
        fw_command(tool, &["-F", ABUSE_CHAIN]).await?;
        fw_command(tool, &["-X", ABUSE_CHAIN]).await?;
        return Ok(());
    }
    if existing.is_err() {
        fw_command(tool, &["-N", ABUSE_CHAIN]).await?;
        fw_command(
            tool,
            &[
                "-A",
                ABUSE_CHAIN,
                "-m",
                "comment",
                "--comment",
                ABUSE_MARKER,
                "-j",
                "RETURN",
            ],
        )
        .await?;
    } else {
        fw_command(tool, &["-F", ABUSE_CHAIN]).await?;
        fw_command(
            tool,
            &[
                "-A",
                ABUSE_CHAIN,
                "-m",
                "comment",
                "--comment",
                ABUSE_MARKER,
                "-j",
                "RETURN",
            ],
        )
        .await?;
    }
    for iface in &policy.interfaces {
        if policy.speedtest {
            insert_abuse(
                tool,
                iface,
                &[
                    "-p",
                    "tcp",
                    "--dport",
                    "5201",
                    "-j",
                    "REJECT",
                    "--reject-with",
                    "tcp-reset",
                ],
            )
            .await?;
            insert_abuse(tool, iface, &["-p", "udp", "--dport", "5201", "-j", "DROP"]).await?;
        }
        if policy.mining {
            insert_abuse(
                tool,
                iface,
                &[
                    "-p",
                    "tcp",
                    "-m",
                    "multiport",
                    "--dports",
                    "3333,4444,5555,6666,7777,8888,9999,14433,14444",
                    "-j",
                    "REJECT",
                    "--reject-with",
                    "tcp-reset",
                ],
            )
            .await?;
        }
        if policy.bt {
            for protocol in ["tcp", "udp"] {
                for ports in ["6881:6889", "6969", "51413", "4662,4672"] {
                    if ports.contains(',') {
                        insert_abuse(
                            tool,
                            iface,
                            &[
                                "-p",
                                protocol,
                                "-m",
                                "multiport",
                                "--dports",
                                ports,
                                "-j",
                                "DROP",
                            ],
                        )
                        .await?;
                    } else {
                        insert_abuse(
                            tool,
                            iface,
                            &["-p", protocol, "--dport", ports, "-j", "DROP"],
                        )
                        .await?;
                    }
                }
            }
        }
    }
    if fw_command(tool, &["-C", "FORWARD", "-j", ABUSE_CHAIN])
        .await
        .is_err()
    {
        fw_command(tool, &["-I", "FORWARD", "1", "-j", ABUSE_CHAIN]).await?;
    }
    Ok(())
}

async fn insert_abuse(tool: &str, iface: &str, rest: &[&str]) -> Result<()> {
    let mut args = vec!["-I", ABUSE_CHAIN, "1", "-i", iface];
    args.extend_from_slice(rest);
    fw_command(tool, &args).await
}

async fn fw_command(tool: &str, args: &[&str]) -> Result<()> {
    let mut full = vec!["-w", "5", "-t", "filter"];
    full.extend_from_slice(args);
    let out = Command::new(tool)
        .args(&full)
        .output()
        .await
        .with_context(|| format!("run {tool}"))?;
    if !out.status.success() {
        bail!(
            "{tool} {} failed: {}",
            full.join(" "),
            String::from_utf8_lossy(&out.stderr).trim()
        );
    }
    Ok(())
}

async fn fw_output(tool: &str, args: &[&str]) -> Result<String> {
    let mut full = vec!["-w", "5", "-t", "filter"];
    full.extend_from_slice(args);
    let out = Command::new(tool)
        .args(&full)
        .output()
        .await
        .with_context(|| format!("run {tool}"))?;
    if !out.status.success() {
        bail!("{tool} {} failed", full.join(" "));
    }
    Ok(String::from_utf8_lossy(&out.stdout).into_owned())
}

fn load_state(path: &Path) -> Result<State> {
    match std::fs::read(path) {
        Ok(data) => {
            let mut state: State =
                serde_json::from_slice(&data).context("decode persisted host firewall policy")?;
            if state.revision > 0 {
                let policy = normalize_policy(state.policy.clone())
                    .context("persisted host firewall policy is invalid")?;
                if policy.revision != state.revision {
                    bail!("persisted host firewall policy revision mismatch");
                }
                state.policy = policy;
            }
            if state
                .managed_rules
                .iter()
                .any(|r| r.key.is_empty() || r.id < 1 || r.fingerprint.is_empty())
            {
                bail!("persisted managed RFW rule ownership is invalid");
            }
            Ok(state)
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(State::default()),
        Err(e) => Err(e.into()),
    }
}

fn save_state(path: &Path, state: &State) -> Result<()> {
    let dir = path
        .parent()
        .context("host firewall state has no parent directory")?;
    std::fs::create_dir_all(dir)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700))?;
    }
    let temp = dir.join(format!(".host-firewall-{}.tmp", uuid::Uuid::new_v4()));
    let bytes = serde_json::to_vec_pretty(state)?;
    {
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&temp)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            file.set_permissions(std::fs::Permissions::from_mode(0o600))?;
        }
        use std::io::Write;
        file.write_all(&bytes)?;
        file.sync_all()?;
    }
    std::fs::rename(&temp, path).with_context(|| format!("replace {}", path.display()))
}

fn now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs() as i64)
}

fn normalize_cidr(value: &str) -> Result<String> {
    let (address, prefix) = value
        .trim()
        .split_once('/')
        .context("RFW CIDR rule requires a valid CIDR")?;
    let prefix: u8 = prefix.parse().context("invalid CIDR prefix length")?;
    let ip: IpAddr = address.parse().context("invalid CIDR address")?;
    match ip {
        IpAddr::V4(ip) if prefix <= 32 => {
            let mask = if prefix == 0 {
                0
            } else {
                u32::MAX << (32 - u32::from(prefix))
            };
            Ok(format!(
                "{}/{}",
                std::net::Ipv4Addr::from(u32::from(ip) & mask),
                prefix
            ))
        }
        IpAddr::V6(ip) if prefix <= 128 => {
            let mask = if prefix == 0 {
                0
            } else {
                u128::MAX << (128 - u32::from(prefix))
            };
            Ok(format!(
                "{}/{}",
                std::net::Ipv6Addr::from(u128::from(ip) & mask),
                prefix
            ))
        }
        _ => bail!("CIDR prefix length is out of range"),
    }
}

fn short_body(body: &[u8]) -> String {
    let text = String::from_utf8_lossy(body);
    text.chars().take(300).collect()
}

fn url_encode(s: &str) -> String {
    let mut out = String::new();
    for b in s.bytes() {
        if b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.' | b'~') {
            out.push(b as char);
        } else {
            out.push_str(&format!("%{b:02X}"));
        }
    }
    out
}
