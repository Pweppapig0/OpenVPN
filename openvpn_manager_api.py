#!/usr/bin/env python3
import ipaddress
import json
import os
import re
import secrets
import socket
import sqlite3
import subprocess
import sys
import uuid
from datetime import datetime, timezone
from functools import wraps
from pathlib import Path

from flask import Flask, Response, jsonify, request


APP_VERSION = "0.1.0"
CONFIG_PATH = Path(os.environ.get("PAYMENTER_OPENVPN_CONFIG", "/etc/paymenter-openvpn-manager/config.json"))
app = Flask(__name__)


def ensure_permissions(path: Path, mode: int, directory: bool = False) -> None:
    if not path.exists():
        return

    try:
        os.chmod(path, mode)
    except PermissionError:
        pass

    if directory:
        try:
            current_mode = path.stat().st_mode & 0o7777
        except PermissionError:
            return
        if current_mode != mode:
            try:
                os.chmod(path, mode)
            except PermissionError:
                pass


def utcnow_iso() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def load_config() -> dict:
    if not CONFIG_PATH.exists():
        raise RuntimeError(f"Missing configuration file: {CONFIG_PATH}")

    data = json.loads(CONFIG_PATH.read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise RuntimeError("Configuration file must contain a JSON object")
    return data


def db_path() -> Path:
    cfg = load_config()
    return Path(cfg.get("database_path", "/var/lib/paymenter-openvpn-manager/manager.db"))


def connect_db() -> sqlite3.Connection:
    path = db_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    ensure_permissions(path.parent, 0o2775, directory=True)
    conn = sqlite3.connect(path)
    conn.row_factory = sqlite3.Row
    ensure_permissions(path, 0o664)
    return conn


def init_db() -> None:
    with connect_db() as conn:
        conn.executescript(
            """
            CREATE TABLE IF NOT EXISTS clients (
                id TEXT PRIMARY KEY,
                service_ref TEXT NOT NULL,
                profile_slug TEXT NOT NULL,
                common_name TEXT NOT NULL UNIQUE,
                display_name TEXT NOT NULL,
                download_name TEXT NOT NULL,
                dns_servers_json TEXT NOT NULL DEFAULT '[]',
                redirect_gateway INTEGER NOT NULL DEFAULT 1,
                route_networks_json TEXT NOT NULL DEFAULT '[]',
                extra_pushes_json TEXT NOT NULL DEFAULT '[]',
                disabled INTEGER NOT NULL DEFAULT 0,
                disabled_reason TEXT NOT NULL DEFAULT '',
                revoked INTEGER NOT NULL DEFAULT 0,
                total_bytes_received INTEGER NOT NULL DEFAULT 0,
                total_bytes_sent INTEGER NOT NULL DEFAULT 0,
                last_connected_at TEXT,
                last_disconnected_at TEXT,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
            );
            CREATE UNIQUE INDEX IF NOT EXISTS idx_clients_service_slug
                ON clients(service_ref, profile_slug);
            """
        )


def json_list(value) -> list[str]:
    if isinstance(value, list):
        result = []
        for item in value:
            text = str(item).strip()
            if text:
                result.append(text)
        return result
    return []


def bool_from_value(value, default=False) -> bool:
    if isinstance(value, bool):
        return value
    if isinstance(value, (int, float)):
        return int(value) != 0
    if isinstance(value, str):
        normalized = value.strip().lower()
        if normalized in {"1", "true", "yes", "on"}:
            return True
        if normalized in {"0", "false", "no", "off"}:
            return False
    return default


def slugify(value: str, fallback: str = "profile") -> str:
    text = re.sub(r"[^a-zA-Z0-9._-]+", "-", value.strip().lower())
    text = text.strip("-_.")
    return text or fallback


def cert_path(common_name: str) -> Path:
    cfg = load_config()
    template = str(cfg["cert_path_template"])
    return Path(template.format(common_name=common_name))


def key_path(common_name: str) -> Path:
    cfg = load_config()
    template = str(cfg["key_path_template"])
    return Path(template.format(common_name=common_name))


def ccd_path(common_name: str) -> Path:
    cfg = load_config()
    return Path(cfg["ccd_dir"]) / common_name


def load_client_by_id(client_id: str):
    with connect_db() as conn:
        return conn.execute("SELECT * FROM clients WHERE id = ?", (client_id,)).fetchone()


def load_client_by_service_slug(service_ref: str, profile_slug: str):
    with connect_db() as conn:
        return conn.execute(
            "SELECT * FROM clients WHERE service_ref = ? AND profile_slug = ?",
            (service_ref, profile_slug),
        ).fetchone()


def save_client(row: dict) -> None:
    now = utcnow_iso()
    row["updated_at"] = now
    if "created_at" not in row:
        row["created_at"] = now

    with connect_db() as conn:
        conn.execute(
            """
            INSERT INTO clients (
                id, service_ref, profile_slug, common_name, display_name, download_name,
                dns_servers_json, redirect_gateway, route_networks_json, extra_pushes_json,
                disabled, disabled_reason, revoked, total_bytes_received, total_bytes_sent,
                last_connected_at, last_disconnected_at, created_at, updated_at
            ) VALUES (
                :id, :service_ref, :profile_slug, :common_name, :display_name, :download_name,
                :dns_servers_json, :redirect_gateway, :route_networks_json, :extra_pushes_json,
                :disabled, :disabled_reason, :revoked, :total_bytes_received, :total_bytes_sent,
                :last_connected_at, :last_disconnected_at, :created_at, :updated_at
            )
            ON CONFLICT(id) DO UPDATE SET
                service_ref = excluded.service_ref,
                profile_slug = excluded.profile_slug,
                common_name = excluded.common_name,
                display_name = excluded.display_name,
                download_name = excluded.download_name,
                dns_servers_json = excluded.dns_servers_json,
                redirect_gateway = excluded.redirect_gateway,
                route_networks_json = excluded.route_networks_json,
                extra_pushes_json = excluded.extra_pushes_json,
                disabled = excluded.disabled,
                disabled_reason = excluded.disabled_reason,
                revoked = excluded.revoked,
                total_bytes_received = excluded.total_bytes_received,
                total_bytes_sent = excluded.total_bytes_sent,
                last_connected_at = excluded.last_connected_at,
                last_disconnected_at = excluded.last_disconnected_at,
                updated_at = excluded.updated_at
            """,
            row,
        )


def delete_client_record(client_id: str) -> None:
    with connect_db() as conn:
        conn.execute("DELETE FROM clients WHERE id = ?", (client_id,))


def row_to_dict(row: sqlite3.Row) -> dict:
    data = dict(row)
    data["dns_servers"] = json_list(json.loads(data.get("dns_servers_json") or "[]"))
    data["route_networks"] = json_list(json.loads(data.get("route_networks_json") or "[]"))
    data["extra_pushes"] = json_list(json.loads(data.get("extra_pushes_json") or "[]"))
    data["redirect_gateway"] = bool(data.get("redirect_gateway"))
    data["disabled"] = bool(data.get("disabled"))
    data["revoked"] = bool(data.get("revoked"))
    data.pop("dns_servers_json", None)
    data.pop("route_networks_json", None)
    data.pop("extra_pushes_json", None)
    return data


def ensure_auth():
    cfg = load_config()
    expected = str(cfg.get("api_token", "")).strip()
    provided = request.headers.get("Authorization", "")
    token = ""
    if provided.lower().startswith("bearer "):
        token = provided[7:].strip()
    if expected == "" or token != expected:
        return jsonify({"error": "unauthorized"}), 401
    return None


def require_auth(fn):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        auth_result = ensure_auth()
        if auth_result is not None:
            return auth_result
        return fn(*args, **kwargs)

    return wrapper


def run_command(args, cwd=None, env=None):
    completed = subprocess.run(
        args,
        cwd=cwd,
        env=env,
        text=True,
        capture_output=True,
        check=False,
    )
    if completed.returncode != 0:
        raise RuntimeError((completed.stderr or completed.stdout or "command failed").strip())
    return completed


def easyrsa_env() -> dict:
    env = os.environ.copy()
    env["EASYRSA_BATCH"] = "1"
    return env


def ensure_client_certificate(common_name: str) -> None:
    cfg = load_config()
    cert = cert_path(common_name)
    key = key_path(common_name)
    if cert.exists() and key.exists():
        return

    run_command(
        ["./easyrsa", "build-client-full", common_name, "nopass"],
        cwd=cfg["easyrsa_dir"],
        env=easyrsa_env(),
    )


def revoke_client_certificate(common_name: str) -> None:
    cfg = load_config()
    easyrsa_dir = cfg["easyrsa_dir"]
    env = easyrsa_env()

    try:
        run_command(["./easyrsa", "revoke", common_name], cwd=easyrsa_dir, env=env)
    except RuntimeError as exc:
        message = str(exc).lower()
        if "already revoked" not in message and "unable to revoke as the input file does not exist" not in message:
            raise

    run_command(["./easyrsa", "gen-crl"], cwd=easyrsa_dir, env=env)
    source_crl = Path(easyrsa_dir) / "pki" / "crl.pem"
    target_crl = Path(cfg["crl_path"])
    target_crl.write_bytes(source_crl.read_bytes())
    os.chmod(target_crl, 0o644)


def normalize_push_directive(raw: str) -> str | None:
    text = raw.strip()
    if not text:
        return None
    if text.startswith("push "):
        return text
    if text.startswith('"') and text.endswith('"'):
        return f"push {text}"
    return f'push "{text}"'


def write_ccd(common_name: str, dns_servers: list[str], redirect_gateway: bool, route_networks: list[str], extra_pushes: list[str]) -> None:
    lines = ["push-reset"]

    if redirect_gateway:
        lines.append('push "redirect-gateway def1 bypass-dhcp"')

    for dns in dns_servers:
        lines.append(f'push "dhcp-option DNS {dns}"')

    for cidr in route_networks:
        network = ipaddress.ip_network(cidr, strict=False)
        lines.append(f'push "route {network.network_address} {network.netmask}"')

    for push in extra_pushes:
        normalized = normalize_push_directive(push)
        if normalized:
            lines.append(normalized)

    target = ccd_path(common_name)
    target.parent.mkdir(parents=True, exist_ok=True)
    ensure_permissions(target.parent, 0o755, directory=True)
    target.write_text("\n".join(lines) + "\n", encoding="utf-8")
    ensure_permissions(target, 0o644)


def row_dns_servers(row: dict, cfg: dict) -> list[str]:
    dns_servers = json_list(row.get("dns_servers"))
    if dns_servers:
        return dns_servers
    return json_list(cfg.get("default_dns_servers"))


def row_route_networks(row: dict) -> list[str]:
    return json_list(row.get("route_networks"))


def row_redirect_gateway(row: dict, cfg: dict) -> bool:
    if "redirect_gateway" in row:
        return bool_from_value(row.get("redirect_gateway"), True)
    return bool_from_value(cfg.get("default_redirect_gateway"), True)


def build_client_config(common_name: str, row: dict) -> str:
    cfg = load_config()
    ca_text = Path(cfg["ca_path"]).read_text(encoding="utf-8").strip()
    cert_text = cert_path(common_name).read_text(encoding="utf-8").strip()
    key_text = key_path(common_name).read_text(encoding="utf-8").strip()
    tls_crypt_text = Path(cfg["tls_crypt_path"]).read_text(encoding="utf-8").strip()
    redirect_gateway = row_redirect_gateway(row, cfg)
    dns_servers = row_dns_servers(row, cfg)
    route_networks = row_route_networks(row)

    lines = [
        "client",
        "dev tun",
        "topology subnet",
        f"proto {cfg['protocol']}",
        f"remote {cfg['public_host']} {cfg['port']}",
        "nobind",
        "persist-key",
        "persist-tun",
        "pull",
        "route-delay 5",
        "resolv-retry infinite",
        "remote-cert-tls server",
        "auth-nocache",
        "verb 3",
        f"cipher {cfg['cipher']}",
        f"data-ciphers {cfg['data_ciphers']}",
        f"auth {cfg['auth']}",
        "key-direction 1",
    ]

    if redirect_gateway:
        lines.append("redirect-gateway def1 bypass-dhcp")

    for dns in dns_servers:
        lines.append(f"dhcp-option DNS {dns}")

    for cidr in route_networks:
        network = ipaddress.ip_network(cidr, strict=False)
        lines.append(f"route {network.network_address} {network.netmask}")

    lines.extend(
        [
            "",
            "<ca>",
            ca_text,
            "</ca>",
            "<cert>",
            cert_text,
            "</cert>",
            "<key>",
            key_text,
            "</key>",
            "<tls-crypt>",
            tls_crypt_text,
            "</tls-crypt>",
            "",
        ]
    )
    return "\n".join(lines)


def management_command(command: str) -> str:
    cfg = load_config()
    host = cfg.get("management_host", "127.0.0.1")
    port = int(cfg.get("management_port", 7505))

    with socket.create_connection((host, port), timeout=5) as sock:
        sock.settimeout(5)
        sock.sendall((command.strip() + "\nquit\n").encode("utf-8"))
        chunks = []
        while True:
            try:
                chunk = sock.recv(4096)
            except TimeoutError:
                break
            if not chunk:
                break
            chunks.append(chunk)
    return b"".join(chunks).decode("utf-8", errors="ignore")


def disconnect_active_client(common_name: str) -> None:
    try:
        management_command(f"kill {common_name}")
    except OSError:
        pass


def parse_status_text(status_text: str) -> dict[str, dict]:
    if not status_text.strip():
        return {}

    headers = {}
    sessions = {}
    for raw_line in status_text.splitlines():
        line = raw_line.strip()
        if not line:
            continue

        parts = line.split(",")
        if len(parts) < 2:
            continue

        if parts[0] == "HEADER":
            headers[parts[1]] = parts[2:]
            continue

        if parts[0] != "CLIENT_LIST":
            continue

        columns = headers.get("CLIENT_LIST", [])
        values = parts[1:]
        row = {}
        for idx, column in enumerate(columns):
            row[column] = values[idx] if idx < len(values) else ""

        common_name = str(row.get("Common Name", "") or row.get("Common name", "")).strip()
        if not common_name:
            continue

        current = sessions.setdefault(
            common_name,
            {
                "connected": True,
                "bytes_received": 0,
                "bytes_sent": 0,
                "connected_since": None,
                "remote_address": None,
                "virtual_address": None,
            },
        )

        try:
            current["bytes_received"] += int(row.get("Bytes Received", "0") or 0)
        except ValueError:
            pass
        try:
            current["bytes_sent"] += int(row.get("Bytes Sent", "0") or 0)
        except ValueError:
            pass

        connected_since = row.get("Connected Since")
        if connected_since:
            current["connected_since"] = connected_since

        remote_address = row.get("Real Address") or row.get("Real address")
        if remote_address:
            current["remote_address"] = remote_address

        virtual_address = (
            row.get("Virtual Address")
            or row.get("Virtual IPv4 Address")
            or row.get("Virtual IPv6 Address")
            or row.get("Virtual address")
        )
        if virtual_address:
            current["virtual_address"] = virtual_address

    return sessions


def parse_status() -> dict[str, dict]:
    try:
        management_status = management_command("status 3")
        sessions = parse_status_text(management_status)
        if sessions:
            return sessions
    except OSError:
        pass
    except Exception:
        pass

    cfg = load_config()
    status_file = Path(cfg.get("status_file", "/var/lib/paymenter-openvpn-manager/openvpn-status.log"))
    if not status_file.exists():
        return {}

    return parse_status_text(status_file.read_text(encoding="utf-8", errors="ignore"))


def usage_payload(row: sqlite3.Row) -> dict:
    data = row_to_dict(row)
    live_sessions = parse_status()
    live = live_sessions.get(data["common_name"], {})
    download_bytes = int(data["total_bytes_received"] or 0) + int(live.get("bytes_received") or 0)
    upload_bytes = int(data["total_bytes_sent"] or 0) + int(live.get("bytes_sent") or 0)
    last_connected_at = data.get("last_connected_at")
    last_disconnected_at = data.get("last_disconnected_at")

    optimistic_connected = False
    if not live and last_connected_at:
        try:
            connected_dt = datetime.fromisoformat(str(last_connected_at).replace("Z", "+00:00"))
            disconnected_dt = None
            if last_disconnected_at:
                disconnected_dt = datetime.fromisoformat(str(last_disconnected_at).replace("Z", "+00:00"))

            if disconnected_dt is None or connected_dt > disconnected_dt:
                optimistic_connected = True
        except ValueError:
            optimistic_connected = False

    return {
        "id": data["id"],
        "service_ref": data["service_ref"],
        "profile_slug": data["profile_slug"],
        "display_name": data["display_name"],
        "common_name": data["common_name"],
        "download_name": data["download_name"],
        "download_bytes": download_bytes,
        "upload_bytes": upload_bytes,
        "connected": bool(live) or optimistic_connected,
        "connected_since": live.get("connected_since") or last_connected_at,
        "remote_address": live.get("remote_address"),
        "virtual_address": live.get("virtual_address"),
        "disabled": data["disabled"],
        "disabled_reason": data["disabled_reason"] or None,
        "revoked": data["revoked"],
    }


def validate_client_payload(payload: dict) -> dict:
    service_ref = str(payload.get("service_ref", "")).strip()
    display_name = str(payload.get("display_name", "")).strip()
    profile_slug = slugify(str(payload.get("profile_slug", "")).strip() or display_name or service_ref)
    dns_servers = json_list(payload.get("dns_servers"))
    route_networks = json_list(payload.get("route_networks"))
    extra_pushes = json_list(payload.get("extra_pushes"))
    redirect_gateway = bool_from_value(payload.get("redirect_gateway"), True)

    if not service_ref:
        raise ValueError("service_ref is required")
    if not display_name:
        raise ValueError("display_name is required")

    for cidr in route_networks:
        ipaddress.ip_network(cidr, strict=False)

    return {
        "service_ref": service_ref,
        "display_name": display_name,
        "profile_slug": profile_slug,
        "dns_servers": dns_servers,
        "route_networks": route_networks,
        "extra_pushes": extra_pushes,
        "redirect_gateway": redirect_gateway,
    }


def make_common_name(service_ref: str, profile_slug: str) -> str:
    base = slugify(service_ref, "service")[:12]
    slug = slugify(profile_slug, "profile")[:16]
    suffix = secrets.token_hex(3)
    common_name = f"pmt-{base}-{slug}-{suffix}"
    return common_name[:63]


def provision_or_update_client(payload: dict) -> dict:
    validated = validate_client_payload(payload)
    existing = load_client_by_service_slug(validated["service_ref"], validated["profile_slug"])

    if existing:
        row = row_to_dict(existing)
        if row["revoked"]:
            raise RuntimeError("existing profile was revoked and cannot be reused")

        row["display_name"] = validated["display_name"]
        row["dns_servers"] = validated["dns_servers"]
        row["route_networks"] = validated["route_networks"]
        row["extra_pushes"] = validated["extra_pushes"]
        row["redirect_gateway"] = validated["redirect_gateway"]
        row["download_name"] = row["download_name"] or f"{row['profile_slug']}.ovpn"
        row["dns_servers_json"] = json.dumps(row["dns_servers"])
        row["route_networks_json"] = json.dumps(row["route_networks"])
        row["extra_pushes_json"] = json.dumps(row["extra_pushes"])
        row["redirect_gateway"] = 1 if row["redirect_gateway"] else 0
        save_client(row)
        write_ccd(row["common_name"], validated["dns_servers"], validated["redirect_gateway"], validated["route_networks"], validated["extra_pushes"])
        config = build_client_config(row["common_name"], row)
        return {
            "id": row["id"],
            "common_name": row["common_name"],
            "display_name": row["display_name"],
            "profile_slug": row["profile_slug"],
            "download_name": row["download_name"],
            "config": config,
        }

    common_name = make_common_name(validated["service_ref"], validated["profile_slug"])
    client_id = str(uuid.uuid4())
    ensure_client_certificate(common_name)
    write_ccd(common_name, validated["dns_servers"], validated["redirect_gateway"], validated["route_networks"], validated["extra_pushes"])

    row = {
        "id": client_id,
        "service_ref": validated["service_ref"],
        "profile_slug": validated["profile_slug"],
        "common_name": common_name,
        "display_name": validated["display_name"],
        "download_name": f"{validated['profile_slug']}.ovpn",
        "dns_servers_json": json.dumps(validated["dns_servers"]),
        "redirect_gateway": 1 if validated["redirect_gateway"] else 0,
        "route_networks_json": json.dumps(validated["route_networks"]),
        "extra_pushes_json": json.dumps(validated["extra_pushes"]),
        "disabled": 0,
        "disabled_reason": "",
        "revoked": 0,
        "total_bytes_received": 0,
        "total_bytes_sent": 0,
        "last_connected_at": None,
        "last_disconnected_at": None,
    }
    save_client(row)
    config = build_client_config(common_name, row)
    return {
        "id": client_id,
        "common_name": common_name,
        "display_name": validated["display_name"],
        "profile_slug": validated["profile_slug"],
        "download_name": f"{validated['profile_slug']}.ovpn",
        "config": config,
    }


def mark_connected(common_name: str) -> bool:
    with connect_db() as conn:
        row = conn.execute("SELECT * FROM clients WHERE common_name = ?", (common_name,)).fetchone()
        if not row:
            return True

        disabled = bool(row["disabled"])
        revoked = bool(row["revoked"])
        if disabled or revoked:
            return False

        conn.execute(
            "UPDATE clients SET last_connected_at = ?, updated_at = ? WHERE common_name = ?",
            (utcnow_iso(), utcnow_iso(), common_name),
        )
    return True


def mark_disconnected(common_name: str, bytes_received: int, bytes_sent: int) -> None:
    with connect_db() as conn:
        row = conn.execute("SELECT * FROM clients WHERE common_name = ?", (common_name,)).fetchone()
        if not row:
            return

        conn.execute(
            """
            UPDATE clients
            SET total_bytes_received = total_bytes_received + ?,
                total_bytes_sent = total_bytes_sent + ?,
                last_disconnected_at = ?,
                updated_at = ?
            WHERE common_name = ?
            """,
            (
                max(0, int(bytes_received)),
                max(0, int(bytes_sent)),
                utcnow_iso(),
                utcnow_iso(),
                common_name,
            ),
        )


@app.get("/api/v1/health")
@require_auth
def health():
    cfg = load_config()
    return jsonify(
        {
            "ok": True,
            "version": APP_VERSION,
            "public_host": cfg.get("public_host"),
            "protocol": cfg.get("protocol"),
            "port": cfg.get("port"),
        }
    )


@app.get("/api/v1/server")
@require_auth
def server():
    cfg = load_config()
    endpoint = f"{cfg.get('public_host')}:{cfg.get('port')} / {str(cfg.get('protocol', '')).upper()}"
    return jsonify(
        {
            "public_host": cfg.get("public_host"),
            "protocol": cfg.get("protocol"),
            "port": cfg.get("port"),
            "public_endpoint": endpoint,
            "default_dns_servers": json_list(cfg.get("default_dns_servers")),
            "default_redirect_gateway": bool_from_value(cfg.get("default_redirect_gateway"), True),
        }
    )


@app.post("/api/v1/clients")
@require_auth
def create_client():
    try:
        payload = request.get_json(silent=True) or {}
        result = provision_or_update_client(payload)
        return jsonify(result)
    except ValueError as exc:
        return jsonify({"error": str(exc)}), 422
    except Exception as exc:
        return jsonify({"error": str(exc)}), 500


@app.get("/api/v1/clients/<client_id>")
@require_auth
def get_client(client_id: str):
    row = load_client_by_id(client_id)
    if not row:
        return jsonify({"error": "not_found"}), 404
    return jsonify(row_to_dict(row))


@app.get("/api/v1/clients/<client_id>/usage")
@require_auth
def get_client_usage(client_id: str):
    row = load_client_by_id(client_id)
    if not row:
        return jsonify({"error": "not_found"}), 404
    return jsonify(usage_payload(row))


@app.get("/api/v1/clients/<client_id>/config")
@require_auth
def get_client_config(client_id: str):
    row = load_client_by_id(client_id)
    if not row:
        return jsonify({"error": "not_found"}), 404
    data = row_to_dict(row)
    config = build_client_config(data["common_name"], data)
    return Response(config, mimetype="text/plain")


@app.post("/api/v1/clients/<client_id>/disable")
@require_auth
def disable_client(client_id: str):
    row = load_client_by_id(client_id)
    if not row:
        return jsonify({"error": "not_found"}), 404

    reason = str((request.get_json(silent=True) or {}).get("reason", "")).strip()
    with connect_db() as conn:
        conn.execute(
            "UPDATE clients SET disabled = 1, disabled_reason = ?, updated_at = ? WHERE id = ?",
            (reason, utcnow_iso(), client_id),
        )

    disconnect_active_client(row["common_name"])
    updated = load_client_by_id(client_id)
    return jsonify(usage_payload(updated))


@app.post("/api/v1/clients/<client_id>/enable")
@require_auth
def enable_client(client_id: str):
    row = load_client_by_id(client_id)
    if not row:
        return jsonify({"error": "not_found"}), 404

    with connect_db() as conn:
        conn.execute(
            "UPDATE clients SET disabled = 0, disabled_reason = '', updated_at = ? WHERE id = ?",
            (utcnow_iso(), client_id),
        )

    updated = load_client_by_id(client_id)
    return jsonify(usage_payload(updated))


@app.delete("/api/v1/clients/<client_id>")
@require_auth
def delete_client(client_id: str):
    row = load_client_by_id(client_id)
    if not row:
        return jsonify({"ok": True})

    data = row_to_dict(row)
    disconnect_active_client(data["common_name"])
    revoke_client_certificate(data["common_name"])
    ccd = ccd_path(data["common_name"])
    if ccd.exists():
        ccd.unlink()
    delete_client_record(client_id)
    return jsonify({"ok": True})


def main() -> int:
    init_db()

    if len(sys.argv) >= 2 and sys.argv[1] == "init-db":
        return 0

    if len(sys.argv) >= 3 and sys.argv[1] == "connect-check":
        common_name = sys.argv[2].strip()
        return 0 if mark_connected(common_name) else 1

    if len(sys.argv) >= 5 and sys.argv[1] == "disconnect":
        common_name = sys.argv[2].strip()
        bytes_received = int(float(sys.argv[3] or 0))
        bytes_sent = int(float(sys.argv[4] or 0))
        mark_disconnected(common_name, bytes_received, bytes_sent)
        return 0

    if len(sys.argv) >= 2 and sys.argv[1] == "serve":
        cfg = load_config()
        host = cfg.get("bind_host", "127.0.0.1")
        port = int(cfg.get("bind_port", 9081))
        app.run(host=host, port=port)
        return 0

    print("Usage: openvpn_manager_api.py [init-db|connect-check <cn>|disconnect <cn> <rx> <tx>|serve]", file=sys.stderr)
    return 1


init_db()


if __name__ == "__main__":
    raise SystemExit(main())
