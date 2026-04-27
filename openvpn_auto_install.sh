#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]:-${0}}")" >/dev/null 2>&1 && pwd || echo ".")"
DOWNLOADED_API_SOURCE=""

cleanup() {
    if [[ -n "${DOWNLOADED_API_SOURCE}" && -f "${DOWNLOADED_API_SOURCE}" ]]; then
        rm -f "${DOWNLOADED_API_SOURCE}"
    fi
}

trap cleanup EXIT

abort() {
    echo "Error: $*" >&2
    exit 1
}

need_root() {
    if [[ "${EUID}" -ne 0 ]]; then
        abort "Please run this installer as root."
    fi
}

need_ubuntu_2204() {
    if [[ ! -f /etc/os-release ]]; then
        abort "/etc/os-release is missing; cannot verify the operating system."
    fi

    # shellcheck disable=SC1091
    source /etc/os-release
    if [[ "${ID:-}" != "ubuntu" || "${VERSION_ID:-}" != "22.04" ]]; then
        abort "This installer is written for Ubuntu 22.04 LTS."
    fi
}

need_fresh_install_target() {
    if [[ -e /etc/openvpn/server/server.conf || -d /etc/paymenter-openvpn-manager || -d /etc/openvpn/easy-rsa/pki || -d /opt/paymenter-openvpn-manager || -d /var/lib/paymenter-openvpn-manager ]]; then
        abort "Existing OpenVPN manager files were detected. Use a fresh host or clean the previous installation first."
    fi
}

need_local_assets() {
    DOWNLOADED_API_SOURCE="$(mktemp /tmp/paymenter-openvpn-manager-api.XXXXXX.py)"
    cat <<'EOF_PYTHON_API' > "${DOWNLOADED_API_SOURCE}"
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


def resolve_path(value: str | None, *, base: Path | None = None) -> str | None:
    text = str(value or "").strip()
    if not text:
        return None

    candidate = Path(text)
    if candidate.is_absolute():
        return str(candidate)
    if base is not None:
        return str((base / candidate).resolve())
    return str(candidate.resolve())


def first_existing_path(candidates: list[str]) -> str | None:
    for candidate in candidates:
        if candidate and Path(candidate).exists():
            return candidate
    return None


def parse_server_config(path: Path) -> dict[str, list[list[str]]]:
    directives: dict[str, list[list[str]]] = {}
    if not path.exists():
        return directives

    for raw_line in path.read_text(encoding="utf-8", errors="ignore").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#") or line.startswith(";"):
            continue

        if "#" in line:
            line = line.split("#", 1)[0].strip()
        if ";" in line and not line.startswith('"'):
            line = line.split(";", 1)[0].strip()
        if not line:
            continue

        parts = line.split()
        if not parts:
            continue

        directives.setdefault(parts[0], []).append(parts[1:])

    return directives


def load_config() -> dict:
    if not CONFIG_PATH.exists():
        raise RuntimeError(f"Missing configuration file: {CONFIG_PATH}")

    data = json.loads(CONFIG_PATH.read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise RuntimeError("Configuration file must contain a JSON object")

    server_config_path = resolve_path(
        data.get("server_config_path") or first_existing_path(
            [
                "/etc/openvpn/server/server.conf",
                "/etc/openvpn/server.conf",
            ]
        )
    )
    data["server_config_path"] = server_config_path

    server_config = parse_server_config(Path(server_config_path)) if server_config_path else {}
    server_dir = Path(server_config_path).parent if server_config_path else None

    management = server_config.get("management", [])
    if management:
        mgmt_parts = management[0]
        if len(mgmt_parts) >= 2 and mgmt_parts[1].lower() == "unix":
            data.setdefault("management_socket_path", resolve_path(mgmt_parts[0], base=server_dir))
        elif len(mgmt_parts) >= 2:
            data.setdefault("management_host", mgmt_parts[0])
            try:
                data.setdefault("management_port", int(mgmt_parts[1]))
            except ValueError:
                pass

    if "status_file" not in data:
        status = server_config.get("status", [])
        status_path = resolve_path(status[0][0], base=server_dir) if status and status[0] else None
        data["status_file"] = status_path or first_existing_path(
            [
                "/var/log/openvpn/status.log",
                "/var/lib/paymenter-openvpn-manager/openvpn-status.log",
            ]
        ) or "/var/lib/paymenter-openvpn-manager/openvpn-status.log"

    if "ccd_dir" not in data:
        ccd = server_config.get("client-config-dir", [])
        ccd_path = resolve_path(ccd[0][0], base=server_dir) if ccd and ccd[0] else None
        data["ccd_dir"] = ccd_path or "/etc/openvpn/server/ccd"

    if "ca_path" not in data:
        ca = server_config.get("ca", [])
        data["ca_path"] = resolve_path(ca[0][0], base=server_dir) if ca and ca[0] else "/etc/openvpn/server/ca.crt"

    if "crl_path" not in data:
        crl = server_config.get("crl-verify", [])
        data["crl_path"] = resolve_path(crl[0][0], base=server_dir) if crl and crl[0] else "/etc/openvpn/server/crl.pem"

    tls_crypt_v2 = server_config.get("tls-crypt-v2", [])
    tls_crypt = server_config.get("tls-crypt", [])
    if "tls_crypt_mode" not in data:
        if tls_crypt_v2:
            data["tls_crypt_mode"] = "tls-crypt-v2"
        else:
            data["tls_crypt_mode"] = "tls-crypt"

    mode = str(data.get("tls_crypt_mode", "tls-crypt")).strip().lower()
    if mode == "tls-crypt-v2":
        if "tls_crypt_v2_server_key_path" not in data:
            data["tls_crypt_v2_server_key_path"] = (
                resolve_path(tls_crypt_v2[0][0], base=server_dir) if tls_crypt_v2 and tls_crypt_v2[0] else
                first_existing_path(["/etc/openvpn/server/tls-crypt-v2.key"])
            )
    else:
        if "tls_crypt_path" not in data:
            data["tls_crypt_path"] = (
                resolve_path(tls_crypt[0][0], base=server_dir) if tls_crypt and tls_crypt[0] else
                first_existing_path(["/etc/openvpn/server/tls-crypt.key"])
            )

    if "easyrsa_dir" not in data:
        data["easyrsa_dir"] = first_existing_path(
            [
                "/etc/openvpn/server/easy-rsa",
                "/etc/openvpn/easy-rsa",
            ]
        ) or "/etc/openvpn/server/easy-rsa"

    easyrsa_dir = str(data["easyrsa_dir"])
    data.setdefault("database_path", "/var/lib/paymenter-openvpn-manager/manager.db")
    data.setdefault("cert_path_template", str(Path(easyrsa_dir) / "pki/issued/{common_name}.crt"))
    data.setdefault("key_path_template", str(Path(easyrsa_dir) / "pki/private/{common_name}.key"))
    data.setdefault("tls_crypt_v2_client_key_dir", "/var/lib/paymenter-openvpn-manager/tls-crypt-v2")

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


def tls_crypt_mode(cfg: dict | None = None) -> str:
    config = cfg or load_config()
    return str(config.get("tls_crypt_mode", "tls-crypt")).strip().lower()


def tls_crypt_v2_client_key_path(common_name: str) -> Path:
    cfg = load_config()
    base_dir = Path(str(cfg.get("tls_crypt_v2_client_key_dir", "/var/lib/paymenter-openvpn-manager/tls-crypt-v2")))
    return base_dir / f"{common_name}.key"


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
    mode = tls_crypt_mode(cfg)
    client_key = tls_crypt_v2_client_key_path(common_name) if mode == "tls-crypt-v2" else None
    if cert.exists() and key.exists() and (client_key is None or client_key.exists()):
        return

    if not cert.exists() or not key.exists():
        run_command(
            ["./easyrsa", "build-client-full", common_name, "nopass"],
            cwd=cfg["easyrsa_dir"],
            env=easyrsa_env(),
        )

    if mode == "tls-crypt-v2":
        server_key_path = str(cfg.get("tls_crypt_v2_server_key_path", "")).strip()
        if not server_key_path:
            raise RuntimeError("tls_crypt_v2_server_key_path is required when tls_crypt_mode is tls-crypt-v2")

        assert client_key is not None
        client_key.parent.mkdir(parents=True, exist_ok=True)
        if not client_key.exists():
            run_command(
                [
                    "openvpn",
                    "--tls-crypt-v2",
                    server_key_path,
                    "--genkey",
                    "tls-crypt-v2-client",
                    str(client_key),
                ]
            )
        os.chmod(client_key, 0o640)


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

    client_key = tls_crypt_v2_client_key_path(common_name)
    if client_key.exists():
        client_key.unlink()


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
    lines = []

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
    control_mode = tls_crypt_mode(cfg)
    tls_crypt_text = ""
    tls_directive = None
    tls_inline_open = None
    tls_inline_close = None
    if control_mode == "tls-crypt-v2":
        client_key_path = tls_crypt_v2_client_key_path(common_name)
        tls_crypt_text = client_key_path.read_text(encoding="utf-8").strip()
        tls_directive = "tls-crypt-v2 [inline]"
        tls_inline_open = "<tls-crypt-v2>"
        tls_inline_close = "</tls-crypt-v2>"
    else:
        tls_crypt_text = Path(cfg["tls_crypt_path"]).read_text(encoding="utf-8").strip()
        tls_directive = "tls-crypt [inline]"
        tls_inline_open = "<tls-crypt>"
        tls_inline_close = "</tls-crypt>"
    redirect_gateway = row_redirect_gateway(row, cfg)
    dns_servers = row_dns_servers(row, cfg)
    route_networks = row_route_networks(row)

    lines = [
        "client",
        "dev tun",
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
            tls_inline_open,
            tls_crypt_text,
            tls_inline_close,
            "",
        ]
    )
    return "\n".join(lines)


def management_command(command: str) -> str:
    cfg = load_config()
    management_socket_path = str(cfg.get("management_socket_path", "")).strip()
    if management_socket_path:
        sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        sock.settimeout(5)
        sock.connect(management_socket_path)
    else:
        host = cfg.get("management_host", "127.0.0.1")
        port = int(cfg.get("management_port", 7505))
        sock = socket.create_connection((host, port), timeout=5)

    with sock:
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

        parts = line.split("\t") if "\t" in line else line.split(",")
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
    download_bytes = int(data["total_bytes_sent"] or 0) + int(live.get("bytes_sent") or 0)
    upload_bytes = int(data["total_bytes_received"] or 0) + int(live.get("bytes_received") or 0)
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

EOF_PYTHON_API

    python3 -m py_compile "${DOWNLOADED_API_SOURCE}" >/dev/null 2>&1 || \
        abort "Bundled companion API file is not valid Python."

    API_SOURCE="${DOWNLOADED_API_SOURCE}"
    echo "Extracted companion API file."
}

ask_default() {
    local prompt="$1"
    local default_value="$2"
    local reply
    read -r -p "${prompt} [${default_value}]: " reply
    if [[ -z "${reply}" ]]; then
        printf '%s' "${default_value}"
    else
        printf '%s' "${reply}"
    fi
}

ask_required() {
    local prompt="$1"
    local reply=""
    while [[ -z "${reply}" ]]; do
        read -r -p "${prompt}: " reply
    done
    printf '%s' "${reply}"
}

ask_yes_no() {
    local prompt="$1"
    local default_value="$2"
    local reply
    local normalized_default
    normalized_default="$(printf '%s' "${default_value}" | tr '[:upper:]' '[:lower:]')"

    while true; do
        if [[ "${normalized_default}" == "y" ]]; then
            read -r -p "${prompt} [Y/n]: " reply
            reply="${reply:-Y}"
        else
            read -r -p "${prompt} [y/N]: " reply
            reply="${reply:-N}"
        fi

        reply="$(printf '%s' "${reply}" | tr '[:upper:]' '[:lower:]')"
        case "${reply}" in
            y|yes) printf 'yes'; return 0 ;;
            n|no) printf 'no'; return 0 ;;
        esac
    done
}

split_csv_to_json() {
    python3 - "$1" <<'PY'
import json
import re
import sys

raw = sys.argv[1]
items = [part.strip() for part in re.split(r"[\r\n,]+", raw) if part.strip()]
print(json.dumps(items))
PY
}

validate_cidr() {
    python3 - "$1" <<'PY'
import ipaddress
import sys

ipaddress.ip_network(sys.argv[1], strict=False)
PY
}

detect_public_nic() {
    ip route show default 2>/dev/null | awk '/default/ {print $5; exit}'
}

prepare_packages() {
    apt-get update
    DEBIAN_FRONTEND=noninteractive apt-get install -y \
        openvpn \
        easy-rsa \
        nginx \
        certbot \
        python3-certbot-nginx \
        python3-flask \
        gunicorn \
        python3 \
        jq \
        curl \
        ca-certificates \
        openssl \
        ufw
}

write_easyrsa_vars() {
    cat > /etc/openvpn/easy-rsa/vars <<EOF
set_var EASYRSA_ALGO ec
set_var EASYRSA_CURVE prime256v1
set_var EASYRSA_DIGEST "sha256"
set_var EASYRSA_REQ_COUNTRY "${EASYRSA_REQ_COUNTRY}"
set_var EASYRSA_REQ_PROVINCE "${EASYRSA_REQ_PROVINCE}"
set_var EASYRSA_REQ_CITY "${EASYRSA_REQ_CITY}"
set_var EASYRSA_REQ_ORG "${EASYRSA_REQ_ORG}"
set_var EASYRSA_REQ_EMAIL "${EASYRSA_REQ_EMAIL}"
set_var EASYRSA_REQ_OU "${EASYRSA_REQ_OU}"
set_var EASYRSA_REQ_CN "${CA_COMMON_NAME}"
EOF
}

setup_easy_rsa() {
    cp -R /usr/share/easy-rsa /etc/openvpn/easy-rsa
    chmod -R 700 /etc/openvpn/easy-rsa
    write_easyrsa_vars

    pushd /etc/openvpn/easy-rsa >/dev/null
    ./easyrsa init-pki
    EASYRSA_BATCH=1 ./easyrsa build-ca nopass
    EASYRSA_BATCH=1 ./easyrsa build-server-full "${SERVER_COMMON_NAME}" nopass
    EASYRSA_BATCH=1 ./easyrsa gen-crl
    popd >/dev/null

    install -d -m 755 /etc/openvpn/server
    install -m 644 /etc/openvpn/easy-rsa/pki/ca.crt /etc/openvpn/server/ca.crt
    install -m 644 "/etc/openvpn/easy-rsa/pki/issued/${SERVER_COMMON_NAME}.crt" /etc/openvpn/server/server.crt
    install -m 600 "/etc/openvpn/easy-rsa/pki/private/${SERVER_COMMON_NAME}.key" /etc/openvpn/server/server.key
    install -m 644 /etc/openvpn/easy-rsa/pki/crl.pem /etc/openvpn/server/crl.pem
    openvpn --genkey secret /etc/openvpn/server/tls-crypt.key
    chmod 600 /etc/openvpn/server/tls-crypt.key
}

write_openvpn_server_config() {
    local explicit_exit=""
    if [[ "${OPENVPN_PROTOCOL}" == "udp" ]]; then
        explicit_exit="explicit-exit-notify 1"
    fi

    cat > /etc/openvpn/server/server.conf <<EOF
port ${OPENVPN_PORT}
proto ${OPENVPN_PROTOCOL}
dev tun
user nobody
group nogroup
persist-key
persist-tun
topology subnet
server ${VPN_NETWORK_ADDRESS} ${VPN_NETMASK}
ifconfig-pool-persist /var/lib/paymenter-openvpn-manager/ipp.txt
keepalive 10 120
status /var/lib/paymenter-openvpn-manager/openvpn-status.log 10
status-version 3
management 127.0.0.1 7505
script-security 2
client-config-dir /etc/openvpn/server/ccd
client-connect /opt/paymenter-openvpn-manager/client-connect.sh
client-disconnect /opt/paymenter-openvpn-manager/client-disconnect.sh
ca /etc/openvpn/server/ca.crt
cert /etc/openvpn/server/server.crt
key /etc/openvpn/server/server.key
crl-verify /etc/openvpn/server/crl.pem
dh none
ecdh-curve prime256v1
tls-crypt /etc/openvpn/server/tls-crypt.key
verify-client-cert require
tls-version-min 1.2
cipher AES-256-GCM
data-ciphers AES-256-GCM:AES-128-GCM:CHACHA20-POLY1305
auth SHA256
verb 3
sndbuf 0
rcvbuf 0
push "sndbuf 0"
push "rcvbuf 0"
push "topology subnet"
${explicit_exit}
EOF
}

write_manager_config() {
    local dns_json
    dns_json="$(split_csv_to_json "${DEFAULT_DNS_SERVERS}")"

    install -d -m 755 /etc/paymenter-openvpn-manager
    cat > /etc/paymenter-openvpn-manager/config.json <<EOF
{
  "api_token": "${API_TOKEN}",
  "bind_host": "127.0.0.1",
  "bind_port": 9081,
  "public_host": "${PUBLIC_OPENVPN_HOST}",
  "protocol": "${OPENVPN_PROTOCOL}",
  "port": ${OPENVPN_PORT},
  "database_path": "/var/lib/paymenter-openvpn-manager/manager.db",
  "status_file": "/var/lib/paymenter-openvpn-manager/openvpn-status.log",
  "easyrsa_dir": "/etc/openvpn/easy-rsa",
  "ccd_dir": "/etc/openvpn/server/ccd",
  "management_host": "127.0.0.1",
  "management_port": 7505,
  "ca_path": "/etc/openvpn/server/ca.crt",
  "tls_crypt_path": "/etc/openvpn/server/tls-crypt.key",
  "crl_path": "/etc/openvpn/server/crl.pem",
  "cert_path_template": "/etc/openvpn/easy-rsa/pki/issued/{common_name}.crt",
  "key_path_template": "/etc/openvpn/easy-rsa/pki/private/{common_name}.key",
  "cipher": "AES-256-GCM",
  "data_ciphers": "AES-256-GCM:AES-128-GCM:CHACHA20-POLY1305",
  "auth": "SHA256",
  "default_dns_servers": ${dns_json},
  "default_redirect_gateway": true
}
EOF

    chown root:root /etc/paymenter-openvpn-manager
    chmod 755 /etc/paymenter-openvpn-manager
    chown root:root /etc/paymenter-openvpn-manager/config.json
    chmod 644 /etc/paymenter-openvpn-manager/config.json
}

write_manager_assets() {
    install -d -m 755 /etc/paymenter-openvpn-manager /opt/paymenter-openvpn-manager /var/lib/paymenter-openvpn-manager /etc/openvpn/server/ccd
    install -m 755 "${API_SOURCE}" /opt/paymenter-openvpn-manager/openvpn_manager_api.py
    touch /var/lib/paymenter-openvpn-manager/ipp.txt
    touch /var/lib/paymenter-openvpn-manager/openvpn-status.log
    chmod 755 /etc/openvpn
    chmod 755 /opt/paymenter-openvpn-manager
    chmod 755 /etc/openvpn/server
    chown root:root /etc/openvpn/server/ccd
    chmod 755 /etc/openvpn/server/ccd
    chown root:nogroup /var/lib/paymenter-openvpn-manager
    chmod 2775 /var/lib/paymenter-openvpn-manager
    chown root:nogroup /var/lib/paymenter-openvpn-manager/ipp.txt /var/lib/paymenter-openvpn-manager/openvpn-status.log
    chmod 664 /var/lib/paymenter-openvpn-manager/ipp.txt /var/lib/paymenter-openvpn-manager/openvpn-status.log

    cat > /opt/paymenter-openvpn-manager/client-connect.sh <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
exec /usr/bin/python3 /opt/paymenter-openvpn-manager/openvpn_manager_api.py connect-check "${common_name:-}"
EOF
    chmod 755 /opt/paymenter-openvpn-manager/client-connect.sh

    cat > /opt/paymenter-openvpn-manager/client-disconnect.sh <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
exec /usr/bin/python3 /opt/paymenter-openvpn-manager/openvpn_manager_api.py disconnect "${common_name:-}" "${bytes_received:-0}" "${bytes_sent:-0}"
EOF
    chmod 755 /opt/paymenter-openvpn-manager/client-disconnect.sh

    cat > /etc/systemd/system/paymenter-openvpn-api.service <<'EOF'
[Unit]
Description=Paymenter OpenVPN Manager API
After=network.target openvpn-server@server.service
Requires=openvpn-server@server.service

[Service]
Type=simple
WorkingDirectory=/opt/paymenter-openvpn-manager
ExecStartPre=/usr/bin/python3 /opt/paymenter-openvpn-manager/openvpn_manager_api.py init-db
ExecStart=/usr/bin/gunicorn --workers 2 --threads 4 --bind 127.0.0.1:9081 --chdir /opt/paymenter-openvpn-manager openvpn_manager_api:app
Restart=always
RestartSec=3

[Install]
WantedBy=multi-user.target
EOF
}

initialize_manager_state() {
    /usr/bin/python3 /opt/paymenter-openvpn-manager/openvpn_manager_api.py init-db

    chmod 755 /etc/openvpn
    chmod 755 /etc/openvpn/server
    chown root:root /etc/openvpn/server/ccd
    chmod 755 /etc/openvpn/server/ccd
    find /etc/openvpn/server/ccd -maxdepth 1 -type f -exec chown root:root {} \;
    find /etc/openvpn/server/ccd -maxdepth 1 -type f -exec chmod 644 {} \;

    chown root:nogroup /var/lib/paymenter-openvpn-manager
    chmod 2775 /var/lib/paymenter-openvpn-manager
    chown root:nogroup /var/lib/paymenter-openvpn-manager/manager.db
    chmod 664 /var/lib/paymenter-openvpn-manager/manager.db
    chown root:nogroup /var/lib/paymenter-openvpn-manager/ipp.txt
    chmod 664 /var/lib/paymenter-openvpn-manager/ipp.txt
    chown root:nogroup /var/lib/paymenter-openvpn-manager/openvpn-status.log
    chmod 664 /var/lib/paymenter-openvpn-manager/openvpn-status.log

    if compgen -G "/var/lib/paymenter-openvpn-manager/manager.db*" > /dev/null; then
        chown root:nogroup /var/lib/paymenter-openvpn-manager/manager.db*
        chmod 664 /var/lib/paymenter-openvpn-manager/manager.db*
    fi

    if [[ -f /etc/openvpn/server/crl.pem ]]; then
        chown root:root /etc/openvpn/server/crl.pem
        chmod 644 /etc/openvpn/server/crl.pem
    fi
    chown root:root /etc/paymenter-openvpn-manager
    chmod 755 /etc/paymenter-openvpn-manager
    chown root:root /etc/paymenter-openvpn-manager/config.json
    chmod 644 /etc/paymenter-openvpn-manager/config.json
}

verify_installation_prereqs() {
    local required_paths=(
        /etc/paymenter-openvpn-manager/config.json
        /opt/paymenter-openvpn-manager/openvpn_manager_api.py
        /opt/paymenter-openvpn-manager/client-connect.sh
        /opt/paymenter-openvpn-manager/client-disconnect.sh
        /etc/openvpn/server/server.conf
        /etc/openvpn/server/ca.crt
        /etc/openvpn/server/server.crt
        /etc/openvpn/server/server.key
        /etc/openvpn/server/crl.pem
        /etc/openvpn/server/tls-crypt.key
        /var/lib/paymenter-openvpn-manager/manager.db
    )
    local path=""

    for path in "${required_paths[@]}"; do
        [[ -e "${path}" ]] || abort "Required installation artifact is missing: ${path}"
    done

    runuser -u nobody -g nogroup -- test -r /etc/paymenter-openvpn-manager/config.json || \
        abort "OpenVPN hook user cannot read /etc/paymenter-openvpn-manager/config.json"
    runuser -u nobody -g nogroup -- test -r /etc/openvpn/server/crl.pem || \
        abort "OpenVPN hook user cannot read /etc/openvpn/server/crl.pem"
    runuser -u nobody -g nogroup -- test -x /etc/openvpn/server/ccd || \
        abort "OpenVPN hook user cannot traverse /etc/openvpn/server/ccd"
    runuser -u nobody -g nogroup -- /usr/bin/python3 /opt/paymenter-openvpn-manager/openvpn_manager_api.py connect-check __installer_probe__ >/dev/null 2>&1 || \
        abort "OpenVPN hook preflight failed; verify config and runtime permissions."
}

configure_sysctl() {
    cat > /etc/sysctl.d/99-paymenter-openvpn.conf <<EOF
net.ipv4.ip_forward = 1
EOF
    sysctl --system >/dev/null
}

configure_ufw() {
    local before_rules="/etc/ufw/before.rules"
    if ! grep -q "paymenter-openvpn-nat" "${before_rules}"; then
        cp "${before_rules}" "${before_rules}.bak.$(date +%s)"
        awk -v vpn_subnet="${VPN_SUBNET}" -v public_nic="${PUBLIC_NIC}" '
            BEGIN {
                print "# START paymenter-openvpn-nat"
                print "*nat"
                print ":POSTROUTING ACCEPT [0:0]"
                print "-A POSTROUTING -s " vpn_subnet " -o " public_nic " -j MASQUERADE"
                print "COMMIT"
                print "# END paymenter-openvpn-nat"
            }
            { print }
        ' "${before_rules}" > "${before_rules}.new"
        mv "${before_rules}.new" "${before_rules}"
    fi

    sed -i 's/^DEFAULT_FORWARD_POLICY=.*/DEFAULT_FORWARD_POLICY="ACCEPT"/' /etc/default/ufw
    ufw allow "${SSH_PORT}/tcp"
    ufw allow 80/tcp
    ufw allow 443/tcp
    ufw allow "${OPENVPN_PORT}/${OPENVPN_PROTOCOL}"
    ufw route allow in on tun0 out on "${PUBLIC_NIC}"
    ufw route allow in on "${PUBLIC_NIC}" out on tun0
    ufw --force enable
}

configure_iptables_persistent() {
    DEBIAN_FRONTEND=noninteractive apt-get install -y iptables-persistent netfilter-persistent

    iptables -t nat -C POSTROUTING -s "${VPN_SUBNET}" -o "${PUBLIC_NIC}" -j MASQUERADE 2>/dev/null || \
        iptables -t nat -A POSTROUTING -s "${VPN_SUBNET}" -o "${PUBLIC_NIC}" -j MASQUERADE
    iptables -C FORWARD -i tun0 -s "${VPN_SUBNET}" -o "${PUBLIC_NIC}" -j ACCEPT 2>/dev/null || \
        iptables -A FORWARD -i tun0 -s "${VPN_SUBNET}" -o "${PUBLIC_NIC}" -j ACCEPT
    iptables -C FORWARD -i "${PUBLIC_NIC}" -d "${VPN_SUBNET}" -o tun0 -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT 2>/dev/null || \
        iptables -A FORWARD -i "${PUBLIC_NIC}" -d "${VPN_SUBNET}" -o tun0 -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT

    iptables -C INPUT -p tcp --dport "${SSH_PORT}" -j ACCEPT 2>/dev/null || iptables -A INPUT -p tcp --dport "${SSH_PORT}" -j ACCEPT
    iptables -C INPUT -p tcp --dport 80 -j ACCEPT 2>/dev/null || iptables -A INPUT -p tcp --dport 80 -j ACCEPT
    iptables -C INPUT -p tcp --dport 443 -j ACCEPT 2>/dev/null || iptables -A INPUT -p tcp --dport 443 -j ACCEPT
    iptables -C INPUT -p "${OPENVPN_PROTOCOL}" --dport "${OPENVPN_PORT}" -j ACCEPT 2>/dev/null || \
        iptables -A INPUT -p "${OPENVPN_PROTOCOL}" --dport "${OPENVPN_PORT}" -j ACCEPT

    netfilter-persistent save
}

write_nginx_bootstrap_config() {
    cat > /etc/nginx/sites-available/paymenter-openvpn-manager <<EOF
server {
    listen 80;
    listen [::]:80;
    server_name ${API_DOMAIN};

    location /.well-known/acme-challenge/ {
        root /var/www/html;
    }

    location / {
        proxy_pass http://127.0.0.1:9081;
        proxy_http_version 1.1;
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \$scheme;
    }
}
EOF

    ln -sf /etc/nginx/sites-available/paymenter-openvpn-manager /etc/nginx/sites-enabled/paymenter-openvpn-manager
    rm -f /etc/nginx/sites-enabled/default
    nginx -t
    systemctl restart nginx
}

write_nginx_final_config() {
    local cert_path="$1"
    local key_path="$2"
    local allow_rules=""
    if [[ -n "${API_ALLOWLIST}" ]]; then
        while IFS= read -r item; do
            [[ -z "${item}" ]] && continue
            allow_rules="${allow_rules}            allow ${item};"$'\n'
        done < <(python3 - "${API_ALLOWLIST}" <<'PY'
import re
import sys
parts = [part.strip() for part in re.split(r"[\r\n,]+", sys.argv[1]) if part.strip()]
for part in parts:
    print(part)
PY
)
        allow_rules="${allow_rules}            deny all;"$'\n'
    fi

    cat > /etc/nginx/sites-available/paymenter-openvpn-manager <<EOF
server {
    listen 80;
    listen [::]:80;
    server_name ${API_DOMAIN};

    location /.well-known/acme-challenge/ {
        root /var/www/html;
    }

    location / {
        return 301 https://\$host\$request_uri;
    }
}

server {
    listen 443 ssl http2;
    listen [::]:443 ssl http2;
    server_name ${API_DOMAIN};

    ssl_certificate ${cert_path};
    ssl_certificate_key ${key_path};
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_prefer_server_ciphers off;
    client_max_body_size 10m;

    location / {
${allow_rules}        proxy_pass http://127.0.0.1:9081;
        proxy_http_version 1.1;
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \$scheme;
        proxy_set_header Connection "";
    }
}
EOF

    nginx -t
    systemctl restart nginx
}

issue_certificate() {
    local cert_path=""
    local key_path=""

    if [[ "${ENABLE_LETSENCRYPT}" == "yes" ]]; then
        certbot certonly \
            --webroot \
            -w /var/www/html \
            -d "${API_DOMAIN}" \
            --non-interactive \
            --agree-tos \
            -m "${ACME_EMAIL}" \
            --keep-until-expiring
        cert_path="/etc/letsencrypt/live/${API_DOMAIN}/fullchain.pem"
        key_path="/etc/letsencrypt/live/${API_DOMAIN}/privkey.pem"
    else
        cert_path="/etc/ssl/certs/paymenter-openvpn-manager.crt"
        key_path="/etc/ssl/private/paymenter-openvpn-manager.key"
        openssl req -x509 -nodes -days 825 -newkey rsa:4096 \
            -keyout "${key_path}" \
            -out "${cert_path}" \
            -subj "/CN=${API_DOMAIN}"
        chmod 600 "${key_path}"
        chmod 644 "${cert_path}"
    fi

    write_nginx_final_config "${cert_path}" "${key_path}"
}

enable_services() {
    systemctl daemon-reload
    systemctl enable --now openvpn-server@server.service
    systemctl enable --now paymenter-openvpn-api.service
    systemctl enable --now nginx
}

print_summary() {
    cat <<EOF

OpenVPN installation complete.

Paymenter server extension values:
  Base URL: https://${API_DOMAIN}
  API Token: ${API_TOKEN}
  Verify TLS: $( [[ "${ENABLE_LETSENCRYPT}" == "yes" ]] && printf 'true' || printf 'false if you keep the self-signed certificate' )
  Timeout: 15

VPN endpoint summary:
  Public host: ${PUBLIC_OPENVPN_HOST}
  Protocol: ${OPENVPN_PROTOCOL}
  Port: ${OPENVPN_PORT}
  VPN subnet: ${VPN_SUBNET}

Services:
  OpenVPN: systemctl status openvpn-server@server.service
  Manager API: systemctl status paymenter-openvpn-api.service
  Nginx: systemctl status nginx

The companion Paymenter files live in:
  ${SCRIPT_DIR}
EOF
}

need_root
need_ubuntu_2204
need_fresh_install_target
need_local_assets

PUBLIC_NIC="$(detect_public_nic)"
PUBLIC_NIC="${PUBLIC_NIC:-eth0}"

API_DOMAIN="$(ask_required 'API domain for the manager (example: vpn.example.com)')"
PUBLIC_OPENVPN_HOST="$(ask_default 'Hostname or IP clients should use to connect to OpenVPN' "${API_DOMAIN}")"
OPENVPN_PROTOCOL="$(ask_default 'OpenVPN protocol (udp or tcp)' 'udp')"
if [[ "${OPENVPN_PROTOCOL}" != "udp" && "${OPENVPN_PROTOCOL}" != "tcp" ]]; then
    abort "Protocol must be udp or tcp."
fi
OPENVPN_PORT="$(ask_default 'OpenVPN port' '1194')"
VPN_SUBNET="$(ask_default 'VPN subnet in CIDR notation' '10.8.0.0/24')"
validate_cidr "${VPN_SUBNET}" >/dev/null
DEFAULT_DNS_SERVERS="$(ask_default 'Default DNS servers pushed to clients (comma separated)' '1.1.1.1, 1.0.0.1')"
API_ALLOWLIST="$(ask_default 'Optional API allowlist CIDRs for nginx (comma separated, blank to allow all)' '')"
ENABLE_LETSENCRYPT="$(ask_yes_no 'Issue a Let'\''s Encrypt certificate for the nginx API proxy' 'y')"
ACME_EMAIL=""
if [[ "${ENABLE_LETSENCRYPT}" == "yes" ]]; then
    ACME_EMAIL="$(ask_required 'Email address for Let'\''s Encrypt notices')"
fi
ENABLE_UFW="$(ask_yes_no 'Configure and enable UFW firewall rules' 'y')"
SSH_PORT="$(ask_default 'SSH port to allow through the firewall' '22')"
API_TOKEN="$(ask_default 'API token to use for Paymenter (leave random if unsure)' "$(openssl rand -hex 32)")"

EASYRSA_REQ_COUNTRY="$(ask_default 'Easy-RSA country code' 'US')"
EASYRSA_REQ_PROVINCE="$(ask_default 'Easy-RSA state or province' 'State')"
EASYRSA_REQ_CITY="$(ask_default 'Easy-RSA city' 'City')"
EASYRSA_REQ_ORG="$(ask_default 'Easy-RSA organization' 'Paymenter VPN')"
EASYRSA_REQ_EMAIL="$(ask_default 'Easy-RSA contact email' 'admin@'"${API_DOMAIN}")"
EASYRSA_REQ_OU="$(ask_default 'Easy-RSA organizational unit' 'Infrastructure')"
CA_COMMON_NAME="$(ask_default 'Certificate authority common name' 'Paymenter OpenVPN CA')"
SERVER_COMMON_NAME="$(ask_default 'OpenVPN server certificate common name' 'server')"

VPN_NETWORK_ADDRESS="$(python3 - "${VPN_SUBNET}" <<'PY'
import ipaddress
import sys
network = ipaddress.ip_network(sys.argv[1], strict=False)
print(network.network_address)
PY
)"
VPN_NETMASK="$(python3 - "${VPN_SUBNET}" <<'PY'
import ipaddress
import sys
network = ipaddress.ip_network(sys.argv[1], strict=False)
print(network.netmask)
PY
)"

echo
echo "Preparing packages and filesystem..."
prepare_packages

install -d -m 755 /var/www/html
install -d -m 755 /var/www/html/.well-known
install -d -m 755 /var/www/html/.well-known/acme-challenge
write_manager_assets
write_manager_config
configure_sysctl
setup_easy_rsa
write_openvpn_server_config
initialize_manager_state
verify_installation_prereqs

echo "Configuring services and reverse proxy..."
enable_services
write_nginx_bootstrap_config
issue_certificate

if [[ "${ENABLE_UFW}" == "yes" ]]; then
    configure_ufw
else
    configure_iptables_persistent
fi

systemctl restart openvpn-server@server.service
systemctl restart paymenter-openvpn-api.service
systemctl restart nginx

print_summary
