#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
API_SOURCE="${SCRIPT_DIR}/openvpn_manager_api.py"
REMOTE_API_SOURCE_URL="${OPENVPN_MANAGER_API_URL:-https://raw.githubusercontent.com/Pweppapig0/OpenVPN/main/openvpn_manager_api.py}"
DOWNLOADED_API_SOURCE=""

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
    if [[ -e /etc/openvpn/server/server.conf || -d /etc/paymenter-openvpn-manager || -d /etc/openvpn/easy-rsa/pki ]]; then
        abort "Existing OpenVPN manager files were detected. Use a fresh host or clean the previous installation first."
    fi
}

need_local_assets() {
    if [[ -f "${API_SOURCE}" ]]; then
        return 0
    fi

    if [[ -z "${REMOTE_API_SOURCE_URL}" ]]; then
        abort "Missing ${API_SOURCE} and no remote fallback URL was configured."
    fi

    DOWNLOADED_API_SOURCE="$(mktemp /tmp/paymenter-openvpn-manager-api.XXXXXX.py)"

    if command -v curl >/dev/null 2>&1; then
        curl -fsSL "${REMOTE_API_SOURCE_URL}" -o "${DOWNLOADED_API_SOURCE}" || \
            abort "Failed to download openvpn_manager_api.py from ${REMOTE_API_SOURCE_URL}"
    elif command -v wget >/dev/null 2>&1; then
        wget -qO "${DOWNLOADED_API_SOURCE}" "${REMOTE_API_SOURCE_URL}" || \
            abort "Failed to download openvpn_manager_api.py from ${REMOTE_API_SOURCE_URL}"
    else
        abort "Neither curl nor wget is installed, so the companion API file cannot be downloaded automatically."
    fi

    if [[ ! -s "${DOWNLOADED_API_SOURCE}" ]]; then
        abort "Downloaded companion API file is empty: ${REMOTE_API_SOURCE_URL}"
    fi

    API_SOURCE="${DOWNLOADED_API_SOURCE}"
    echo "Downloaded companion API file from ${REMOTE_API_SOURCE_URL}"
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

    install -d -m 750 /etc/openvpn/server
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
${explicit_exit}
EOF
}

write_manager_config() {
    local dns_json
    dns_json="$(split_csv_to_json "${DEFAULT_DNS_SERVERS}")"

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

    chmod 640 /etc/paymenter-openvpn-manager/config.json
}

write_manager_assets() {
    install -d -m 750 /etc/paymenter-openvpn-manager /opt/paymenter-openvpn-manager /var/lib/paymenter-openvpn-manager /etc/openvpn/server/ccd
    install -m 755 "${API_SOURCE}" /opt/paymenter-openvpn-manager/openvpn_manager_api.py
    touch /var/lib/paymenter-openvpn-manager/ipp.txt
    touch /var/lib/paymenter-openvpn-manager/openvpn-status.log

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
    ufw --force enable
}

configure_iptables_persistent() {
    DEBIAN_FRONTEND=noninteractive apt-get install -y iptables-persistent netfilter-persistent

    iptables -t nat -C POSTROUTING -s "${VPN_SUBNET}" -o "${PUBLIC_NIC}" -j MASQUERADE 2>/dev/null || \
        iptables -t nat -A POSTROUTING -s "${VPN_SUBNET}" -o "${PUBLIC_NIC}" -j MASQUERADE

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

if [[ -n "${DOWNLOADED_API_SOURCE}" && -f "${DOWNLOADED_API_SOURCE}" ]]; then
    rm -f "${DOWNLOADED_API_SOURCE}"
fi

print_summary
