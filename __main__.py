import json
import requests
import pulumi
import pulumi_command as command

# ---------------------------------------------------------------------------
# Pulumi Config
# ---------------------------------------------------------------------------

cfg = pulumi.Config()

# ---------------------------------------------------------------------------
# Domain Configuration
# ---------------------------------------------------------------------------

# ---------------------------------------------------------------------------
# Domain Configuration
# ---------------------------------------------------------------------------

ROOT_DOMAIN = cfg.require("domain").strip().lower()
DOMAIN = cfg.require("fqdn").strip().lower()

SELECTOR = (
    cfg.get("selector")
    or "default"
).strip().lower()
# ---------------------------------------------------------------------------
# SMTP Server
# ---------------------------------------------------------------------------

SERVER_HOSTNAME = "blog.etmoney.co.in"

SMTP_IP = "51.79.63.247"

KUBERNETES_POD_CIDR = "10.42.0.0/16"

# ---------------------------------------------------------------------------
# GoDaddy Credentials
# ---------------------------------------------------------------------------

GODADDY_API_KEY = cfg.require("godaddyApiKey")
GODADDY_API_SECRET = cfg.require_secret("godaddyApiSecret")

# ---------------------------------------------------------------------------
# OpenDKIM Paths
# ---------------------------------------------------------------------------

DOMAIN_KEY_DIR = f"/etc/opendkim/keys/{DOMAIN}"

PRIVATE_KEY = f"{DOMAIN_KEY_DIR}/{SELECTOR}.private"

PUBLIC_KEY = f"{DOMAIN_KEY_DIR}/{SELECTOR}.txt"

TRUSTED_HOSTS = "/etc/opendkim/TrustedHosts"

KEY_TABLE = "/etc/opendkim/KeyTable"

SIGNING_TABLE = "/etc/opendkim/SigningTable"

# ---------------------------------------------------------------------------
# Helper
# ---------------------------------------------------------------------------

def run(name: str, cmd: str, deps=None, trigger_values=None):

    triggers = [cmd] if trigger_values is None else trigger_values

    return command.local.Command(
        name,
        create=cmd,
        triggers=triggers,
        opts=pulumi.ResourceOptions(
            depends_on=deps or []
        ),
    )

# ---------------------------------------------------------------------------
# Generate DKIM Keys
# ---------------------------------------------------------------------------

generate_dkim = run(
    "generate_dkim",
    f"""
set -e

echo "======================================="
echo "Generating DKIM for {DOMAIN}"
echo "======================================="

sudo mkdir -p "{DOMAIN_KEY_DIR}"

# Generate only when the private key does not already exist.
if ! sudo test -f "{PRIVATE_KEY}"; then

    echo "Generating a new DKIM key..."

    sudo opendkim-genkey \
        -b 2048 \
        -r \
        -D "{DOMAIN_KEY_DIR}" \
        -s "{SELECTOR}" \
        -d "{DOMAIN}"

    echo "DKIM key generated."

else

    echo "DKIM already exists. Keeping the existing key."

fi

# Verify generated files using sudo because the normal user
# may not be allowed to traverse /etc/opendkim/keys.
if ! sudo test -f "{PRIVATE_KEY}"; then
    echo "ERROR: Private DKIM key was not created."
    exit 1
fi

if ! sudo test -f "{PUBLIC_KEY}"; then
    echo "ERROR: DKIM TXT file was not created."
    exit 1
fi

sudo chown -R opendkim:opendkim "{DOMAIN_KEY_DIR}"
sudo chmod 750 "{DOMAIN_KEY_DIR}"
sudo chmod 600 "{PRIVATE_KEY}"
sudo chmod 644 "{PUBLIC_KEY}"

echo ""
echo "Generated files:"
sudo ls -lh "{DOMAIN_KEY_DIR}"

echo ""
echo "======================================="
""",
    trigger_values=[
        DOMAIN,
        SELECTOR,
    ],
)
# ---------------------------------------------------------------------------
# Update TrustedHosts
# ---------------------------------------------------------------------------

update_trusted_hosts = run(
    "update_trusted_hosts",
    f"""
set -e

echo "======================================="
echo "Updating TrustedHosts"
echo "======================================="

sudo touch "{TRUSTED_HOSTS}"

# Customer sending domain
sudo grep -qxF "{DOMAIN}" "{TRUSTED_HOSTS}" || \
echo "{DOMAIN}" | sudo tee -a "{TRUSTED_HOSTS}" >/dev/null

# IP used by the worker when connecting to Postfix
sudo grep -qxF "{SMTP_IP}" "{TRUSTED_HOSTS}" || \
echo "{SMTP_IP}" | sudo tee -a "{TRUSTED_HOSTS}" >/dev/null

# Stable SMTP server hostname
sudo grep -qxF "{SERVER_HOSTNAME}" "{TRUSTED_HOSTS}" || \
echo "{SERVER_HOSTNAME}" | sudo tee -a "{TRUSTED_HOSTS}" >/dev/null

# Kubernetes Worker Pod network
sudo grep -qxF "{KUBERNETES_POD_CIDR}" "{TRUSTED_HOSTS}" || \
echo "{KUBERNETES_POD_CIDR}" | sudo tee -a "{TRUSTED_HOSTS}" >/dev/null

echo ""
echo "Current TrustedHosts:"
sudo cat "{TRUSTED_HOSTS}"

echo ""
echo "======================================="
""",
    deps=[
        generate_dkim,
    ],
    trigger_values=[
        DOMAIN,
        SMTP_IP,
        SERVER_HOSTNAME,
        KUBERNETES_POD_CIDR,
        "trusted-hosts-v2",
    ],
)

#----------------------------------------------------------------------------
#update key table
# ---------------------------------------------------------------------------

update_key_table = run(
    "update_key_table",
    f"""
set -e

echo "======================================="
echo "Updating KeyTable"
echo "======================================="

sudo touch {KEY_TABLE}

ENTRY="{SELECTOR}._domainkey.{DOMAIN} {DOMAIN}:{SELECTOR}:{PRIVATE_KEY}"

if ! sudo grep -qxF "$ENTRY" {KEY_TABLE}; then

    echo "$ENTRY" | sudo tee -a {KEY_TABLE} >/dev/null

    echo "Added:"
    echo "$ENTRY"

else

    echo "Entry already exists."

fi

echo ""
echo "Current KeyTable:"
sudo cat {KEY_TABLE}

echo ""
echo "======================================="

""",
    deps=[
        update_trusted_hosts,
    ],
    trigger_values=[
        DOMAIN,
        SELECTOR,
        PRIVATE_KEY,
    ],
)

# ---------------------------------------------------------------------------
# Update SigningTable
# ---------------------------------------------------------------------------

update_signing_table = run(
    "update_signing_table",
    f"""
set -e

echo "======================================="
echo "Updating SigningTable"
echo "======================================="

sudo touch {SIGNING_TABLE}

ENTRY="*@{DOMAIN} {SELECTOR}._domainkey.{DOMAIN}"

if ! sudo grep -qxF "$ENTRY" {SIGNING_TABLE}; then

    echo "$ENTRY" | sudo tee -a {SIGNING_TABLE} >/dev/null

    echo "Added:"
    echo "$ENTRY"

else

    echo "Entry already exists."

fi

echo ""
echo "Current SigningTable:"
sudo cat {SIGNING_TABLE}

echo ""
echo "======================================="

""",
    deps=[
        update_key_table,
    ],
    trigger_values=[
        DOMAIN,
        SELECTOR,
    ],
)

# ---------------------------------------------------------------------------
# Reload OpenDKIM & Postfix
# ---------------------------------------------------------------------------

reload_services = run(
    "reload_services",
    f"""
set -e

echo "======================================="
echo "Reloading Services"
echo "======================================="

# ------------------------------------------------------------------
# Fix Permissions
# ------------------------------------------------------------------

sudo chown -R opendkim:opendkim {DOMAIN_KEY_DIR}

sudo chown root:opendkim /etc/opendkim/keys
sudo chmod 750 /etc/opendkim/keys

sudo chmod 750 {DOMAIN_KEY_DIR}

sudo chmod 600 {PRIVATE_KEY}

sudo chmod 644 {PUBLIC_KEY}

sudo chown root:root {TRUSTED_HOSTS}
sudo chmod 644 {TRUSTED_HOSTS}

sudo chown root:root {KEY_TABLE}
sudo chmod 644 {KEY_TABLE}

sudo chown root:root {SIGNING_TABLE}
sudo chmod 644 {SIGNING_TABLE}

# ------------------------------------------------------------------
# Test DKIM Configuration
# ------------------------------------------------------------------

echo ""
echo "Testing DKIM..."

sudo opendkim-testkey \
    -d {DOMAIN} \
    -s {SELECTOR} \
    -k {PRIVATE_KEY} \
    -vvv || true

# ------------------------------------------------------------------
# Restart OpenDKIM
# ------------------------------------------------------------------

echo ""
echo "Restarting OpenDKIM..."

sudo systemctl restart opendkim

sleep 3

sudo systemctl is-active --quiet opendkim

echo "OpenDKIM is running."

# ------------------------------------------------------------------
# Restart Postfix
# ------------------------------------------------------------------

echo ""
echo "Restarting Postfix..."

# Send directly to recipient MX servers.
# Do not relay back into this same Postfix instance.
sudo postconf -e 'relayhost ='

# Force outbound mail to use the redirector/sending IP.
sudo postconf -e 'smtp_bind_address = {SMTP_IP}'

# Keep signed message content unchanged after OpenDKIM signs it.
sudo postconf -e 'smtp_header_checks ='
sudo postconf -e 'smtp_mime_header_checks ='
sudo postconf -e 'smtp_nested_header_checks ='
sudo postconf -e 'smtp_body_checks ='
sudo postconf -e 'smtp_generic_maps ='
sudo postconf -e 'sender_canonical_maps ='
sudo postconf -e 'recipient_canonical_maps ='
sudo postconf -e 'canonical_maps ='
sudo postconf -e 'masquerade_domains ='
sudo postconf -e 'remote_header_rewrite_domain ='

sudo postfix check

sudo systemctl restart postfix

sleep 3

sudo systemctl is-active --quiet postfix

echo "Postfix is running."

# ------------------------------------------------------------------
# Status
# ------------------------------------------------------------------

echo ""
echo "========== SERVICES =========="

systemctl --no-pager --full status opendkim | head -20

echo ""

systemctl --no-pager --full status postfix | head -20

echo ""

echo "=============================="

""",
    deps=[
        update_signing_table,
    ],
    trigger_values=[
        DOMAIN,
        SELECTOR,
        SMTP_IP,
        "postfix-direct-routing-v1"
    ],
)

# ---------------------------------------------------------------------------
# Read DKIM Public Key
# ---------------------------------------------------------------------------

read_dkim = run(
    "read_dkim",
    f"""
set -e

if ! sudo test -f "{PUBLIC_KEY}"; then
    echo "ERROR: DKIM public-key file does not exist: {PUBLIC_KEY}" >&2
    exit 1
fi

# Join only the quoted TXT fragments generated by opendkim-genkey,
# then extract only the p= public-key value.
sudo awk -F'"' '
{{
    for (i = 2; i <= NF; i += 2) {{
        printf "%s", $i
    }}
}}
END {{
    print ""
}}
' "{PUBLIC_KEY}" |
sed -n 's/.*p=\\([A-Za-z0-9+\\/=]*\\).*/\\1/p'
""",
    deps=[
        reload_services,
    ],
    trigger_values=[
        DOMAIN,
        SELECTOR,
        "dkim-parser-v2",
    ],
)


# ---------------------------------------------------------------------------
# Validate Extracted DKIM Public Key
# ---------------------------------------------------------------------------

def extract_dkim_public_key(output: str) -> str:
    import re

    public_key = output.strip()

    if not public_key:
        raise ValueError(
            "Extracted DKIM public key is empty"
        )

    if not re.fullmatch(
        r"[A-Za-z0-9+/=]+",
        public_key,
    ):
        raise ValueError(
            "Extracted DKIM public key contains invalid characters"
        )

    if len(public_key) < 300:
        raise ValueError(
            f"Extracted DKIM public key is unexpectedly short: "
            f"{len(public_key)} characters"
        )

    return public_key


dkim_public_key = read_dkim.stdout.apply(
    extract_dkim_public_key
)
# ---------------------------------------------------------------------------
# Pulumi Exports
# ---------------------------------------------------------------------------

pulumi.export(
    "domain",
    DOMAIN,
)

pulumi.export(
    "dkim_public_key",
    dkim_public_key,
)
# ---------------------------------------------------------------------------
# GoDaddy DNS Configuration
# ---------------------------------------------------------------------------

# Registered GoDaddy DNS zone.
#
# Examples:
# DOMAIN = "mulberri.in"
# ROOT_DOMAIN = "mulberri.in"
#
# DOMAIN = "blog.etmoney.co.in"
# ROOT_DOMAIN = "etmoney.co.in"
DNS_TTL = 600


# ---------------------------------------------------------------------------
# Determine GoDaddy Record Name
# ---------------------------------------------------------------------------

def get_dns_host(domain: str, root_domain: str) -> str:
    normalized_domain = domain.lower().rstrip(".")
    normalized_root = root_domain.lower().rstrip(".")

    if normalized_domain == normalized_root:
        return "@"

    suffix = f".{normalized_root}"

    if not normalized_domain.endswith(suffix):
        raise ValueError(
            f"Domain '{domain}' is not inside "
            f"GoDaddy zone '{root_domain}'"
        )

    host = normalized_domain[:-len(suffix)]

    if not host:
        return "@"

    return host


# ---------------------------------------------------------------------------
# GoDaddy API Helpers
# ---------------------------------------------------------------------------

def build_godaddy_headers(
    api_key: str,
    api_secret: str,
) -> dict:
    return {
        "Authorization": (
            f"sso-key {api_key}:{api_secret}"
        ),
        "Content-Type": "application/json",
        "Accept": "application/json",
    }


def godaddy_request(
    method: str,
    url: str,
    headers: dict,
    payload=None,
):
    response = requests.request(
        method=method,
        url=url,
        headers=headers,
        json=payload,
        timeout=30,
    )

    if not response.ok:
        raise RuntimeError(
            "GoDaddy API request failed\n"
            f"Method: {method}\n"
            f"URL: {url}\n"
            f"Status: {response.status_code}\n"
            f"Response: {response.text}"
        )

    if not response.text.strip():
        return None

    try:
        return response.json()
    except ValueError:
        return response.text


def get_godaddy_records(
    root_domain: str,
    record_type: str,
    record_name: str,
    headers: dict,
) -> list:
    url = (
        "https://api.godaddy.com/v1/domains/"
        f"{root_domain}/records/"
        f"{record_type}/{record_name}"
    )

    result = godaddy_request(
        method="GET",
        url=url,
        headers=headers,
    )

    return result or []


def replace_godaddy_records(
    root_domain: str,
    record_type: str,
    record_name: str,
    records: list,
    headers: dict,
):
    url = (
        "https://api.godaddy.com/v1/domains/"
        f"{root_domain}/records/"
        f"{record_type}/{record_name}"
    )

    godaddy_request(
        method="PUT",
        url=url,
        headers=headers,
        payload=records,
    )


# ---------------------------------------------------------------------------
# Preserve Unrelated TXT Records
# ---------------------------------------------------------------------------

def replace_managed_txt_record(
    root_domain: str,
    record_name: str,
    record_value: str,
    managed_prefix: str,
    headers: dict,
):
    existing_records = get_godaddy_records(
        root_domain=root_domain,
        record_type="TXT",
        record_name=record_name,
        headers=headers,
    )

    preserved_records = []

    for record in existing_records:
        current_value = str(
            record.get("data", "")
        ).strip()

        if not current_value.lower().startswith(
            managed_prefix.lower()
        ):
            preserved_records.append(record)

    preserved_records.append(
        {
            "data": record_value,
            "ttl": DNS_TTL,
        }
    )

    replace_godaddy_records(
        root_domain=root_domain,
        record_type="TXT",
        record_name=record_name,
        records=preserved_records,
        headers=headers,
    )


# ---------------------------------------------------------------------------
# Update DNS Records
# ---------------------------------------------------------------------------

def update_godaddy_dns(
    api_key: str,
    api_secret: str,
    public_key: str,
) -> str:
    # Prevent DNS changes during `pulumi preview`.
    if pulumi.runtime.is_dry_run():
        return (
            f"DNS update planned for {DOMAIN}"
        )

    headers = build_godaddy_headers(
        api_key,
        api_secret,
    )

    host = get_dns_host(
        DOMAIN,
        ROOT_DOMAIN,
    )

    print(f"Domain       : {DOMAIN}")
    print(f"GoDaddy zone : {ROOT_DOMAIN}")
    print(f"Record host  : {host}")
    print(f"SMTP IP      : {SMTP_IP}")
    print(f"MX target    : {SERVER_HOSTNAME}")

    # ------------------------------------------------------------------
    # A Record
    # ------------------------------------------------------------------

    replace_godaddy_records(
        root_domain=ROOT_DOMAIN,
        record_type="A",
        record_name=host,
        records=[
            {
                "data": SMTP_IP,
                "ttl": DNS_TTL,
            }
        ],
        headers=headers,
    )

    print("A record updated.")

    # ------------------------------------------------------------------
    # MX Record
    # ------------------------------------------------------------------

    replace_godaddy_records(
        root_domain=ROOT_DOMAIN,
        record_type="MX",
        record_name=host,
        records=[
            {
                "data": SERVER_HOSTNAME,
                "priority": 10,
                "ttl": DNS_TTL,
            }
        ],
        headers=headers,
    )

    print("MX record updated.")

    # ------------------------------------------------------------------
    # SPF Record
    # ------------------------------------------------------------------

    replace_managed_txt_record(
        root_domain=ROOT_DOMAIN,
        record_name=host,
        record_value=(
            f"v=spf1 ip4:{SMTP_IP} ~all"
        ),
        managed_prefix="v=spf1",
        headers=headers,
    )

    print("SPF record updated.")

    # ------------------------------------------------------------------
    # DKIM Record
    # ------------------------------------------------------------------

    if host == "@":
        dkim_record_name = (
            f"{SELECTOR}._domainkey"
        )
    else:
        dkim_record_name = (
            f"{SELECTOR}._domainkey.{host}"
        )

    replace_managed_txt_record(
        root_domain=ROOT_DOMAIN,
        record_name=dkim_record_name,
        record_value=(
            f"v=DKIM1; k=rsa; p={public_key}"
        ),
        managed_prefix="v=DKIM1",
        headers=headers,
    )

    print("DKIM record updated.")

    # ------------------------------------------------------------------
    # DMARC Record
    # ------------------------------------------------------------------

    if host == "@":
        dmarc_record_name = "_dmarc"
    else:
        dmarc_record_name = (
            f"_dmarc.{host}"
        )

    replace_managed_txt_record(
        root_domain=ROOT_DOMAIN,
        record_name=dmarc_record_name,
        record_value="v=DMARC1; p=none",
        managed_prefix="v=DMARC1",
        headers=headers,
    )

    print("DMARC record updated.")

    return (
        f"DNS successfully updated for {DOMAIN}; "
        f"zone={ROOT_DOMAIN}; host={host}"
    )


# ---------------------------------------------------------------------------
# Execute GoDaddy DNS Update
# ---------------------------------------------------------------------------

dns_update = pulumi.Output.all(
    GODADDY_API_KEY,
    GODADDY_API_SECRET,
    dkim_public_key,
).apply(
    lambda values: update_godaddy_dns(
        api_key=values[0],
        api_secret=values[1],
        public_key=values[2],
    )
)


# ---------------------------------------------------------------------------
# Final Pulumi Exports
# ---------------------------------------------------------------------------

pulumi.export(
    "root_domain",
    ROOT_DOMAIN,
)

pulumi.export(
    "server_hostname",
    SERVER_HOSTNAME,
)

pulumi.export(
    "smtp_ip",
    SMTP_IP,
)

pulumi.export(
    "dkim_selector",
    SELECTOR,
)

pulumi.export(
    "dns_update",
    dns_update,
)
