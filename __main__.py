import os
import re
import base64
import requests
import subprocess
import pulumi
import pulumi_command as command

# ---------------------------------------------------------------------------
# Pulumi Config
# ---------------------------------------------------------------------------
cfg = pulumi.Config()
GODADDY_API_KEY = cfg.require("godaddyApiKey")
GODADDY_API_SECRET = cfg.require_secret("godaddyApiSecret")

ROOT_DOMAIN = cfg.require("domain")   # e.g., "etmoney.co.in"
TARGET_DOMAIN = cfg.require("fqdn")   # e.g., "xyz.etmoney.co.in" or "googl.etmoney.co.in"

# Extract Subdomain Prefix cleanly
if TARGET_DOMAIN == ROOT_DOMAIN:
    SUBDOMAIN_PREFIX = ""
else:
    suffix = "." + ROOT_DOMAIN
    if TARGET_DOMAIN.endswith(suffix):
        SUBDOMAIN_PREFIX = TARGET_DOMAIN[:-len(suffix)]
    else:
        raise Exception(f"fqdn '{TARGET_DOMAIN}' is not under root domain '{ROOT_DOMAIN}'")

# Suffix helper to give Pulumi completely unique resource names per client run
RES_SUFFIX = f"_{SUBDOMAIN_PREFIX}" if SUBDOMAIN_PREFIX else "_root"

# ---------------------------------------------------------------------------
# Server & Domain Helpers
# ---------------------------------------------------------------------------
def get_public_ip():
    try:
        return subprocess.check_output(["curl", "-s", "https://api.ipify.org"]).decode().strip()
    except Exception as e:
        raise Exception(f"Unable to determine public IP: {e}")

VPS_IP = get_public_ip()
PASSWORD_FILE = os.path.join(os.path.dirname(__file__), "mail-passwords.txt")

def generate_password(length=24):
    import secrets
    import string
    chars = string.ascii_letters + string.digits + "!@#$%^&*()-_"
    return "".join(secrets.choice(chars) for _ in range(length))

root_user = re.sub(r"\..*$", "", ROOT_DOMAIN)
DOMAIN_USER = f"{SUBDOMAIN_PREFIX}-{root_user}" if SUBDOMAIN_PREFIX else root_user

# ---------------------------------------------------------------------------
# Thread-safe Password Management
# ---------------------------------------------------------------------------
existing_passwords = {}
if os.path.exists(PASSWORD_FILE):
    with open(PASSWORD_FILE, "r") as f:
        for line in f:
            if ":" in line:
                d, p = line.strip().split(":", 1)
                existing_passwords[d] = p

if TARGET_DOMAIN in existing_passwords:
    DOMAIN_PASSWORD = existing_passwords[TARGET_DOMAIN]
else:
    DOMAIN_PASSWORD = generate_password()
    existing_passwords[TARGET_DOMAIN] = DOMAIN_PASSWORD

with open(PASSWORD_FILE, "w") as f:
    for d, p in existing_passwords.items():
        f.write(f"{d}:{p}\n")

# ---------------------------------------------------------------------------
# Overwrite-Safe Pulumi Automation Core
# ---------------------------------------------------------------------------
def run(name: str, cmd: str, deps=None):
    return command.local.Command(
        f"{name}{RES_SUFFIX}", # Unique naming tracking per dynamic run
        create=cmd,
        opts=pulumi.ResourceOptions(depends_on=deps or []),
    )

# ---------------------------------------------------------------------------
# Append Configuration Sequences (No Overwriting)
# ---------------------------------------------------------------------------
create_opendkim_dirs = run(
    "create_opendkim_dirs",
    "sudo mkdir -p /etc/opendkim/keys /run/opendkim"
)

# Append variables sequentially using 'tee -a' so old profiles remain completely intact
append_mail_configs = run(
    "append_mail_configs",
    f"""
echo "{DOMAIN_USER}:{{PLAIN}}{DOMAIN_PASSWORD}" | sudo tee -a /etc/dovecot/users > /dev/null

echo "{TARGET_DOMAIN}" | sudo tee -a /etc/opendkim/TrustedHosts > /dev/null
echo "*.{TARGET_DOMAIN}" | sudo tee -a /etc/opendkim/TrustedHosts > /dev/null
echo "mail.{TARGET_DOMAIN}" | sudo tee -a /etc/opendkim/TrustedHosts > /dev/null

echo "mail._domainkey.{TARGET_DOMAIN} {TARGET_DOMAIN}:mail:/etc/opendkim/keys/{TARGET_DOMAIN}/mail.private" | sudo tee -a /etc/opendkim/KeyTable > /dev/null
echo "*@{TARGET_DOMAIN} mail._domainkey.{TARGET_DOMAIN}" | sudo tee -a /etc/opendkim/SigningTable > /dev/null
""",
    deps=[create_opendkim_dirs]
)

# ---------------------------------------------------------------------------
# Generate DKIM Keys for This Domain Context
# ---------------------------------------------------------------------------
generate_dkim = run(
    "generate_dkim",
    f"""
sudo mkdir -p /etc/opendkim/keys/{TARGET_DOMAIN}
sudo chown opendkim:opendkim /etc/opendkim/keys/{TARGET_DOMAIN}
sudo chmod 700 /etc/opendkim/keys/{TARGET_DOMAIN}

if [ ! -f /etc/opendkim/keys/{TARGET_DOMAIN}/mail.private ]; then
    sudo opendkim-genkey -b 2048 -D /etc/opendkim/keys/{TARGET_DOMAIN} -s mail -d {TARGET_DOMAIN}
fi

sudo chown opendkim:opendkim /etc/opendkim/keys/{TARGET_DOMAIN}/mail.private /etc/opendkim/keys/{TARGET_DOMAIN}/mail.txt
sudo chmod 600 /etc/opendkim/keys/{TARGET_DOMAIN}/mail.private
sudo chmod 644 /etc/opendkim/keys/{TARGET_DOMAIN}/mail.txt
""",
    deps=[append_mail_configs],
)

read_all_dkim = command.local.Command(
    f"read_all_dkim{RES_SUFFIX}",
    create=f"sudo cat /etc/opendkim/keys/{TARGET_DOMAIN}/mail.txt",
    opts=pulumi.ResourceOptions(depends_on=[generate_dkim]),
)

# ---------------------------------------------------------------------------
# Global Configurations Management (Run safely once or updates seamlessly)
# ---------------------------------------------------------------------------
global_configs = run(
    "global_configs",
    """
if [ ! -f /etc/opendkim.conf ]; then
sudo tee /etc/opendkim.conf << 'EOF'
Syslog yes
LogWhy yes
UMask 002
Canonicalization relaxed/simple
Mode sv
Socket inet:8891@127.0.0.1
UserID opendkim
PidFile /run/opendkim/opendkim.pid
KeyTable file:/etc/opendkim/KeyTable
SigningTable refile:/etc/opendkim/SigningTable
ExternalIgnoreList /etc/opendkim/TrustedHosts
InternalHosts /etc/opendkim/TrustedHosts
EOF
fi

sudo postconf -e "milter_protocol = 6"
sudo postconf -e "milter_default_action = accept"
sudo postconf -e "smtpd_milters = inet:127.0.0.1:8891"
sudo postconf -e "non_smtpd_milters = inet:127.0.0.1:8891"

sudo systemctl restart postfix
sudo systemctl restart opendkim
""",
    deps=[generate_dkim]
)

# ---------------------------------------------------------------------------
# GoDaddy Safe Patch Automation (No Overwriting across instances)
# ---------------------------------------------------------------------------
def patch_godaddy_records(secret, records_list):
    """
    Submits a context update via PATCH to incrementally add entries without
    disturbing configurations belonging to your other active subdomains.
    """
    url = f"https://api.godaddy.com/v1/domains/{ROOT_DOMAIN}/records"
    response = requests.patch(
        url,
        headers={
            "Authorization": f"sso-key {GODADDY_API_KEY}:{secret}",
            "Content-Type": "application/json"
        },
        json=records_list,
        timeout=60,
    )
    print(f"GoDaddy Incremental Patch Status: {response.status_code}")
    response.raise_for_status()

def update_dns(secret):
    txt_path = f"/etc/opendkim/keys/{TARGET_DOMAIN}/mail.txt"
    try:
        dkim_text = subprocess.check_output(["sudo", "cat", txt_path], text=True)
    except subprocess.CalledProcessError as e:
        raise Exception(f"DKIM file could not be read at {txt_path}. Error: {e}")

    cleaned = dkim_text.replace('"', '').replace('(', '').replace(')', '').replace('\n', '')
    cleaned = cleaned.split('; -----')[0]
    p_start = cleaned.find("p=")
    if p_start == -1:
        raise Exception(f"Unable to parse DKIM for {TARGET_DOMAIN}")

    public_key = cleaned[p_start + 2:].strip()
    dkim_value = f"v=DKIM1; k=rsa; p={public_key}"

    def fix_name(record_name):
        if not SUBDOMAIN_PREFIX:
            return record_name
        if record_name == "@":
            return SUBDOMAIN_PREFIX
        if record_name == "*":
            return f"*.{SUBDOMAIN_PREFIX}"
        return f"{record_name}.{SUBDOMAIN_PREFIX}"

    # Safe payload targeted specifically to this client's unique path prefix
    patch_payload = [
        {"type": "A", "name": fix_name("@"), "data": VPS_IP, "ttl": 600},
        {"type": "A", "name": fix_name("mail"), "data": VPS_IP, "ttl": 600},
        {"type": "A", "name": fix_name("*"), "data": VPS_IP, "ttl": 600},
        {"type": "MX", "name": fix_name("@"), "data": f"mail.{TARGET_DOMAIN}", "priority": 10, "ttl": 600},
        {"type": "TXT", "name": fix_name("@"), "data": f"v=spf1 mx ip4:{VPS_IP} -all", "ttl": 600},
        {"type": "TXT", "name": fix_name("_dmarc"), "data": f"v=DMARC1; p=reject; adkim=s; aspf=s; rua=mailto:dmarc@{TARGET_DOMAIN}", "ttl": 600},
        {"type": "TXT", "name": fix_name("mail._domainkey"), "data": dkim_value, "ttl": 600}
    ]

    patch_godaddy_records(secret, patch_payload)
    return f"Successfully added isolated records for {TARGET_DOMAIN}"

# Execute DNS update
update_dns_records = pulumi.Output.all(
    read_all_dkim.stdout,
    GODADDY_API_SECRET,
).apply(lambda args: update_dns(args[1]))

# ---------------------------------------------------------------------------
# Outputs
# ---------------------------------------------------------------------------
pulumi.export("target_domain", TARGET_DOMAIN)
pulumi.export("dns_update", update_dns_records)
pulumi.export("mail_users", {
    TARGET_DOMAIN: {
        "username": DOMAIN_USER,
        "password": DOMAIN_PASSWORD,
    }
})