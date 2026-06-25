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

# ---------------------------------------------------------------------------
# Server & Domain Config
# ---------------------------------------------------------------------------

def get_public_ip():
    try:
        return subprocess.check_output(
            ["curl", "-s", "https://api.ipify.org"]
        ).decode().strip()
    except Exception as e:
        raise Exception(f"Unable to determine public IP: {e}")

VPS_IP = get_public_ip()

def get_primary_domain():
    hostname = subprocess.check_output(
        ["hostname", "-f"]
    ).decode().strip()

    parts = hostname.split(".")

    if len(parts) >= 3:
        return ".".join(parts[-3:])

    if len(parts) >= 2:
        return ".".join(parts[-2:])

    return hostname

PRIMARY_DOMAIN = get_primary_domain()


# ---> FIXED: Target Domain set to your live production domain <---
BASE_DOMAIN = cfg.require("domain")
TARGET_DOMAIN = cfg.require("fqdn")

if TARGET_DOMAIN == BASE_DOMAIN:
    HOST = "@"
else:
    HOST = TARGET_DOMAIN.replace("." + BASE_DOMAIN, "")

# ---------------------------------------------------------------------------
# Local Password Storage
# ---------------------------------------------------------------------------

PASSWORD_FILE = os.path.join(os.path.dirname(__file__), "mail-passwords.txt")

def generate_password(length=24):
    import secrets
    import string

    chars = string.ascii_letters + string.digits + "!@#$%^&*()-_"
    return "".join(secrets.choice(chars) for _ in range(length))

# Parse the single domain username
DOMAIN_USER = TARGET_DOMAIN

# ---------------------------------------------------------------------------
# Generate / Load Password for Single Domain
# ---------------------------------------------------------------------------

existing_passwords = {}

if os.path.exists(PASSWORD_FILE):
    with open(PASSWORD_FILE, "r") as f:
        for line in f:
            if ":" in line:
                d, p = line.strip().split(":", 1)
                existing_passwords[d] = p

# Assign or generate password
if TARGET_DOMAIN in existing_passwords:
    DOMAIN_PASSWORD = existing_passwords[TARGET_DOMAIN]
else:
    DOMAIN_PASSWORD = generate_password()

# Save back to file
with open(PASSWORD_FILE, "w") as f:
    f.write(f"{TARGET_DOMAIN}:{DOMAIN_PASSWORD}\n")

print("Password generated/stored in:", PASSWORD_FILE)

# ---------------------------------------------------------------------------
# Generate Dovecot Password File
# ---------------------------------------------------------------------------

dovecot_users_content = f"{DOMAIN_USER}:{{PLAIN}}{DOMAIN_PASSWORD}"

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def run(name: str, cmd: str, deps=None):
    return command.local.Command(
        name,
        create=cmd,
        opts=pulumi.ResourceOptions(
            depends_on=deps or []
        ),
    )


def put(
    name: str,
    path: str,
    content: str,
    owner: str = "root:root",
    mode: str = "644",
    deps=None,
):
    encoded = base64.b64encode(
        content.encode()
    ).decode()

    return run(
        name,
        f"""
echo '{encoded}' | base64 -d | sudo tee {path} > /dev/null
sudo chown {owner} {path}
sudo chmod {mode} {path}
""",
        deps=deps,
    )

write_dovecot_users = put(
    "write_dovecot_users",
    "/etc/dovecot/users",
    dovecot_users_content,
    owner="root:root",
    mode="644",
)

# ---------------------------------------------------------------------------
# OpenDKIM Directories
# ---------------------------------------------------------------------------

create_opendkim_dirs = run(
    "create_opendkim_dirs",
    """
sudo mkdir -p /etc/opendkim
sudo mkdir -p /etc/opendkim/keys
sudo mkdir -p /run/opendkim
""",
)

# ---------------------------------------------------------------------------
# TrustedHosts
# ---------------------------------------------------------------------------

trusted_hosts = [
    "127.0.0.1",
    "localhost",
    "106.51.72.179",
    VPS_IP,
    TARGET_DOMAIN,
    f"*.{TARGET_DOMAIN}",
    f"mail.{TARGET_DOMAIN}"
]

trustedhosts_content = "\n".join(trusted_hosts)

write_trustedhosts = put(
    "write_trustedhosts",
    "/etc/opendkim/TrustedHosts",
    trustedhosts_content,
    deps=[create_opendkim_dirs, write_dovecot_users],
)

# ---------------------------------------------------------------------------
# KeyTable
# ---------------------------------------------------------------------------

keytable_content = f"mail._domainkey.{TARGET_DOMAIN} {TARGET_DOMAIN}:mail:/etc/opendkim/keys/{TARGET_DOMAIN}/mail.private"

write_keytable = put(
    "write_keytable",
    "/etc/opendkim/KeyTable",
    keytable_content,
    deps=[create_opendkim_dirs],
)

# ---------------------------------------------------------------------------
# SigningTable
# ---------------------------------------------------------------------------

# ---> FIXED: Removed '*@' pattern to avoid regex compilation mismatches <---
signingtable_content = f"*@{TARGET_DOMAIN} mail._domainkey.{TARGET_DOMAIN}\n"

write_signingtable = put(
    "write_signingtable",
    "/etc/opendkim/SigningTable",
    signingtable_content,
    deps=[create_opendkim_dirs],
)

# ------------------------------------------------------------->
# Config DKIM Keys
# ------------------------------------------------------------->

# ---> FIXED: Table lines changed from 'refile:' to explicit 'file:' <---
write_opendkim_conf = put(
    "write_opendkim_conf",
    "/etc/opendkim.conf",
    """
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
""".strip(),
    owner="root:root",
    mode="644",
    deps=[write_keytable, write_signingtable],
)

configure_postfix_milter = run(
    "configure_postfix_milter",
    """
sudo postconf -e "milter_protocol = 6"
sudo postconf -e "milter_default_action = accept"
sudo postconf -e "smtpd_milters = inet:127.0.0.1:8891"
sudo postconf -e "non_smtpd_milters = inet:127.0.0.1:8891"
sudo systemctl restart postfix
""",
    deps=[write_opendkim_conf],
)

# ---------------------------------------------------------------------------
# Generate DKIM Keys
# ---------------------------------------------------------------------------

dkim_command = f"""
sudo mkdir -p /etc/opendkim/keys/{TARGET_DOMAIN}
sudo chown opendkim:opendkim /etc/opendkim/keys/{TARGET_DOMAIN}
sudo chmod 700 /etc/opendkim/keys/{TARGET_DOMAIN}

if [ ! -f /etc/opendkim/keys/{TARGET_DOMAIN}/mail.private ]; then
    sudo opendkim-genkey -b 2048 -D /etc/opendkim/keys/{TARGET_DOMAIN} -s mail -d {TARGET_DOMAIN}
fi

sudo chown opendkim:opendkim /etc/opendkim/keys/{TARGET_DOMAIN}/mail.private /etc/opendkim/keys/{TARGET_DOMAIN}/mail.txt
sudo chmod 600 /etc/opendkim/keys/{TARGET_DOMAIN}/mail.private
sudo chmod 644 /etc/opendkim/keys/{TARGET_DOMAIN}/mail.txt
"""

generate_dkim = run(
    "generate_dkim",
    dkim_command,
    deps=[
        write_trustedhosts,
        write_keytable,
        write_signingtable,
    ],
)

# ---------------------------------------------------------------------------
# Read DKIM Public Key
# ---------------------------------------------------------------------------

read_all_dkim = command.local.Command(
    "read_all_dkim",
    create=f"""
echo "=====DOMAIN:{TARGET_DOMAIN}====="
sudo cat /etc/opendkim/keys/{TARGET_DOMAIN}/mail.txt
""",
    opts=pulumi.ResourceOptions(
        depends_on=[generate_dkim]
    ),
)

# ---------------------------------------------------------------------------
# GoDaddy Helpers
# ---------------------------------------------------------------------------

def godaddy_headers(secret):
    return {
        "Authorization": f"sso-key {GODADDY_API_KEY}:{secret}",
        "Content-Type": "application/json",
        "Accept": "application/json",
    }


def update_record(
    secret,
    domain,
    record_type,
    name,
    value,
    ttl=600,
):
    url = f"https://api.godaddy.com/v1/domains/{domain}/records/{record_type}/{name}"

    response = requests.put(
        url,
        headers=godaddy_headers(secret),
        json=[{"data": value, "ttl": ttl}],
        timeout=60,
    )
    print(f"{domain} {record_type} {name}: {response.status_code}")
    response.raise_for_status()


def update_mx_record(secret, domain, name, target_mail):
    url = f"https://api.godaddy.com/v1/domains/{domain}/records/MX/{name}"

    response = requests.put(
        url,
        headers=godaddy_headers(secret),
        json=[{
            "data": target_mail,
            "priority": 10,
            "ttl": 600
        }],
        timeout=60,
    )

    print(f"{domain} MX {name}: {response.status_code}")
    response.raise_for_status()


pulumi.export(
    "mail_users",
    {
        TARGET_DOMAIN: {
            "username": DOMAIN_USER,
            "password": DOMAIN_PASSWORD,
            }
    },
)

# ---------------------------------------------------------------------------
# DNS Update
# ---------------------------------------------------------------------------

def update_dns(secret):
    txt_path = f"/etc/opendkim/keys/{TARGET_DOMAIN}/mail.txt"

    import subprocess

    try:
        dkim_text = subprocess.check_output(["sudo", "cat", txt_path], text=True)
    except subprocess.CalledProcessError as e:
        raise Exception(f"DKIM file could not be read at {txt_path}. Error: {e}")

    cleaned = (
        dkim_text
        .replace('"', '')
        .replace('(', '')
        .replace(')', '')
        .replace('\n', '')
    )

    cleaned = cleaned.split('; -----')[0]
    p_start = cleaned.find("p=")

    if p_start == -1:
        raise Exception(f"Unable to parse DKIM for {TARGET_DOMAIN}")

    public_key = cleaned[p_start + 2:].strip()
    dkim_value = f"v=DKIM1; k=rsa; p={public_key}"

    def fix_name(record_name):
        if HOST == "@":
            return record_name

        if record_name == "@":
            return HOST

        if record_name == "*":
            return f"*.{HOST}"

        return f"{record_name}.{HOST}"

    # Update Records
    update_record(secret, BASE_DOMAIN, "A", fix_name("@"), VPS_IP)
    update_record(secret, BASE_DOMAIN, "A", fix_name("mail"), VPS_IP)
    update_record(secret, BASE_DOMAIN, "A", fix_name("*"), VPS_IP)

    update_mx_record(
        secret,
        BASE_DOMAIN,
        fix_name("@"),
        f"mail.{TARGET_DOMAIN}"
    )

    update_record(
        secret,
        BASE_DOMAIN,
        "TXT",
        fix_name("@"),
        f"v=spf1 mx ip4:{VPS_IP} -all"
    )

    update_record(
        secret,
        BASE_DOMAIN,
        "TXT",
        fix_name("_dmarc"),
        f"v=DMARC1; p=reject; adkim=s; aspf=s; rua=mailto:dmarc@{TARGET_DOMAIN}"
    )

    update_record(
        secret,
        BASE_DOMAIN,
        "TXT",
        fix_name("mail._domainkey"),
        dkim_value
    )

    return f"Updated DNS for {TARGET_DOMAIN}"


# Execute DNS Updates
update_dns_records = pulumi.Output.all(
    read_all_dkim.stdout,
    GODADDY_API_SECRET,
).apply(
    lambda args: update_dns(args[1])
)


# ---------------------------------------------------------------------------
# Restart OpenDKIM
# ---------------------------------------------------------------------------

restart_opendkim = run(
    "restart_opendkim",
    """
sudo systemctl restart opendkim
sleep 3
sudo systemctl is-active opendkim
""",
    deps=[
        write_opendkim_conf,
        write_keytable,
        write_signingtable,
        write_trustedhosts,
    ],
)

verify_dkim = run(
    "verify_dkim",
    f"""
sudo opendkim-testkey \
    -d {TARGET_DOMAIN} \
    -s mail \
    -k /etc/opendkim/keys/{TARGET_DOMAIN}/mail.private \
    -vvv
""",
    deps=[restart_opendkim],
)

# ---------------------------------------------------------------------------
# Outputs
# ---------------------------------------------------------------------------

pulumi.export("target_domain", TARGET_DOMAIN)
pulumi.export("dns_update", update_dns_records)
pulumi.export("dkim_dump", read_all_dkim.stdout)