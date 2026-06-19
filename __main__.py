import os
import re
import base64
import requests

import pulumi
import pulumi_command as command


# ---------------------------------------------------------------------------
# Pulumi Config
# ---------------------------------------------------------------------------

cfg = pulumi.Config()

GODADDY_API_KEY = cfg.require("godaddyApiKey")
GODADDY_API_SECRET = cfg.require_secret("godaddyApiSecret")

# ---------------------------------------------------------------------------
# Server Config
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

DOMAINS_FILE = "/home/ubuntu/domains.txt"

# ---------------------------------------------------------------------------
# Local Password Storage (NEW)
# ---------------------------------------------------------------------------

PASSWORD_FILE = os.path.join(os.path.dirname(__file__), "mail-passwords.txt")

def generate_password(length=24):
    import secrets
    import string

    chars = string.ascii_letters + string.digits + "!@#$%^&*()-_"
    return "".join(secrets.choice(chars) for _ in range(length))

# ---------------------------------------------------------------------------
# Read Domains From domains.txt
# ---------------------------------------------------------------------------

if not os.path.exists(DOMAINS_FILE):
    with open(DOMAINS_FILE, "w") as f:
        pass

domains = set()
domain_users = {}
domain_passwords = {}

with open(DOMAINS_FILE, "r") as f:
    for line in f:
        domain = line.strip()

        if not domain:
            continue

        domains.add(domain)

        username = re.sub(r"\..*$", "", domain)
        domain_users[domain] = username

DOMAINS = sorted(domains)

# ---------------------------------------------------------------------------
# Generate / Load Passwords
# ---------------------------------------------------------------------------

existing_passwords = {}

if os.path.exists(PASSWORD_FILE):
    with open(PASSWORD_FILE, "r") as f:
        for line in f:
            if ":" in line:
                d, p = line.strip().split(":", 1)
                existing_passwords[d] = p

for domain in DOMAINS:
    if domain in existing_passwords:
        domain_passwords[domain] = existing_passwords[domain]
    else:
        domain_passwords[domain] = generate_password()

# Save back to file
with open(PASSWORD_FILE, "w") as f:
    for domain in DOMAINS:
        f.write(f"{domain}:{domain_passwords[domain]}\n")

print("Passwords generated/stored in:", PASSWORD_FILE)

# ---------------------------------------------------------------------------
# Generate Dovecot Password File
# ---------------------------------------------------------------------------

dovecot_users = []

for domain in DOMAINS:

    username = domain_users[domain]
    password = domain_passwords[domain]

    dovecot_users.append(
        f"{username}:{password}"
    )

dovecot_users_content = "\n".join(dovecot_users)

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
    VPS_IP,
]

for domain in DOMAINS:
    trusted_hosts.append(domain)
    trusted_hosts.append(f"*.{domain}")
    trusted_hosts.append(f"mail.{domain}")

trustedhosts_content = "\n".join(trusted_hosts)

write_trustedhosts = put(
    "write_trustedhosts",
    "/etc/opendkim/TrustedHosts",
    trustedhosts_content,
    deps=[create_opendkim_dirs,write_dovecot_users],
)

# ---------------------------------------------------------------------------
# KeyTable
# ---------------------------------------------------------------------------

keytable_content = "\n".join(
    [
        f"mail._domainkey.{domain} {domain}:mail:/etc/opendkim/keys/{domain}/mail.private"
        for domain in DOMAINS
    ]
)

write_keytable = put(
    "write_keytable",
    "/etc/opendkim/KeyTable",
    keytable_content,
    deps=[create_opendkim_dirs],
)

# ---------------------------------------------------------------------------
# SigningTable
# ---------------------------------------------------------------------------

signingtable_content = "\n".join(
    [
        f"*@{domain} mail._domainkey.{domain}"
        for domain in DOMAINS
    ]
)

write_signingtable = put(
    "write_signingtable",
    "/etc/opendkim/SigningTable",
    signingtable_content,
    deps=[create_opendkim_dirs],
)

# ------------------------------------------------------------->
# Config DKIM Keys
# ------------------------------------------------------------->

write_opendkim_conf = put(
    "write_opendkim_conf",
    "/etc/opendkim.conf",
    """
Syslog yes
LogWhy yes
UMask 002

Canonicalization relaxed/simple
Mode sv
Socket inet:8891@localhost

UserID opendkim
PidFile /run/opendkim/opendkim.pid

KeyTable /etc/opendkim/KeyTable
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
sudo postconf -e "smtpd_milters = inet:localhost:8891"
sudo postconf -e "non_smtpd_milters = inet:localhost:8891"
sudo systemctl restart postfix
""",
    deps=[write_opendkim_conf],
)

# ---------------------------------------------------------------------------
# Generate DKIM Keys
# ---------------------------------------------------------------------------

dkim_commands = []

for domain in DOMAINS:
    dkim_commands.append(
        f"""
if [ ! -f /etc/opendkim/keys/{domain}/mail.txt ]; then

    sudo mkdir -p /etc/opendkim/keys/{domain}

    # Correct ownership BEFORE key generation
    sudo chown opendkim:opendkim /etc/opendkim/keys/{domain}
    sudo chmod 700 /etc/opendkim/keys/{domain}

    # Generate DKIM key (FIXED LINE CONTINUATION)
    sudo opendkim-genkey \
        -b 2048 \
        -D /etc/opendkim/keys/{domain} \
        -s mail \
        -d {domain}

    # Ensure correct ownership AFTER generation
    sudo chown opendkim:opendkim /etc/opendkim/keys/{domain}/mail.private
    sudo chmod 600 /etc/opendkim/keys/{domain}/mail.private

    sudo chown opendkim:opendkim /etc/opendkim/keys/{domain}/mail.txt
    sudo chmod 644 /etc/opendkim/keys/{domain}/mail.txt

fi
"""
    )

generate_dkim = run(
    "generate_dkim",
    "\n".join(dkim_commands),
    deps=[
        write_trustedhosts,
        write_keytable,
        write_signingtable,
    ],
)
# ---------------------------------------------------------------------------
# Read All DKIM Public Keys
# ---------------------------------------------------------------------------

read_all_dkim = command.local.Command(
    "read_all_dkim",
    create="""
for d in $(ls /etc/opendkim/keys); do
    echo "=====DOMAIN:$d====="
    cat /etc/opendkim/keys/$d/mail.txt
done
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
    url = (
        f"https://api.godaddy.com/v1/domains/"
        f"{domain}/records/{record_type}/{name}"
    )

    response = requests.put(
        url,
        headers=godaddy_headers(secret),
        json=[
            {
                "data": value,
                "ttl": ttl,
            }
        ],
        timeout=60,
    )

    print(
        f"{domain} {record_type} {name}: "
        f"{response.status_code}"
    )

    response.raise_for_status()


def update_mx_record(
    secret,
    domain,
):
    url = (
        f"https://api.godaddy.com/v1/domains/"
        f"{domain}/records/MX/@"
    )

    response = requests.put(
        url,
        headers=godaddy_headers(secret),
        json=[
            {
                "data": f"mail.{domain}",
                "priority": 10,
                "ttl": 600,
            }
        ],
        timeout=60,
    )

    print(
        f"{domain} MX: "
        f"{response.status_code}"
    )

    response.raise_for_status()


pulumi.export(
    "mail_users",
    {
        domain: {
            "username": domain_users[domain],
            "password": domain_passwords[domain],
        }
        for domain in DOMAINS
    },
)

# ---------------------------------------------------------------------------
# DNS Update
# -------------------------------------------------------------------------------------------------------------

def update_dns(secret):

    for domain in DOMAINS:

        txt_path = (
            f"/etc/opendkim/keys/"
            f"{domain}/mail.txt"
        )
        if not os.path.isfile(txt_path):
            print(
                f"Skipping {domain}, "
                f"DKIM file not found yet"
            )
            continue

        with open(txt_path, "r") as f:
            dkim_text = f.read()

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
            raise Exception(
                f"Unable to parse DKIM for {domain}"
            )

        public_key = cleaned[p_start + 2:].strip()

        dkim_value = (
            f"v=DKIM1; k=rsa; p={public_key}"
        )


        # -------------------------------------------------
        # A Records
        # -------------------------------------------------

        update_record(
            secret,
            domain,
            "A",
            "@",
            VPS_IP,
        )

        update_record(
            secret,
            domain,
            "A",
            "mail",
            VPS_IP,
        )
        update_record(
            secret,
            domain,
            "A",
            "*",
            VPS_IP,
        )

        # -------------------------------------------------
        # MX
        # -------------------------------------------------

        update_mx_record(
            secret,
            domain,
        )

        # -------------------------------------------------
        # SPF
        # -------------------------------------------------

        update_record(
            secret,
            domain,
            "TXT",
            "@",
            f"v=spf1 mx ip4:{VPS_IP} -all",
        )

        # -------------------------------------------------
        # DMARC
        # -------------------------------------------------

        update_record(
            secret,
            domain,
            "TXT",
            "_dmarc",
            (
                f"v=DMARC1; p=reject; "
                f"adkim=s; aspf=s; "
                f"rua=mailto:dmarc@{domain}"
            ),
        )

        # -------------------------------------------------
        # DKIM
        # -------------------------------------------------

        update_record(
            secret,
            domain,
            "TXT",
            "mail._domainkey",
            dkim_value,
        )

    return (
        f"Updated DNS for "
        f"{len(DOMAINS)} domains"
    )


# ---------------------------------------------------------------------------
# Execute DNS Updates
# ---------------------------------------------------------------------------
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
# ---------------------------------------------------------------------------
# Outputs
# ---------------------------------------------------------------------------

pulumi.export(
    "domains",
    DOMAINS,
)

pulumi.export(
    "dns_update",
    update_dns_records,
)

pulumi.export(
    "dkim_dump",
    read_all_dkim.stdout,
)