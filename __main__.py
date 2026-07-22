import os
import re
import requests
import subprocess
import pulumi
import pulumi_command as command
import time

# ---------------------------------------------------------------------------
# Pulumi Config
# ---------------------------------------------------------------------------

cfg = pulumi.Config()

GODADDY_API_KEY = cfg.require("godaddyApiKey")
GODADDY_API_SECRET = cfg.require_secret("godaddyApiSecret")

# ---------------------------------------------------------------------------
# Server & Domain Config
# ---------------------------------------------------------------------------

VPS_IP = "51.79.63.247"

ROOT_DOMAIN = cfg.require("domain")
TARGET_DOMAIN = cfg.require("fqdn")

if TARGET_DOMAIN == ROOT_DOMAIN:
    SUBDOMAIN_PREFIX = ""
else:
    suffix = "." + ROOT_DOMAIN
    if TARGET_DOMAIN.endswith(suffix):
        SUBDOMAIN_PREFIX = TARGET_DOMAIN[:-len(suffix)]
    else:
        raise Exception(
            f"fqdn '{TARGET_DOMAIN}' is not under root domain '{ROOT_DOMAIN}'"
        )

# ---------------------------------------------------------------------------
# Execution Execution Engine Helpers
# ---------------------------------------------------------------------------

def run(name: str, cmd: str, deps=None, trigger_values=None):
    # If forcing recreation, append a unique string to triggers to force execution
    t_vals = [cmd] if trigger_values is None else trigger_values

    return command.local.Command(
        name,
        create=cmd,
        triggers=t_vals,
        opts=pulumi.ResourceOptions(depends_on=deps or []),
    )

#domain skim propagation wait function
def wait_for_dkim(domain):
    for _ in range(60):
        try:
            out = subprocess.check_output(
                ["dig", "+short", "TXT", f"mail._domainkey.{domain}"],
                text=True,
            )

            if "DKIM1" in out:
                print("DKIM record propagated.")
                return

        except Exception:
            pass

        time.sleep(5)

    raise Exception("DKIM DNS record did not propagate.")

# ---------------------------------------------------------------------------
# Multi-Tenant Core Configuration Directory Prep
# ----------------------------------------------------------------------------------------------------------------------

cleanup_domain = run(
    "cleanup_domain",
    """
set -e

sudo mkdir -p /etc/opendkim
sudo touch /etc/opendkim/TrustedHosts
sudo touch /etc/opendkim/KeyTable
sudo touch /etc/opendkim/SigningTable
""",
    trigger_values=[TARGET_DOMAIN],
)

# ---------------------------------------------------------------------------
# 2. Append TrustedHosts Array Safely
# ---------------------------------------------------------------------------

hosts_to_add = [
    "127.0.0.1",
    "localhost",
    VPS_IP,
    TARGET_DOMAIN,
    f"*.{TARGET_DOMAIN}",
    f"mail.{TARGET_DOMAIN}",
]

trusted_hosts_script = """
set -e

sudo mkdir -p /etc/opendkim
sudo touch /etc/opendkim/TrustedHosts

# Ensure the file always ends with a newline
sudo sed -i -e '$a\\' /etc/opendkim/TrustedHosts
"""

for host in hosts_to_add:
    trusted_hosts_script += f"""
grep -qxF "{host}" /etc/opendkim/TrustedHosts || \
echo "{host}" | sudo tee -a /etc/opendkim/TrustedHosts >/dev/null
"""

write_trustedhosts = run(
    "write_trustedhosts",
    trusted_hosts_script,
    deps=[cleanup_domain],
    trigger_values=[TARGET_DOMAIN],
)

# ---------------------------------------------------------------------------
# 3. Update KeyTable (Replace existing entry if present)
# ---------------------------------------------------------------------------

keytable_line = (
    f"mail._domainkey.{TARGET_DOMAIN} "
    f"{TARGET_DOMAIN}:mail:/etc/opendkim/keys/{TARGET_DOMAIN}/mail.private"
)

write_keytable = run(
    "write_keytable",
    f"""
set -e

sudo touch /etc/opendkim/KeyTable

# Remove any existing entry for this domain
sudo sed -i '\\|mail._domainkey.{TARGET_DOMAIN}|d' /etc/opendkim/KeyTable

# Add fresh entry
echo "{keytable_line}" | sudo tee -a /etc/opendkim/KeyTable >/dev/null
""",
    deps=[cleanup_domain],
    trigger_values=[TARGET_DOMAIN],
)

# ---------------------------------------------------------------------------
# 4. Update SigningTable (Replace existing entry if present)
# ---------------------------------------------------------------------------

signingtable_line = (
    f"*@{TARGET_DOMAIN} mail._domainkey.{TARGET_DOMAIN}"
)

write_signingtable = run(
    "write_signingtable",
    f"""
set -e

sudo touch /etc/opendkim/SigningTable

# Remove previous mapping
sudo sed -i '\\|{TARGET_DOMAIN}|d' /etc/opendkim/SigningTable

# Add new mapping
echo "{signingtable_line}" | sudo tee -a /etc/opendkim/SigningTable >/dev/null
""",
    deps=[cleanup_domain],
    trigger_values=[TARGET_DOMAIN],
)


# ---------------------------------------------------------------------------
# DKIM Key pair Isolation Factory (Modified to support forced wipe)
# ---------------------------------------------------------------------------

purge_keys_cmd = ""


dkim_command = f"""
set -e

echo "Removing previous DKIM key..."

sudo rm -rf /etc/opendkim/keys/{TARGET_DOMAIN}

echo "Creating key directory..."

sudo mkdir -p /etc/opendkim/keys/{TARGET_DOMAIN}

echo "Generating new DKIM key..."

sudo opendkim-genkey \
    -b 2048 \
    -D /etc/opendkim/keys/{TARGET_DOMAIN} \
    -d {TARGET_DOMAIN} \
    -s mail

sudo chown -R opendkim:opendkim /etc/opendkim/keys/{TARGET_DOMAIN}

sudo chmod 700 /etc/opendkim/keys/{TARGET_DOMAIN}
sudo chmod 600 /etc/opendkim/keys/{TARGET_DOMAIN}/mail.private
sudo chmod 644 /etc/opendkim/keys/{TARGET_DOMAIN}/mail.txt
"""

generate_dkim = run(
    "generate_dkim",
    dkim_command,
    deps=[
        cleanup_domain,
        write_signingtable,
        write_keytable,
    ],
    trigger_values=[TARGET_DOMAIN],
)

read_all_dkim = command.local.Command(
    "read_all_dkim",
    create=f"sudo cat /etc/opendkim/keys/{TARGET_DOMAIN}/mail.txt",
    triggers=[dkim_command],
    opts=pulumi.ResourceOptions(depends_on=[generate_dkim]),
)

# ---------------------------------------------------------------------------
# GoDaddy Automated API Engine Contexts
# ---------------------------------------------------------------------------

def godaddy_headers(secret):
    return {
        "Authorization": f"sso-key {GODADDY_API_KEY}:{secret}",
        "Content-Type": "application/json",
        "Accept": "application/json",
    }

def update_record(secret, domain, record_type, name, value, ttl=600):
    url = f"https://api.godaddy.com/v1/domains/{domain}/records/{record_type}/{name}"
    # GoDaddy's PUT request updates/overwrites existing array records automatically
    response = requests.put(
        url, headers=godaddy_headers(secret), json=[{"data": value, "ttl": ttl}], timeout=60
    )
    print(f"GoDaddy Sync -> {domain} {record_type} {name}: Status {response.status_code}")
    response.raise_for_status()

def update_mx_record(secret, domain, name, target_mail):
    url = f"https://api.godaddy.com/v1/domains/{domain}/records/MX/{name}"
    response = requests.put(
        url, headers=godaddy_headers(secret), json=[{"data": target_mail, "priority": 10, "ttl": 600}], timeout=60
    )
    print(f"GoDaddy Sync -> {domain} MX {name}: Status {response.status_code}")
    response.raise_for_status()



# ---------------------------------------------------------------------------
# Isolated External DNS Propagation Phase
# ---------------------------------------------------------------------------

def update_dns(secret, dkim_text):

    if '; -----' in dkim_text:
        dkim_text = dkim_text.split('; -----')[0]
    elif ';' in dkim_text:
        dkim_text = dkim_text.split(';')[0]

    cleaned = (
        dkim_text
        .replace('"', '')
        .replace('(', '')
        .replace(')', '')
        .replace('\n', '')
        .replace('\t', '')
        .replace(' ', '')
    )

    match = re.search(r"p=([A-Za-z0-9+/=]+)", cleaned)

    if not match:
        raise Exception(f"Unable to parse DKIM for {TARGET_DOMAIN}")

    public_key = match.group(1)

    dkim_value = f"v=DKIM1; k=rsa; p={public_key}"

    def fix_name(record_name):
        if not SUBDOMAIN_PREFIX:
            return record_name

        if record_name == "@":
            return SUBDOMAIN_PREFIX

        if record_name == "*":
            return f"*.{SUBDOMAIN_PREFIX}"

        return f"{record_name}.{SUBDOMAIN_PREFIX}"

    print("Updating DNS records...")

    update_record(secret, ROOT_DOMAIN, "A", fix_name("@"), VPS_IP)
    update_record(secret, ROOT_DOMAIN, "A", fix_name("mail"), VPS_IP)
    update_record(secret, ROOT_DOMAIN, "A", fix_name("*"), VPS_IP)

    update_mx_record(
        secret,
        ROOT_DOMAIN,
        fix_name("@"),
        f"mail.{TARGET_DOMAIN}",
    )

    update_record(
        secret,
        ROOT_DOMAIN,
        "TXT",
        fix_name("@"),
        f"v=spf1 mx ip4:{VPS_IP} -all",
    )

    update_record(
        secret,
        ROOT_DOMAIN,
        "TXT",
        fix_name("_dmarc"),
        f"v=DMARC1; p=reject; adkim=s; aspf=s; rua=mailto:dmarc@{TARGET_DOMAIN}",
    )

    update_record(
        secret,
        ROOT_DOMAIN,
        "TXT",
        fix_name("mail._domainkey"),
        dkim_value,
    )

    print("Waiting for authoritative DNS...")

    wait_for_dkim(TARGET_DOMAIN)

    print("Waiting 60 seconds for global propagation...")

    time.sleep(60)

    print("DNS propagation completed.")

    return f"Successfully configured {TARGET_DOMAIN}"

update_dns_records = pulumi.Output.all(
    GODADDY_API_SECRET,
    read_all_dkim.stdout
).apply(lambda args: update_dns(args[0], args[1]))


# ---------------------------------------------------------------------------
# Atomic Real-Time Service Cycles
# ---------------------------------------------------------------------------

reload_daemons = run(
    "reload_daemons",
    f"""
set -e

echo "=============================="
echo "Preparing OpenDKIM..."
echo "=============================="

sudo mkdir -p /run/opendkim

sudo chown -R opendkim:opendkim /etc/opendkim
sudo chown -R opendkim:opendkim /etc/opendkim/keys
sudo chown -R opendkim:opendkim /run/opendkim

sudo chmod 750 /etc/opendkim
sudo chmod 750 /run/opendkim

sudo find /etc/opendkim/keys -type d -exec chmod 750 {{}} \\;
sudo find /etc/opendkim/keys -type f -name "*.private" -exec chmod 600 {{}} \\;
sudo find /etc/opendkim/keys -type f -name "*.txt" -exec chmod 644 {{}} \\;

echo "Checking DKIM key..."

sudo test -f /etc/opendkim/keys/{TARGET_DOMAIN}/mail.private

echo "Configuring relayhost..."

sudo postconf -e "relayhost=[10.10.0.2]:25"

echo "Restarting OpenDKIM..."

sudo systemctl restart opendkim

echo "Waiting for OpenDKIM..."

for i in $(seq 1 10); do
    if systemctl is-active --quiet opendkim; then
        echo "OpenDKIM is ready."
        break
    fi
    sleep 1
done

systemctl is-active --quiet opendkim

echo "Restarting Postfix..."

sudo systemctl restart postfix

echo "Waiting for Postfix (587)..."

for i in $(seq 1 20); do
    if nc -z 127.0.0.1 587; then
        echo "Postfix is ready."
        break
    fi
    sleep 1
done

nc -z 127.0.0.1 587

echo ""
echo "=============================="
echo "OpenDKIM : $(systemctl is-active opendkim)"
echo "Postfix  : $(systemctl is-active postfix)"
echo "Dovecot  : $(systemctl is-active dovecot)"
echo "=============================="

echo "Configuration completed successfully."
""",
    deps=[
        write_trustedhosts,
        write_keytable,
        write_signingtable,
        generate_dkim,
    ],
    trigger_values=[
        TARGET_DOMAIN,
    ],
)

#---------------------------------------------------------------------------
# Terminal Control Interface Exports
# ---------------------------------------------------------------------------

pulumi.export("target_domain", TARGET_DOMAIN)
pulumi.export("dns_update", update_dns_records)