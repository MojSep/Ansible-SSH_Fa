#!/usr/bin/env bash
# ============================================================================
#  SSH Health & Security Check
#  Author: MojSep
#  Description: Comprehensive health & security audit for SSH server/client
#  Usage: sudo ./ssh-healthcheck.sh
# ============================================================================

# ---------- Header ----------
echo ""
echo "Visit more at https://github.com/MojSep"
echo ""
echo "================================================================================"
echo "              SSH HEALTH & SECURITY CHECK"
echo "              Started at: $(date '+%Y-%m-%d %H:%M:%S')"
echo "              Host: $(hostname) / User: $(whoami)"
echo "================================================================================"
echo ""

# ---------- Colors ----------
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
MAGENTA='\033[0;35m'
BOLD='\033[1m'
NC='\033[0m'

# ---------- Counters ----------
PASS=0
WARN=0
FAIL=0
INFO=0

# ---------- Helpers ----------
pass_check() { echo -e "${GREEN}✅ [PASS]${NC} $*";             ((PASS++)); }
warn_check() { echo -e "${YELLOW}⚠️  [WARN]${NC} $*";            ((WARN++)); }
fail_check() { echo -e "${RED}❌ [FAIL]${NC} $*";               ((FAIL++)); }
info_check() { echo -e "${BLUE}ℹ️  [INFO]${NC} $*";             ((INFO++)); }

section() {
    echo ""
    echo -e "${CYAN}════════════════════════════════════════════════════════════════════════${NC}"
    echo -e "${CYAN}  ▶ $*${NC}"
    echo -e "${CYAN}════════════════════════════════════════════════════════════════════════${NC}"
}

sub() {
    echo -e "  ${MAGENTA}── $* ──${NC}"
}

# Check file permission
check_perm() {
    local file="$1" expected="$2" severity="$3"
    if [[ ! -e "$file" ]]; then
        info_check "File not present: $file"
        return
    fi
    local actual owner group
    actual=$(stat -c '%a' "$file" 2>/dev/null)
    owner=$(stat -c '%U' "$file" 2>/dev/null)
    group=$(stat -c '%G' "$file" 2>/dev/null)
    if [[ "$actual" == "$expected" ]]; then
        pass_check "Permissions '$actual' $owner:$group on $file"
    else
        case "$severity" in
            critical) fail_check "Insecure permissions '$actual' $owner:$group on $file (expected '$expected')" ;;
            warning)  warn_check "Permissions '$actual' $owner:$group on $file (expected '$expected')" ;;
            info)     info_check "Permissions '$actual' on $file" ;;
        esac
    fi
}

# Find setting line number across sshd_config + drop-ins
find_sshd_setting() {
    local key="$1"
    local line=""
    
    for f in /etc/ssh/sshd_config /etc/ssh/sshd_config.d/*.conf; do
        [[ -f "$f" ]] || continue
        local hit
        hit=$(grep -nE "^\s*${key}\s*[ =]" "$f" 2>/dev/null | tail -1)
        if [[ -n "$hit" ]]; then
            line="${f}:${hit}"
        fi
    done
    
    echo "$line"
}

# Generic setting check (exact match by regex)
check_sshd() {
    local key="$1" pattern="$2" expected="$3" severity="$4"
    local hit
    hit=$(find_sshd_setting "$key")
    
    if [[ -z "$hit" ]]; then
        case "$severity" in
            critical) fail_check "$key: NOT CONFIGURED anywhere — expected '$expected' ($pattern)" ;;
            warning)  warn_check "$key: NOT CONFIGURED — expected '$expected' ($pattern)" ;;
            info)     info_check "$key: not set (default applies) — recommended '$expected'" ;;
        esac
        return
    fi
    
    local file rest line_num value
    file=$(echo "$hit" | cut -d: -f1)
    rest=$(echo "$hit" | cut -d: -f2-)
    line_num=$(echo "$rest" | cut -d: -f1)
    value=$(echo "$rest" | sed 's/^[0-9]*://' | awk '{$1=""; print $0}' | xargs)
    
    if [[ "$value" =~ ^(${pattern})$ ]]; then
        pass_check "$key = '$value' (File: $file Line: $line_num)"
    else
        case "$severity" in
            critical) fail_check "$key: File: $file Line: $line_num Current: '$value' Expected: '$expected'" ;;
            warning)  warn_check "$key: File: $file Line: $line_num Current: '$value' Expected: '$expected'" ;;
            info)     info_check "$key = '$value' (File: $file Line: $line_num)" ;;
        esac
    fi
}

# Numeric check (key <= max or >= min)
check_sshd_numeric() {
    local key="$1" op="$2" threshold="$3" severity="$4"
    local hit
    hit=$(find_sshd_setting "$key")
    
    if [[ -z "$hit" ]]; then
        case "$severity" in
            critical) fail_check "$key: NOT CONFIGURED — $op $threshold required" ;;
            warning)  warn_check "$key: NOT CONFIGURED — $op $threshold recommended" ;;
            info)     info_check "$key: not set — $op $threshold recommended" ;;
        esac
        return
    fi
    
    local file rest line_num value
    file=$(echo "$hit" | cut -d: -f1)
    rest=$(echo "$hit" | cut -d: -f2-)
    line_num=$(echo "$rest" | cut -d: -f1)
    value=$(echo "$rest" | sed 's/^[0-9]*://' | awk '{$1=""; print $0}' | xargs)
    
    if [[ "$value" =~ ^[0-9]+$ ]]; then
        local cmp
        if [[ "$op" == "<=" ]]; then
            cmp=$([[ "$value" -le "$threshold" ]] && echo ok || echo bad)
        else
            cmp=$([[ "$value" -ge "$threshold" ]] && echo ok || echo bad)
        fi
        if [[ "$cmp" == "ok" ]]; then
            pass_check "$key = $value (File: $file Line: $line_num, $op $threshold)"
        else
            case "$severity" in
                critical) fail_check "$key: File: $file Line: $line_num Current: '$value' Expected: $op $threshold" ;;
                warning)  warn_check "$key: File: $file Line: $line_num Current: '$value' Expected: $op $threshold" ;;
            esac
        fi
    else
        warn_check "$key = '$value' (non-numeric, cannot compare)"
    fi
}

# ============================================================================
# SECTION 1: PACKAGE & BINARY
# ============================================================================
section "1. SSH PACKAGE & BINARY"

sub "sshd binary"
if command -v sshd >/dev/null 2>&1; then
    SSHD_BIN=$(command -v sshd)
    pass_check "sshd binary: $SSHD_BIN"
elif [[ -x /usr/sbin/sshd ]]; then
    SSHD_BIN=/usr/sbin/sshd
    pass_check "sshd binary: $SSHD_BIN"
else
    fail_check "sshd binary NOT found"
    SSHD_BIN=""
fi

sub "Client binary"
if command -v ssh >/dev/null 2>&1; then
    pass_check "ssh client: $(command -v ssh)"
else
    fail_check "ssh client NOT found"
fi

sub "Version"
if [[ -n "$SSHD_BIN" ]]; then
    SSH_VERSION=$(ssh -V 2>&1)
    info_check "$SSH_VERSION"
    if echo "$SSH_VERSION" | grep -qE "OpenSSH_[0-9]+\.[0-9]+"; then
        VER=$(echo "$SSH_VERSION" | sed -E 's/.*OpenSSH_([0-9]+\.[0-9]+).*/\1/')
        VER_MAJOR=$(echo "$VER" | cut -d. -f1)
        VER_MINOR=$(echo "$VER" | cut -d. -f2)
        # critical OpenSSH < 8.0 (many CVEs)
        if [[ "$VER_MAJOR" -lt 8 ]] || { [[ "$VER_MAJOR" -eq 8 ]] && [[ "$VER_MINOR" -lt 0 ]]; }; then
            fail_check "OpenSSH $VER is TOO OLD (< 8.0) — contains known CVEs"
        elif [[ "$VER_MAJOR" -lt 9 ]]; then
            warn_check "OpenSSH $VER — consider upgrading to 9.x"
        else
            pass_check "OpenSSH $VER (>= 9.0)"
        fi
    fi
fi

# ============================================================================
# SECTION 2: SERVICE STATUS
# ============================================================================
section "2. SSHD SERVICE STATUS"

if systemctl list-unit-files 2>/dev/null | grep -q "sshd.service"; then
    sub "sshd.service"
    if systemctl is-active --quiet sshd 2>/dev/null; then
        pass_check "sshd.service is ACTIVE"
    else
        fail_check "sshd.service is INACTIVE — SSH not accepting connections"
    fi
    if systemctl is-enabled --quiet sshd 2>/dev/null; then
        pass_check "sshd.service is ENABLED (starts at boot)"
    else
        warn_check "sshd.service is DISABLED — will not start on reboot"
    fi
elif systemctl list-unit-files 2>/dev/null | grep -q "ssh.service"; then
    sub "ssh.service (Debian/Ubuntu)"
    if systemctl is-active --quiet ssh; then
        pass_check "ssh.service is ACTIVE"
    else
        fail_check "ssh.service is INACTIVE"
    fi
    if systemctl is-enabled --quiet ssh; then
        pass_check "ssh.service is ENABLED"
    else
        warn_check "ssh.service is DISABLED"
    fi
else
    warn_check "No sshd.service / ssh.service unit found"
fi

if systemctl list-unit-files 2>/dev/null | grep -q "ssh.socket"; then
    sub "ssh.socket (socket activation)"
    if systemctl is-active --quiet ssh.socket 2>/dev/null; then
        info_check "ssh.socket is active (socket activation in use)"
    fi
fi

# ============================================================================
# SECTION 3: CONFIG FILES EXISTENCE & SYNTAX
# ============================================================================
section "3. CONFIG FILES & SYNTAX"

sub "Server config"
SSHD_CONFIG="/etc/ssh/sshd_config"
if [[ -f "$SSHD_CONFIG" ]]; then
    pass_check "$SSHD_CONFIG exists"
else
    fail_check "$SSHD_CONFIG MISSING"
fi

sub "Drop-in directory"
if [[ -d /etc/ssh/sshd_config.d ]]; then
    pass_check "/etc/ssh/sshd_config.d/ exists"
    for f in /etc/ssh/sshd_config.d/*.conf; do
        [[ -f "$f" ]] && info_check "Drop-in: $f"
    done
fi

sub "Client config"
[[ -f /etc/ssh/ssh_config ]] && pass_check "/etc/ssh/ssh_config exists"
[[ -f "$HOME/.ssh/config" ]] && info_check "User config: $HOME/.ssh/config"

sub "Syntax check (sshd -t)"
if [[ -n "$SSHD_BIN" ]]; then
    if $SSHD_BIN -t 2>/dev/null; then
        pass_check "sshd -t: config syntax OK"
    else
        fail_check "sshd -t: config has SYNTAX ERRORS — service may fail to start"
        $SSHD_BIN -t 2>&1 | sed 's/^/    /'
    fi
fi

sub "Effective config (sshd -T, requires root)"
if [[ $EUID -eq 0 && -n "$SSHD_BIN" ]]; then
    if $SSHD_BIN -T >/dev/null 2>&1; then
        pass_check "sshd -T: effective config readable"
    else
        warn_check "sshd -T failed — cannot verify effective values"
    fi
else
    info_check "Skipped sshd -T (not root)"
fi

# ============================================================================
# SECTION 4: FILE PERMISSIONS
# ============================================================================
section "4. FILE PERMISSIONS"

sub "Server config"
check_perm "$SSHD_CONFIG" "600" critical

sub "Host keys"
for f in /etc/ssh/ssh_host_*_key; do
    [[ -f "$f" ]] && check_perm "$f" "600" critical
done

sub "Host public keys"
for f in /etc/ssh/ssh_host_*_key.pub; do
    [[ -f "$f" ]] && check_perm "$f" "644" warning
done

sub "Client config"
[[ -f /etc/ssh/ssh_config ]] && check_perm /etc/ssh/ssh_config "644" warning
[[ -f "$HOME/.ssh/config" ]] && check_perm "$HOME/.ssh/config" "600" warning

sub "User SSH directory & files"
if [[ -d "$HOME/.ssh" ]]; then
    check_perm "$HOME/.ssh" "700" critical
    [[ -f "$HOME/.ssh/authorized_keys" ]] && check_perm "$HOME/.ssh/authorized_keys" "600" critical
    [[ -f "$HOME/.ssh/known_hosts" ]] && check_perm "$HOME/.ssh/known_hosts" "600" warning
    for f in "$HOME/.ssh/id_"*; do
        case "$f" in
            *.pub) [[ -f "$f" ]] && check_perm "$f" "644" warning ;;
            *)     [[ -f "$f" ]] && check_perm "$f" "600" critical ;;
        esac
    done
fi

sub "Root SSH directory"
if [[ $EUID -eq 0 && -d /root/.ssh ]]; then
    check_perm /root/.ssh "700" critical
    [[ -f /root/.ssh/authorized_keys ]] && check_perm /root/.ssh/authorized_keys "600" critical
fi

sub "Global known_hosts"
[[ -f /etc/ssh/ssh_known_hosts ]] && check_perm /etc/ssh/ssh_known_hosts "644" warning

sub "Home directory writability (not world-writable)"
if [[ -d "$HOME" ]]; then
    HPERM=$(stat -c '%a' "$HOME")
    if [[ "${HPERM: -1}" -ge 2 ]]; then
        fail_check "Home $HOME is world-writable (${HPERM}) — SSH refuses keys from insecure home"
    else
        pass_check "Home $HOME not world-writable (${HPERM})"
    fi
fi

# ============================================================================
# SECTION 5: HOST KEYS
# ============================================================================
section "5. HOST KEYS"

KEY_RSA=0; KEY_ED=0; KEY_DSA=0; KEY_ECDSA=0
for f in /etc/ssh/ssh_host_*_key; do
    [[ -f "$f" ]] || continue
    case "$f" in
        *_rsa_key)   KEY_RSA=1 ;;
        *_ed25519_key) KEY_ED=1 ;;
        *_dsa_key)   KEY_DSA=1 ;;
        *_ecdsa_key) KEY_ECDSA=1 ;;
    esac
done

[[ $KEY_ED -eq 1 ]] && pass_check "Ed25519 host key present" || warn_check "No Ed25519 host key"
[[ $KEY_RSA -eq 1 ]] && info_check "RSA host key present" || warn_check "No RSA host key"
[[ $KEY_ECDSA -eq 1 ]] && info_check "ECDSA host key present"
[[ $KEY_DSA -eq 1 ]] && fail_check "DSA host key present — REMOVE (insecure)" || pass_check "No DSA host key"

sub "RSA key length"
if [[ -f /etc/ssh/ssh_host_rsa_key.pub ]]; then
    BITS=$(ssh-keygen -lf /etc/ssh/ssh_host_rsa_key.pub 2>/dev/null | awk '{print $1}')
    if [[ -n "$BITS" ]]; then
        if [[ "$BITS" -ge 3072 ]]; then
            pass_check "RSA host key: $BITS bits (>= 3072)"
        else
            fail_check "RSA host key: $BITS bits — TOO SMALL (< 3072)"
        fi
    fi
fi

# ============================================================================
# SECTION 6: CRITICAL SECURITY SETTINGS
# ============================================================================
section "6. CRITICAL SECURITY SETTINGS"

sub "Authentication"
check_sshd "PermitRootLogin"           "no|prohibit-password|without-password" "PermitRootLogin no" critical
check_sshd "PasswordAuthentication"    "no"    "PasswordAuthentication no" critical
check_sshd "PermitEmptyPasswords"      "no"    "PermitEmptyPasswords no" critical
check_sshd "PubkeyAuthentication"      "yes"   "PubkeyAuthentication yes" warning
check_sshd "KbdInteractiveAuthentication" "no" "KbdInteractiveAuthentication no" warning
check_sshd "ChallengeResponseAuthentication" "no" "ChallengeResponseAuthentication no" warning
check_sshd "HostbasedAuthentication"   "no"    "HostbasedAuthentication no" critical
check_sshd "IgnoreRhosts"              "yes"   "IgnoreRhosts yes" warning

sub "Forwarding / Permissions"
check_sshd "X11Forwarding"             "no"    "X11Forwarding no" warning
check_sshd "AllowAgentForwarding"      "no"    "AllowAgentForwarding no" warning
check_sshd "AllowTcpForwarding"        "no"    "AllowTcpForwarding no" warning
check_sshd "PermitTunnel"              "no"    "PermitTunnel no" warning
check_sshd "PermitUserEnvironment"     "no"    "PermitUserEnvironment no" critical
check_sshd "UsePAM"                    "yes"   "UsePAM yes" info

sub "Limits / Timeouts"
check_sshd_numeric "MaxAuthTries"     "<=" 4    warning
check_sshd_numeric "MaxSessions"      "<=" 10   warning
check_sshd_numeric "MaxStartups"      "<=" 100  info
check_sshd_numeric "LoginGraceTime"   "<=" 60   warning
check_sshd_numeric "ClientAliveInterval" ">=" 300 warning
check_sshd_numeric "ClientAliveCountMax" "<=" 3  warning

sub "Banner"
BANNER=$(find_sshd_setting "Banner")
if [[ -n "$BANNER" ]]; then
    pass_check "Banner configured: $BANNER"
else
    warn_check "No Banner configured (legal warning recommended)"
fi

sub "Listening port"
PORT=$(find_sshd_setting "Port")
if [[ -n "$PORT" ]]; then
    PORT_VAL=$(echo "$PORT" | awk -F'[: ]+' '{print $NF}')
    info_check "Port: $PORT_VAL $( [[ "$PORT_VAL" != "22" ]] && echo '(non-default)' || echo '(default)' )"
fi

sub "AllowUsers / AllowGroups"
AU=$(find_sshd_setting "AllowUsers")
AG=$(find_sshd_setting "AllowGroups")
if [[ -n "$AU" || -n "$AG" ]]; then
    pass_check "Access restricted via AllowUsers/AllowGroups"
    [[ -n "$AU" ]] && info_check "  AllowUsers: $AU"
    [[ -n "$AG" ]] && info_check "  AllowGroups: $AG"
else
    warn_check "No AllowUsers/AllowGroups set — any valid user can attempt SSH"
fi

sub "DenyUsers / DenyGroups"
DU=$(find_sshd_setting "DenyUsers")
DG=$(find_sshd_setting "DenyGroups")
if [[ -n "$DU" || -n "$DG" ]]; then
    info_check "DenyUsers/DenyGroups configured"
    [[ -n "$DU" ]] && info_check "  DenyUsers: $DU"
    [[ -n "$DG" ]] && info_check "  DenyGroups: $DG"
fi

# ============================================================================
# SECTION 7: CRYPTOGRAPHY
# ============================================================================
section "7. CRYPTOGRAPHY"

sub "Ciphers"
CIPHERS=$(find_sshd_setting "Ciphers")
if [[ -n "$CIPHERS" ]]; then
    if echo "$CIPHERS" | grep -qiE "arcfour|3des|des-cbc|blowfish|cast128"; then
        fail_check "WEAK cipher found in: $CIPHERS"
    else
        pass_check "No weak ciphers configured"
    fi
    info_check "  Ciphers: $CIPHERS"
else
    info_check "Ciphers not explicit — using OpenSSH defaults (usually safe on >= 8.x)"
fi

sub "MACs"
MACS=$(find_sshd_setting "MACs")
if [[ -n "$MACS" ]]; then
    if echo "$MACS" | grep -qiE "md5|hmac-sha1-96|hmac-md5"; then
        warn_check "WEAK MAC algorithm found in: $MACS"
    else
        pass_check "No weak MACs configured"
    fi
    info_check "  MACs: $MACS"
fi

sub "KexAlgorithms"
KEX=$(find_sshd_setting "KexAlgorithms")
if [[ -n "$KEX" ]]; then
    if echo "$KEX" | grep -qiE "diffie-hellman-group1-sha1|diffie-hellman-group14-sha1"; then
        warn_check "Weak KEX algorithm found in: $KEX"
    else
        pass_check "No weak KEX configured"
    fi
    info_check "  KexAlgorithms: $KEX"
fi

sub "Protocol version"
PROTO=$(find_sshd_setting "Protocol")
if [[ -n "$PROTO" ]]; then
    if echo "$PROTO" | grep -q "1"; then
        fail_check "Protocol 1 configured — INSECURE"
    else
        pass_check "Protocol 2 only"
    fi
else
    pass_check "Protocol not set explicitly (2 is default on modern OpenSSH)"
fi

# ============================================================================
# SECTION 8: FIREWALL
# ============================================================================
section "8. FIREWALL RULES"

SSH_PORT=${PORT_VAL:-22}

if command -v firewall-cmd >/dev/null 2>&1 && systemctl is-active --quiet firewalld 2>/dev/null; then
    sub "firewalld"
    if firewall-cmd --list-services 2>/dev/null | grep -qw "ssh"; then
        pass_check "firewalld: ssh service allowed"
    fi
    if firewall-cmd --list-ports 2>/dev/null | grep -qw "$SSH_PORT/tcp"; then
        pass_check "firewalld: port $SSH_PORT/tcp explicitly allowed"
    fi
elif command -v ufw >/dev/null 2>&1 && ufw status 2>/dev/null | grep -q "Status: active"; then
    sub "ufw"
    if ufw status 2>/dev/null | grep -qE "$SSH_PORT.*ALLOW|OpenSSH.*ALLOW"; then
        pass_check "ufw: SSH access allowed"
    else
        warn_check "ufw active but SSH rule not explicit"
    fi
elif command -v iptables >/dev/null 2>&1; then
    sub "iptables"
    if iptables -L INPUT -n 2>/dev/null | grep -qE "dpt:$SSH_PORT.*ACCEPT|state RELATED"; then
        pass_check "iptables: rules present for SSH"
    else
        info_check "iptables: cannot definitively confirm SSH rule"
    fi
else
    warn_check "No active firewall (firewalld/ufw/iptables) — SSH may be exposed"
fi

# ============================================================================
# SECTION 9: BRUTE FORCE PROTECTION
# ============================================================================
section "9. BRUTE FORCE PROTECTION"

sub "fail2ban"
if command -v fail2ban-client >/dev/null 2>&1; then
    pass_check "fail2ban installed"
    if systemctl is-active --quiet fail2ban; then
        pass_check "fail2ban running"
        if fail2ban-client status sshd >/dev/null 2>&1; then
            BANNED=$(fail2ban-client status sshd 2>/dev/null | grep "Currently banned" | awk -F: '{print $2}' | xargs)
            info_check "fail2ban sshd jail active (currently banned: ${BANNED:-0})"
        fi
    else
        warn_check "fail2ban installed but NOT running"
    fi
else
    warn_check "fail2ban not installed — consider it for brute-force protection"
fi

sub "Other tools"
for tool in sshguard crowdsec; do
    if command -v "$tool" >/dev/null 2>&1; then
        info_check "$tool is installed"
    fi
done

# ============================================================================
# SECTION 10: AUTHORIZED KEYS AUDIT
# ============================================================================
section "10. AUTHORIZED KEYS AUDIT"

AK_FILES=()
[[ -f "$HOME/.ssh/authorized_keys" ]] && AK_FILES+=("$HOME/.ssh/authorized_keys")
[[ -f /root/.ssh/authorized_keys ]] && AK_FILES+=("/root/.ssh/authorized_keys")

for ak in "${AK_FILES[@]}"; do
    sub "File: $ak"
    KEY_COUNT=$(grep -cE "^(ssh-|ecdsa-|sk-)" "$ak" 2>/dev/null)
    if [[ "$KEY_COUNT" -gt 0 ]]; then
        info_check "$KEY_COUNT public key(s) authorized"
        # check for DSA keys
        if grep -qE "^ssh-dss" "$ak" 2>/dev/null; then
            fail_check "DSA key present in $ak — REMOVE"
        fi
        # check for weak RSA (< 2048)
        WEAK_RSA=$(ssh-keygen -lf "$ak" 2>/dev/null | awk '$1 < 2048 && /RSA/ {print $NF}')
        if [[ -n "$WEAK_RSA" ]]; then
            warn_check "Weak RSA key(s) (< 2048 bits) in $ak"
        fi
        # check for overly permissive options
        if grep -qE "no-port-forwarding|no-pty|from=" "$ak" 2>/dev/null; then
            pass_check "Authorized keys include restrictions (from=/no-pty/etc)"
        else
            warn_check "No key restrictions (from=, no-pty) — consider limiting"
        fi
    fi
done

# ============================================================================
# SECTION 11: KNOWN HOSTS
# ============================================================================
section "11. KNOWN HOSTS"

sub "User known_hosts"
if [[ -f "$HOME/.ssh/known_hosts" ]]; then
    KH_COUNT=$(grep -cvE "^(#|$)" "$HOME/.ssh/known_hosts" 2>/dev/null)
    pass_check "$HOME/.ssh/known_hosts has $KH_COUNT host(s)"
else
    info_check "No user known_hosts file"
fi

sub "Global known_hosts"
if [[ -f /etc/ssh/ssh_known_hosts ]]; then
    GH_COUNT=$(grep -cvE "^(#|$)" /etc/ssh/ssh_known_hosts 2>/dev/null)
    pass_check "/etc/ssh/ssh_known_hosts has $GH_COUNT host(s)"
else
    info_check "No global known_hosts file"
fi

sub "SSH Host CA (best practice)"
if grep -rq "@cert-authority" /etc/ssh/ssh_known_hosts "$HOME/.ssh/known_hosts" 2>/dev/null; then
    pass_check "SSH Host CA trusted (cert-authority configured)"
else
    info_check "No SSH Host CA — consider for scalable host verification"
fi

# ============================================================================
# SECTION 12: RECENT LOGINS / AUTH EVENTS
# ============================================================================
section "12. RECENT LOGINS & AUTH EVENTS"

sub "Recent logins (last 5)"
if command -v last >/dev/null 2>&1; then
    last -5 2>/dev/null | head -5 | sed 's/^/    /' | while read -r line; do
        [[ -n "$line" ]] && echo -e "  ${BLUE}$line${NC}"
    done
fi

sub "Failed login attempts (last 24h)"
if [[ -f /var/log/auth.log ]]; then
    FAILED=$(grep -c "Failed password\|authentication failure" /var/log/auth.log 2>/dev/null)
    if [[ "$FAILED" -gt 20 ]]; then
        fail_check "$FAILED failed login attempts in auth.log — possible brute-force"
    elif [[ "$FAILED" -gt 0 ]]; then
        warn_check "$FAILED failed login attempts logged"
    else
        pass_check "No failed logins in auth.log"
    fi
elif [[ -f /var/log/secure ]]; then
    FAILED=$(grep -c "Failed password" /var/log/secure 2>/dev/null)
    if [[ "$FAILED" -gt 20 ]]; then
        fail_check "$FAILED failed login attempts in /var/log/secure"
    elif [[ "$FAILED" -gt 0 ]]; then
        warn_check "$FAILED failed login attempts logged"
    else
        pass_check "No failed logins in /var/log/secure"
    fi
else
    info_check "No auth log found (checked auth.log and secure)"
fi

# ============================================================================
# SECTION 13: ACTIVE CONNECTIONS
# ============================================================================
section "13. ACTIVE SSH CONNECTIONS"

if command -v ss >/dev/null 2>&1; then
    CONN=$(ss -tn state established "( sport = :$SSH_PORT or dport = :$SSH_PORT )" 2>/dev/null | tail -n +2 | wc -l)
    info_check "$CONN established SSH connection(s) on port $SSH_PORT"
elif command -v netstat >/dev/null 2>&1; then
    CONN=$(netstat -tn 2>/dev/null | grep -cE ":${SSH_PORT}\b.*ESTABLISHED")
    info_check "$CONN established SSH connection(s)"
fi

if [[ -f /etc/ssh/sshd_config ]]; then
    if find_sshd_setting "Port" >/dev/null 2>&1; then
        if [[ "$SSH_PORT" == "22" ]]; then
            info_check "SSH running on default port 22 (informational)"
        else
            pass_check "SSH on non-default port $SSH_PORT"
        fi
    fi
fi

# ============================================================================
# SECTION 14: CLEANUP / HOUSEKEEPING
# ============================================================================
section "14. HOUSEKEEPING"

sub "Old authorized_keys backups"
AK_BAK=$(find "$HOME/.ssh" /root/.ssh -name "authorized_keys.*" 2>/dev/null | wc -l)
[[ "$AK_BAK" -gt 0 ]] && warn_check "$AK_BAK authorized_keys backup files present — verify manually"

sub "Orphan .ssh files with wrong ownership"
if [[ $EUID -eq 0 ]]; then
    WRONG_OWN=$(find /home -maxdepth 3 -path "*/.ssh/*" ! -user "$(stat -c '%U' /home 2>/dev/null || echo root)" 2>/dev/null | head -5)
    if [[ -n "$WRONG_OWN" ]]; then
        warn_check "Some ~/.ssh files may have wrong ownership (SSH will reject them)"
        echo "$WRONG_OWN" | sed 's/^/    /'
    fi
fi

# ============================================================================
# SECTION 15: SUMMARY
# ============================================================================
section "SUMMARY"

echo ""
echo -e "${BOLD}  Total PASS: ${GREEN}$PASS${NC}"
echo -e "${BOLD}  Total WARN: ${YELLOW}$WARN${NC}"
echo -e "${BOLD}  Total FAIL: ${RED}$FAIL${NC}"
echo -e "${BOLD}  Total INFO: ${BLUE}$INFO${NC}"
echo ""

if [[ $FAIL -gt 0 ]]; then
    echo -e "${RED}${BOLD}  RESULT: UNSAFE ❌ — $FAIL critical issue(s) must be fixed${NC}"
    EXIT_CODE=2
elif [[ $WARN -gt 0 ]]; then
    echo -e "${YELLOW}${BOLD}  RESULT: NEEDS ATTENTION ⚠️  — $WARN warning(s)${NC}"
    EXIT_CODE=1
else
    echo -e "${GREEN}${BOLD}  RESULT: HEALTHY ✅ — all checks passed${NC}"
    EXIT_CODE=0
fi

echo ""
echo "================================================================================"
echo "              Finished at: $(date '+%Y-%m-%d %H:%M:%S')"
echo "================================================================================"
echo ""
echo "Visit more at https://github.com/MojSep"
echo ""

exit $EXIT_CODE


