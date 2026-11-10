#!/usr/bin/env bash
# ============================================================================
#  Ansible Health & Security Check
#  Author: MojSep
#  Description: Comprehensive health & security audit for Ansible
#  Usage: sudo ./ansible-healthcheck.sh [-v]
# ============================================================================

# ---------- Header ----------
echo ""
echo "Visit more at https://github.com/MojSep"
echo ""
echo "================================================================================"
echo "              ANSIBLE HEALTH & SECURITY CHECK"
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

# ---------- Verbose flag ----------
VERBOSE=${1:-}

# ---------- Helper Functions ----------
pass_check()  { echo -e "${GREEN}✅ [PASS]${NC} $*";             ((PASS++)); }
warn_check()  { echo -e "${YELLOW}⚠️  [WARN]${NC} $*";            ((WARN++)); }
fail_check()  { echo -e "${RED}❌ [FAIL]${NC} $*";               ((FAIL++)); }
info_check()  { echo -e "${BLUE}ℹ️  [INFO]${NC} $*";             ((INFO++)); }

section() {
    echo ""
    echo -e "${CYAN}════════════════════════════════════════════════════════════════════════${NC}"
    echo -e "${CYAN}  ▶ $*${NC}"
    echo -e "${CYAN}════════════════════════════════════════════════════════════════════════${NC}"
}

sub() {
    echo -e "  ${MAGENTA}── $* ──${NC}"
}

# Find the line number of a setting in a config file
find_line() {
    local file="$1" key="$2"
    grep -nE "^\s*${key}\s*=" "$file" 2>/dev/null | head -1 | cut -d: -f1
}

# Get value of a setting in a config file
get_value() {
    local file="$1" key="$2"
    grep -E "^\s*${key}\s*=" "$file" 2>/dev/null | head -1 | sed "s/^\s*${key}\s*=\s*//" | sed 's/\s*#.*$//' | xargs
}

# Check a config key with expected value
check_cfg() {
    local file="$1" key="$2" expected="$3" severity="$4"
    local line_num value

    if [[ ! -f "$file" ]]; then
        return 1
    fi

    line_num=$(find_line "$file" "$key")
    value=$(get_value "$file" "$key")

    if [[ -z "$line_num" ]]; then
        case "$severity" in
            critical) fail_check "$key: NOT SET in $file (expected: $expected)" ;;
            warning)  warn_check "$key: NOT SET in $file (expected: $expected)" ;;
            info)     info_check "$key: NOT SET in $file (default applies)" ;;
        esac
        return 1
    fi

    if [[ "$value" =~ ^(${expected})$ ]]; then
        pass_check "$key = '$value' [${file##*/}:${line_num}]"
    else
        case "$severity" in
            critical) fail_check "$key = '$value' (File: $file Line: $line_num) — expected: '$expected'" ;;
            warning)  warn_check "$key = '$value' (File: $file Line: $line_num) — expected: '$expected'" ;;
            info)     info_check "$key = '$value' (File: $file Line: $line_num)" ;;
        esac
    fi
}

# Check file permissions
check_perm() {
    local file="$1" expected="$2" severity="$3"
    if [[ ! -e "$file" ]]; then
        info_check "File not present: $file"
        return
    fi
    local actual
    actual=$(stat -c '%a' "$file" 2>/dev/null)
    if [[ "$actual" == "$expected" ]]; then
        pass_check "Permissions '$actual' on $file"
    else
        case "$severity" in
            critical) fail_check "Insecure permissions '$actual' on $file (expected '$expected')" ;;
            warning)  warn_check "Permissions '$actual' on $file (expected '$expected')" ;;
        esac
    fi
}

# ============================================================================
# SECTION 1: PREREQUISITES
# ============================================================================
section "1. SYSTEM PREREQUISITES"

sub "Python interpreter"
if command -v python3 >/dev/null 2>&1; then
    PY_VER=$(python3 --version 2>&1 | awk '{print $2}')
    PY_MAJOR=$(echo "$PY_VER" | cut -d. -f1)
    PY_MINOR=$(echo "$PY_VER" | cut -d. -f2)
    if [[ "$PY_MAJOR" -ge 3 && "$PY_MINOR" -ge 9 ]]; then
        pass_check "python3 version $PY_VER (>= 3.9 required)"
    else
        fail_check "python3 version $PY_VER is too old (>= 3.9 required)"
    fi
else
    fail_check "python3 not found in PATH"
fi

sub "pip / pip3"
if command -v pip3 >/dev/null 2>&1 || command -v pip >/dev/null 2>&1; then
    pass_check "pip is available"
    if pip3 check 2>&1 | grep -qi "broken"; then
        fail_check "pip check reports broken dependencies"
    else
        pass_check "pip check — no broken dependencies"
    fi
else
    warn_check "pip not found — Ansible may still work but cannot be upgraded via pip"
fi

# ============================================================================
# SECTION 2: ANSIBLE INSTALLATION
# ============================================================================
section "2. ANSIBLE INSTALLATION"

sub "Binary"
if command -v ansible >/dev/null 2>&1; then
    ANSIBLE_BIN=$(command -v ansible)
    pass_check "ansible binary: $ANSIBLE_BIN"
else
    fail_check "ansible binary NOT found in PATH — cannot continue"
    echo ""
    echo "Visit more at https://github.com/MojSep"
    echo ""
    exit 3
fi

sub "Version"
ANSIBLE_VERSION_OUT=$(ansible --version 2>&1)
ANSIBLE_CORE_VER=$(echo "$ANSIBLE_VERSION_OUT" | grep -i "ansible.core" | head -1 | awk -F'[][]' '{print $2}')
if [[ -n "$ANSIBLE_CORE_VER" ]]; then
    info_check "ansible-core version: $ANSIBLE_CORE_VER"
else
    ANSIBLE_CORE_VER=$(echo "$ANSIBLE_VERSION_OUT" | grep -i "ansible" | head -1 | awk '{print $2}')
    info_check "ansible version: $ANSIBLE_CORE_VER"
fi

sub "ansible-playbook / ansible-galaxy / ansible-vault"
for bin in ansible-playbook ansible-galaxy ansible-vault ansible-config ansible-doc ansible-inventory; do
    if command -v "$bin" >/dev/null 2>&1; then
        pass_check "$bin: $(command -v $bin)"
    else
        warn_check "$bin missing in PATH"
    fi
done

sub "Python interpreter used by Ansible"
PY_FROM_ANSIBLE=$(echo "$ANSIBLE_VERSION_OUT" | grep -i "python version" | awk -F'=' '{print $2}' | xargs)
if [[ -n "$PY_FROM_ANSIBLE" ]]; then
    info_check "Ansible running with Python: $PY_FROM_ANSIBLE"
fi

# ============================================================================
# SECTION 3: CONFIGURATION FILE DISCOVERY
# ============================================================================
section "3. CONFIGURATION FILE DISCOVERY (Priority order)"

ACTIVE_CFG=""
CFG_LOCATIONS=()
[[ -n "$ANSIBLE_CONFIG" ]] && CFG_LOCATIONS+=("ANSIBLE_CONFIG=$ANSIBLE_CONFIG")
CFG_LOCATIONS+=("./ansible.cfg")
CFG_LOCATIONS+=("$HOME/.ansible.cfg")
CFG_LOCATIONS+=("/etc/ansible/ansible.cfg")

for cfg in "${CFG_LOCATIONS[@]}"; do
    if [[ "$cfg" == ANSIBLE_CONFIG=* ]]; then
        path="${cfg#ANSIBLE_CONFIG=}"
        if [[ -f "$path" ]]; then
            pass_check "$cfg (exists)"
            [[ -z "$ACTIVE_CFG" ]] && ACTIVE_CFG="$path"
        else
            fail_check "$cfg — path does not exist"
        fi
        continue
    fi

    if [[ -f "$cfg" ]]; then
        pass_check "Config file exists: $cfg"
        [[ -z "$ACTIVE_CFG" ]] && ACTIVE_CFG="$cfg"
    else
        info_check "Config not present: $cfg"
    fi
done

if [[ -n "$ACTIVE_CFG" ]]; then
    info_check "Effective config file: $ACTIVE_CFG"
    echo ""
    echo -e "  ${BOLD}Effective configuration (dump --only-changed):${NC}"
    ansible-config dump --only-changed 2>&1 | head -20 | sed 's/^/    /'
else
    warn_check "No ansible.cfg found — using defaults (dangerous for production)"
fi

# ============================================================================
# SECTION 4: ANSIBLE.CFG SECURITY SETTINGS
# ============================================================================
section "4. ANSIBLE.CFG SECURITY SETTINGS"

if [[ -n "$ACTIVE_CFG" && -f "$ACTIVE_CFG" ]]; then
    sub "[defaults] — critical security"
    check_cfg "$ACTIVE_CFG" "host_key_checking"         "True|true|yes|Yes"         critical
    check_cfg "$ACTIVE_CFG" "allow_world_readable_tmpfiles" "False|false|no|No"    critical
    check_cfg "$ACTIVE_CFG" "error_on_undefined_vars"   "True|true|yes|Yes"        warning
    check_cfg "$ACTIVE_CFG" "allow_unsafe_lookups"      "False|false|no|No"        critical
    check_cfg "$ACTIVE_CFG" "inject_facts_as_vars"      "False|false|no|No"        warning
    check_cfg "$ACTIVE_CFG" "hash_behaviour"            "replace"                   warning
    check_cfg "$ACTIVE_CFG" "interpreter_python"        "/usr/bin/python3"          warning
    check_cfg "$ACTIVE_CFG" "transport"                 "smart|ssh"                 warning
    check_cfg "$ACTIVE_CFG" "gathering"                 "smart|explicit"            info
    check_cfg "$ACTIVE_CFG" "retry_files_enabled"       "True|true|yes"             info

    sub "[defaults] — log"
    LOG_PATH=$(get_value "$ACTIVE_CFG" "log_path")
    if [[ -n "$LOG_PATH" ]]; then
        pass_check "log_path configured: $LOG_PATH"
        if [[ -f "$LOG_PATH" ]]; then
            check_perm "$LOG_PATH" "640" warning
        else
            warn_check "log_path '$LOG_PATH' does not exist yet (will be created on first run)"
        fi
    else
        warn_check "log_path NOT configured — audit trail missing"
    fi

    sub "[privilege_escalation]"
    BECOME=$(get_value "$ACTIVE_CFG" "become")
    if [[ "$BECOME" == "True" || "$BECOME" == "true" ]]; then
        warn_check "become = True globally — restrict to tasks that need it"
    else
        pass_check "become not enabled globally (good — task-level only)"
    fi
    check_cfg "$ACTIVE_CFG" "become_method"             "sudo"                      info
    check_cfg "$ACTIVE_CFG" "become_flags"              "\-H \-S \-n"               info

    sub "[ssh_connection]"
    check_cfg "$ACTIVE_CFG" "pipelining"                "True|true|yes"             warning
    SSH_ARGS=$(get_value "$ACTIVE_CFG" "ssh_args")
    if [[ -n "$SSH_ARGS" ]]; then
        if echo "$SSH_ARGS" | grep -q "StrictHostKeyChecking=yes"; then
            pass_check "ssh_args: StrictHostKeyChecking=yes"
        else
            fail_check "ssh_args: StrictHostKeyChecking not enforced — MITM risk"
        fi
        if echo "$SSH_ARGS" | grep -q "PasswordAuthentication=no"; then
            pass_check "ssh_args: PasswordAuthentication=no"
        else
            warn_check "ssh_args: PasswordAuthentication not disabled"
        fi
        if echo "$SSH_ARGS" | grep -q "PreferredAuthentications=publickey"; then
            pass_check "ssh_args: PreferredAuthentications=publickey"
        else
            warn_check "ssh_args: PreferredAuthentications not restricted to publickey"
        fi
    else
        warn_check "ssh_args not configured — using insecure defaults"
    fi

    CP_DIR=$(get_value "$ACTIVE_CFG" "control_path_dir")
    if [[ -n "$CP_DIR" ]]; then
        CP_DIR_EXPANDED="${CP_DIR/#\~/$HOME}"
        if [[ -d "$CP_DIR_EXPANDED" ]]; then
            check_perm "$CP_DIR_EXPANDED" "700" critical
        else
            info_check "control_path_dir does not exist yet: $CP_DIR"
        fi
    fi

    sub "[galaxy]"
    check_cfg "$ACTIVE_CFG" "ignore_certs"              "False|false|no"            critical
    GALAXY_SERVER=$(get_value "$ACTIVE_CFG" "server")
    if [[ -n "$GALAXY_SERVER" ]]; then
        info_check "galaxy server: $GALAXY_SERVER"
        if [[ "$GALAXY_SERVER" == *"galaxy.ansible.com"* ]]; then
            warn_check "Using public galaxy.ansible.com — consider internal Automation Hub"
        fi
    fi

    sub "[inventory]"
    INV_PLUGINS=$(get_value "$ACTIVE_CFG" "enable_plugins")
    if [[ -n "$INV_PLUGINS" && "$INV_PLUGINS" == *"script"* ]]; then
        warn_check "enable_plugins includes 'script' — RCE risk if inventory dir compromised"
    else
        pass_check "enable_plugins does not include 'script'"
    fi

else
    warn_check "No ansible.cfg found — skipping setting checks"
fi

# ============================================================================
# SECTION 5: FILE PERMISSIONS
# ============================================================================
section "5. FILE PERMISSIONS"

sub "Ansible config"
for f in /etc/ansible/ansible.cfg "$HOME/.ansible.cfg" "./ansible.cfg"; do
    [[ -f "$f" ]] && check_perm "$f" "640" warning
done

sub "/etc/ansible directory"
if [[ -d /etc/ansible ]]; then
    check_perm "/etc/ansible" "750" warning
fi

sub "Vault password files"
for f in "$HOME/.vault_pass" /etc/ansible/.vault_pass /etc/ansible/vault_*; do
    if [[ -f "$f" ]]; then
        check_perm "$f" "600" critical
    fi
done

sub "SSH private keys"
for f in "$HOME/.ssh/id_rsa" "$HOME/.ssh/id_ed25519" /etc/ansible/keys/*; do
    if [[ -f "$f" ]]; then
        case "$f" in
            *.pub) check_perm "$f" "644" warning ;;
            *)     check_perm "$f" "600" critical ;;
        esac
    fi
done

sub "~/.ssh directory"
[[ -d "$HOME/.ssh" ]] && check_perm "$HOME/.ssh" "700" critical

sub "Control paths"
[[ -d "$HOME/.ansible/cp" ]] && check_perm "$HOME/.ansible/cp" "700" critical
[[ -d "$HOME/.ansible/pc" ]] && check_perm "$HOME/.ansible/pc" "700" critical

# ============================================================================
# SECTION 6: INVENTORY HEALTH
# ============================================================================
section "6. INVENTORY HEALTH"

sub "Default inventory location"
if [[ -f /etc/ansible/hosts ]]; then
    pass_check "/etc/ansible/hosts exists"
    check_perm /etc/ansible/hosts "640" warning
    if ansible-inventory -i /etc/ansible/hosts --list >/dev/null 2>&1; then
        pass_check "/etc/ansible/hosts parses successfully"
    else
        fail_check "/etc/ansible/hosts FAILED to parse"
    fi
elif [[ -d /etc/ansible/hosts ]]; then
    pass_check "/etc/ansible/hosts directory exists"
else
    warn_check "/etc/ansible/hosts does not exist"
fi

sub "Configured inventory path"
if [[ -n "$ACTIVE_CFG" ]]; then
    INV_PATH=$(get_value "$ACTIVE_CFG" "inventory")
    if [[ -n "$INV_PATH" ]]; then
        if [[ -e "$INV_PATH" ]]; then
            pass_check "inventory path exists: $INV_PATH"
            if ansible-inventory -i "$INV_PATH" --list >/dev/null 2>&1; then
                pass_check "inventory parses successfully"
            else
                fail_check "inventory FAILS to parse: $INV_PATH"
            fi
        else
            fail_check "inventory path does NOT exist: $INV_PATH"
        fi
    fi
fi

# ============================================================================
# SECTION 7: COLLECTIONS & ROLES
# ============================================================================
section "7. COLLECTIONS & ROLES"

sub "Installed collections"
if ansible-galaxy collection list >/dev/null 2>&1; then
    COLL_COUNT=$(ansible-galaxy collection list 2>/dev/null | grep -cE "^\S+\.\S+")
    pass_check "ansible-galaxy collection list works ($COLL_COUNT collections installed)"
else
    warn_check "ansible-galaxy collection list failed"
fi

sub "Collections path"
COLL_PATH=$(ansible-config dump 2>/dev/null | grep "COLLECTIONS_PATHS" | awk -F'=' '{print $2}' | xargs)
[[ -n "$COLL_PATH" ]] && info_check "collections_path: $COLL_PATH"

sub "Roles path"
ROLES_PATH=$(ansible-config dump 2>/dev/null | grep "DEFAULT_ROLES_PATH" | awk -F'=' '{print $2}' | xargs)
[[ -n "$ROLES_PATH" ]] && info_check "roles_path: $ROLES_PATH"

# ============================================================================
# SECTION 8: RETRY FILES
# ============================================================================
section "8. RETRY FILES (housekeeping)"

RETRY_FILES=$(find /etc/ansible /var/lib/ansible "$HOME" -maxdepth 3 -name "*.retry" 2>/dev/null | head -20)
if [[ -n "$RETRY_FILES" ]]; then
    COUNT=$(echo "$RETRY_FILES" | wc -l)
    warn_check "$COUNT stale .retry files found — investigate failed hosts"
    echo "$RETRY_FILES" | head -5 | sed 's/^/    /'
else
    pass_check "No stale .retry files"
fi

# ============================================================================
# SECTION 9: SUDOERS / BECOME
# ============================================================================
section "9. SUDOERS / PRIVILEGE ESCALATION"

if [[ -f /etc/sudoers.d/ansible ]]; then
    pass_check "/etc/sudoers.d/ansible exists"
    check_perm /etc/sudoers.d/ansible "440" critical
    if sudo -n visudo -cf /etc/sudoers.d/ansible >/dev/null 2>&1; then
        pass_check "sudoers file valid"
    else
        fail_check "sudoers file INVALID (visudo failed)"
    fi
    if grep -q "NOPASSWD: ALL" /etc/sudoers.d/ansible 2>/dev/null; then
        warn_check "sudoers grants NOPASSWD: ALL — restrict to specific commands"
    fi
else
    info_check "/etc/sudoers.d/ansible not present"
fi

# ============================================================================
# SECTION 10: LOG FILES
# ============================================================================
section "10. LOG FILES"

for log in /var/log/ansible.log "$HOME/.ansible.log"; do
    if [[ -f "$log" ]]; then
        pass_check "Log exists: $log ($(stat -c '%s' "$log") bytes)"
        check_perm "$log" "640" warning
        # check for secrets leaked in log
        if grep -qiE "password=|token=|api_key=|secret=" "$log" 2>/dev/null | head -1 | grep -q .; then
            fail_check "SECRET-like strings found in $log — inspect and rotate credentials"
        else
            pass_check "No obvious secrets in $log"
        fi
    fi
done

if [[ ! -f /var/log/ansible.log ]] && [[ ! -f "$HOME/.ansible.log" ]]; then
    warn_check "No Ansible log file found (audit trail missing)"
fi

# ============================================================================
# SECTION 11: LOCAL CONNECTIVITY TEST
# ============================================================================
section "11. LOCAL CONNECTIVITY TEST"

if ansible localhost -m ping -c local >/dev/null 2>&1; then
    pass_check "ansible localhost -m ping -c local works"
else
    fail_check "ansible localhost ping FAILED (check local connection)"
fi

if ansible localhost -m setup -c local >/dev/null 2>&1; then
    pass_check "ansible localhost -m setup works (facts gathering)"
else
    warn_check "ansible localhost -m setup failed"
fi

# ============================================================================
# SECTION 12: CRON / SCHEDULED JOBS
# ============================================================================
section "12. SCHEDULED JOBS"

CRON_JOBS=$( (crontab -l 2>/dev/null; cat /etc/cron.d/* 2>/dev/null) | grep -iE "ansible|ansible-playbook" | grep -v "^#" )
if [[ -n "$CRON_JOBS" ]]; then
    info_check "Cron jobs referencing Ansible:"
    echo "$CRON_JOBS" | sed 's/^/    /'
    warn_check "Review cron jobs for hardcoded credentials or unsafe playbooks"
else
    pass_check "No cron jobs invoking Ansible"
fi

# ============================================================================
# SECTION 13: SUMMARY
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



