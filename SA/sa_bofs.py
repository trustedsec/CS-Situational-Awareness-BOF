# =============================================================================
# SA BOFs — Nighthawk Python Module
# Port of SA.cna (TrustedSec Situational Awareness BOFs) for Nighthawk C2
# Author: Dominic Chell (@domchell)
# =============================================================================


# =============================================================================
# Section 1: Constants
# =============================================================================

RECORD_MAPPING = {
    "A": 1,
    "NS": 2,
    "MD": 3,
    "MF": 4,
    "CNAME": 5,
    "SOA": 6,
    "MB": 7,
    "MG": 8,
    "MR": 9,
    "WKS": 0x0B,
    "PTR": 0x0C,
    "HINFO": 0x0D,
    "MINFO": 0x0E,
    "MX": 0x0F,
    "TEXT": 0x10,
    "RP": 0x11,
    "AFSDB": 0x12,
    "X25": 0x13,
    "ISDN": 0x14,
    "RT": 0x15,
    "AAAA": 0x1C,
    "SRV": 0x21,
    "WINSR": 0xFF02,
    "KEY": 0x19,
    "ANY": 0xFF,
}

ENUM_TYPE = {
    "all": 1,
    "locked": 2,
    "disabled": 3,
    "active": 4,
}

REG_HIVES = {
    "HKCR": 0,
    "HKCU": 1,
    "HKLM": 2,
    "HKU": 3,
}


# =============================================================================
# Section 2: Helper Functions
# =============================================================================

def load_bof(info, bof_name):
    """Load BOF binary for the agent's architecture."""
    arch = info.Agent.ProcessArch
    path = nighthawk.script_resource(f"{bof_name}/{bof_name}.{arch}.o")
    try:
        with open(path, "rb") as f:
            data = f.read()
        if len(data) == 0:
            nighthawk.console_write(CONSOLE_ERROR, f"BOF file is empty: {path}")
            return None
        return data
    except Exception:
        nighthawk.console_write(CONSOLE_ERROR, f"Could not read BOF file: {path}")
        return None


def run_bof(info, bof_name, packed_args=b""):
    """Load and execute a BOF in one call."""
    bof_data = load_bof(info, bof_name)
    if bof_data is None:
        return
    arch = info.Agent.ProcessArch
    api.execute_bof(
        f"{bof_name}.{arch}.o", bof_data, packed_args,
        "go", True, 0, False, "", show_in_console=True,
    )


def parse_opts(params):
    """Parse /flag and /key:value options from a parameter list.

    Returns a dict where:
      - /KEY:VALUE entries become {"KEY": "VALUE"}
      - /FLAG entries become {"FLAG": "TRUE"}
      - positional args become {"1": val, "2": val, ...}
    """
    opts = {}
    pos = 1
    for arg in params:
        if arg.startswith("/") and ":" in arg[1:]:
            key, val = arg[1:].split(":", 1)
            opts[key] = val
        elif arg.startswith("/"):
            opts[arg[1:]] = "TRUE"
        else:
            opts[str(pos)] = arg
            pos += 1
    return opts


# =============================================================================
# Section 3: Command Handlers
# =============================================================================

# ---------------------------------------------------------------------------
# No-argument commands
# ---------------------------------------------------------------------------

def cmd_env(params, info):
    run_bof(info, "env")


def cmd_ipconfig(params, info):
    run_bof(info, "ipconfig")


def cmd_get_dpapi_system(params, info):
    run_bof(info, "get_dpapi_system")


def cmd_arp(params, info):
    run_bof(info, "arp")


def cmd_listdns(params, info):
    run_bof(info, "listdns")


def cmd_locale(params, info):
    run_bof(info, "locale")


def cmd_notepad(params, info):
    run_bof(info, "notepad")


def cmd_netstat(params, info):
    run_bof(info, "netstat")


def cmd_routeprint(params, info):
    run_bof(info, "routeprint")


def cmd_whoami(params, info):
    run_bof(info, "whoami")


def cmd_driversigs(params, info):
    run_bof(info, "driversigs")


def cmd_resources(params, info):
    run_bof(info, "resources")


def cmd_uptime(params, info):
    run_bof(info, "uptime")


def cmd_useridletime(params, info):
    run_bof(info, "useridletime")


def cmd_list_firewall_rules(params, info):
    run_bof(info, "list_firewall_rules")


def cmd_enumLocalSessions(params, info):
    run_bof(info, "enumlocalsessions")


def cmd_adcs_enum_com(params, info):
    run_bof(info, "adcs_enum_com")


def cmd_adcs_enum_com2(params, info):
    run_bof(info, "adcs_enum_com2")


def cmd_aadjoininfo(params, info):
    run_bof(info, "aadjoininfo")


def cmd_get_session_info(params, info):
    run_bof(info, "get_session_info")


# ---------------------------------------------------------------------------
# Single-argument commands
# ---------------------------------------------------------------------------

def cmd_netview(params, info):
    domain = params[0] if len(params) >= 1 else ""
    p = Packer()
    p.addwstr(domain)
    run_bof(info, "netview", p.getbuffer())


def cmd_listmods(params, info):
    pid = int(params[0]) if len(params) >= 1 else 0
    p = Packer()
    p.adduint32(pid)
    run_bof(info, "listmods", p.getbuffer())


def cmd_windowlist(params, info):
    flag = 1 if (len(params) >= 1 and params[0] == "all") else 0
    p = Packer()
    p.adduint32(flag)
    run_bof(info, "windowlist", p.getbuffer())


def cmd_sc_enum(params, info):
    hostname = params[0] if len(params) >= 1 else ""
    p = Packer()
    p.addstr(hostname)
    run_bof(info, "sc_enum", p.getbuffer())


def cmd_schtasksenum(params, info):
    target = params[0] if len(params) >= 1 else ""
    p = Packer()
    p.addwstr(target)
    run_bof(info, "schtasksenum", p.getbuffer())


def cmd_adcs_enum(params, info):
    domain = params[0] if len(params) >= 1 else ""
    p = Packer()
    p.addwstr(domain)
    run_bof(info, "adcs_enum", p.getbuffer())


def cmd_get_password_policy(params, info):
    if len(params) < 1:
        nighthawk.console_write(
            CONSOLE_ERROR,
            "Usage: get_password_policy <server>\n"
            "Specify a target server or DC.",
        )
        return
    p = Packer()
    p.addwstr(params[0])
    run_bof(info, "get_password_policy", p.getbuffer())


def cmd_netloggedon(params, info):
    name = params[0] if len(params) >= 1 else ""
    p = Packer()
    p.addwstr(name)
    p.adduint32(0)
    run_bof(info, "netloggedon", p.getbuffer())


def cmd_netloggedon2(params, info):
    name = params[0] if len(params) >= 1 else ""
    p = Packer()
    p.addwstr(name)
    p.adduint32(0)
    run_bof(info, "netloggedon2", p.getbuffer())


def cmd_netuptime(params, info):
    name = params[0] if len(params) >= 1 else ""
    p = Packer()
    p.addwstr(name)
    p.adduint32(0)
    run_bof(info, "netuptime", p.getbuffer())


def cmd_nettime(params, info):
    name = params[0] if len(params) >= 1 else ""
    p = Packer()
    p.addwstr(name)
    run_bof(info, "nettime", p.getbuffer())


def cmd_regsession(params, info):
    name = params[0] if len(params) >= 1 else ""
    p = Packer()
    p.addstr(name)
    run_bof(info, "regsession", p.getbuffer())


def cmd_enum_filter_driver(params, info):
    system = params[0] if len(params) >= 1 else ""
    p = Packer()
    p.addstr(system)
    run_bof(info, "enum_filter_driver", p.getbuffer())


def cmd_adv_audit_policies(params, info):
    is_wow64 = 1 if info.Agent.ProcessArch != info.Agent.MachineArch else 0
    p = Packer()
    p.adduint32(is_wow64)
    run_bof(info, "adv_audit_policies", p.getbuffer())


# ---------------------------------------------------------------------------
# Multi-argument commands
# ---------------------------------------------------------------------------

def cmd_dir(params, info):
    opts = parse_opts(params)
    targetdir = opts.get("1", ".\\")
    subdirs = 1 if "s" in opts else 0
    p = Packer()
    p.addstr(targetdir)
    p.addshort(subdirs)
    run_bof(info, "dir", p.getbuffer())


def cmd_ldapsearch(params, info):
    if len(params) < 1:
        nighthawk.console_write(
            CONSOLE_ERROR,
            "Usage: ldapsearch <query> [--attributes val] [--count val] "
            "[--scope val] [--hostname val] [--dn val] [--ldaps]",
        )
        return

    query = params[0]
    attributes = "*"
    result_limit = 0
    scope = 3
    hostname = ""
    dn = ""
    ldaps = 0

    i = 1
    while i < len(params):
        opt = params[i]
        if opt == "--attributes" and i + 1 < len(params):
            i += 1
            attributes = params[i]
        elif opt == "--count" and i + 1 < len(params):
            i += 1
            result_limit = int(params[i])
        elif opt == "--scope" and i + 1 < len(params):
            i += 1
            scope = int(params[i])
        elif opt == "--hostname" and i + 1 < len(params):
            i += 1
            hostname = params[i]
        elif opt == "--dn" and i + 1 < len(params):
            i += 1
            dn = params[i]
        elif opt == "--ldaps":
            ldaps = 1
        else:
            nighthawk.console_write(CONSOLE_ERROR, f"Unknown argument: {opt}")
            return
        i += 1

    p = Packer()
    p.addstr(query)
    p.addstr(attributes)
    p.adduint32(result_limit)
    p.adduint32(scope)
    p.addstr(hostname)
    p.addstr(dn)
    p.adduint32(ldaps)
    run_bof(info, "ldapsearch", p.getbuffer())


def cmd_nonpagedldapsearch(params, info):
    if len(params) < 1:
        nighthawk.console_write(
            CONSOLE_ERROR,
            "Usage: nonpagedldapsearch <query> [attributes] [count] "
            "[hostname] [domain]",
        )
        return

    query = params[0]
    attributes = params[1] if len(params) > 1 else ""
    result_limit = int(params[2]) if len(params) > 2 else 0
    hostname = params[3] if len(params) > 3 else ""
    domain = params[4] if len(params) > 4 else ""

    p = Packer()
    p.addstr(query)
    p.addstr(attributes)
    p.adduint32(result_limit)
    p.addstr(hostname)
    p.addstr(domain)
    run_bof(info, "nonpagedldapsearch", p.getbuffer())


def cmd_nslookup(params, info):
    if len(params) < 1:
        nighthawk.console_write(
            CONSOLE_ERROR,
            "Usage: nslookup <lookup> [server] [type]\n"
            "Type is a DNS record type (A, AAAA, SRV, etc.)",
        )
        return

    lookup = params[0]
    server = params[1] if len(params) > 1 else ""
    record_type = params[2].upper() if len(params) > 2 else "A"
    type_val = RECORD_MAPPING.get(record_type, RECORD_MAPPING["A"])

    if server == "127.0.0.1":
        nighthawk.console_write(
            CONSOLE_ERROR,
            "Localhost DNS queries have a potential to crash, refusing",
        )
        return

    if info.Agent.ProcessArch == "x86":
        server = ""

    p = Packer()
    p.addstr(lookup)
    p.addstr(server)
    p.addshort(type_val)
    run_bof(info, "nslookup", p.getbuffer())


# --- net use commands (share BOF "netuse") ---

def cmd_netuse_add(params, info):
    if len(params) < 3:
        nighthawk.console_write(
            CONSOLE_ERROR,
            "Usage: netuse_add <share> <user> <password> "
            "[/DEVICE:devname] [/PERSIST] [/REQUIREPRIVACY]",
        )
        return

    share = params[0]
    user = params[1]
    password = params[2]
    opts = parse_opts(params)
    device = ""
    persist = 0
    requireencrypt = 0
    if "PERSIST" in opts:
        persist = 1
    if "REQUIREPRIVACY" in opts:
        requireencrypt = 1
    if "DEVICE" in opts:
        device = opts["DEVICE"] + ":"

    p = Packer()
    p.addshort(1)
    p.addwstr(share)
    p.addwstr(user)
    p.addwstr(password)
    p.addwstr(device)
    p.addshort(persist)
    p.addshort(requireencrypt)
    run_bof(info, "netuse", p.getbuffer())


def cmd_netuse_list(params, info):
    target = ""
    if len(params) >= 1:
        target = params[0]
        if len(target) == 1:
            target = target + ":"
        elif len(target) > 2 and not target.startswith("\\\\"):
            target = "\\\\" + target
    p = Packer()
    p.addshort(2)
    p.addwstr(target)
    run_bof(info, "netuse", p.getbuffer())


def cmd_netuse_delete(params, info):
    if len(params) < 1:
        nighthawk.console_write(
            CONSOLE_ERROR,
            "Usage: netuse_delete <device|share> [/PERSIST] [/FORCE]",
        )
        return

    target = params[0]
    if len(target) == 1:
        target = target + ":"
    elif len(target) > 2 and not target.startswith("\\\\"):
        target = "\\\\" + target

    opts = parse_opts(params)
    persist = 1 if "PERSIST" in opts else 0
    force = 1 if "FORCE" in opts else 0

    p = Packer()
    p.addshort(3)
    p.addwstr(target)
    p.addshort(persist)
    p.addshort(force)
    run_bof(info, "netuse", p.getbuffer())


# --- net user ---

def cmd_netuser(params, info):
    if len(params) < 1:
        nighthawk.console_write(
            CONSOLE_ERROR,
            "Usage: netuser <username> [domain]",
        )
        return
    username = params[0]
    domain = params[1] if len(params) >= 2 else ""
    p = Packer()
    p.addwstr(username)
    p.addwstr(domain)
    run_bof(info, "netuser", p.getbuffer())


# --- user / domain enumeration (share BOF "netuserenum") ---

def cmd_userenum(params, info):
    filter_name = params[0] if len(params) >= 1 else "all"
    if filter_name not in ENUM_TYPE:
        nighthawk.console_write(
            CONSOLE_ERROR,
            "Invalid filter. Use one of: all, locked, disabled, active",
        )
        return
    p = Packer()
    p.adduint32(0)
    p.adduint32(ENUM_TYPE[filter_name])
    run_bof(info, "netuserenum", p.getbuffer())


def cmd_domainenum(params, info):
    filter_name = params[0] if len(params) >= 1 else "all"
    if filter_name not in ENUM_TYPE:
        nighthawk.console_write(
            CONSOLE_ERROR,
            "Invalid filter. Use one of: all, locked, disabled, active",
        )
        return
    p = Packer()
    p.adduint32(1)
    p.adduint32(ENUM_TYPE[filter_name])
    run_bof(info, "netuserenum", p.getbuffer())


# --- net shares ---

def cmd_netshares(params, info):
    name = params[0] if len(params) >= 1 else ""
    p = Packer()
    p.addwstr(name)
    p.adduint32(0)
    run_bof(info, "netshares", p.getbuffer())


def cmd_netsharesAdmin(params, info):
    name = params[0] if len(params) >= 1 else ""
    p = Packer()
    p.addwstr(name)
    p.adduint32(1)
    run_bof(info, "netshares", p.getbuffer())


# --- net group (share BOF "netgroup") ---

def cmd_netGroupList(params, info):
    domain = params[0] if len(params) >= 1 else ""
    p = Packer()
    p.addshort(0)
    p.addwstr(domain)
    p.addwstr("")
    run_bof(info, "netgroup", p.getbuffer())


def cmd_netGroupListMembers(params, info):
    if len(params) < 1:
        nighthawk.console_write(
            CONSOLE_ERROR,
            "Usage: netGroupListMembers <group> [domain]",
        )
        return
    group = params[0]
    domain = params[1] if len(params) >= 2 else ""
    p = Packer()
    p.addshort(1)
    p.addwstr(domain)
    p.addwstr(group)
    run_bof(info, "netgroup", p.getbuffer())


# --- net local group (share BOF "netlocalgroup") ---

def cmd_netLocalGroupList(params, info):
    server = params[0] if len(params) >= 1 else ""
    p = Packer()
    p.addshort(0)
    p.addwstr(server)
    p.addwstr("")
    run_bof(info, "netlocalgroup", p.getbuffer())


def cmd_netLocalGroupListMembers(params, info):
    if len(params) < 1:
        nighthawk.console_write(
            CONSOLE_ERROR,
            "Usage: netLocalGroupListMembers <group> [server]",
        )
        return
    group = params[0]
    server = params[1] if len(params) >= 2 else ""
    p = Packer()
    p.addshort(1)
    p.addwstr(server)
    p.addwstr(group)
    run_bof(info, "netlocalgroup", p.getbuffer())


def cmd_netLocalGroupListMembers2(params, info):
    group = params[0] if len(params) >= 1 else ""
    server = params[1] if len(params) >= 2 else ""
    p = Packer()
    p.addwstr(server)
    p.addwstr(group)
    run_bof(info, "netlocalgroup2", p.getbuffer())


# --- scheduled tasks ---

def cmd_schtasksquery(params, info):
    if len(params) < 1 or len(params) > 2:
        nighthawk.console_write(
            CONSOLE_ERROR,
            "Usage: schtasksquery [server] <taskname>\n"
            "Task name must be given by full path, e.g. "
            "\\Microsoft\\Windows\\MUI\\LpRemove",
        )
        return
    if len(params) == 1:
        server = ""
        taskname = params[0]
    else:
        server = params[0]
        taskname = params[1]
    p = Packer()
    p.addwstr(server)
    p.addwstr(taskname)
    run_bof(info, "schtasksquery", p.getbuffer())


# --- cacls ---

def cmd_cacls(params, info):
    if len(params) < 1:
        nighthawk.console_write(
            CONSOLE_ERROR,
            "Usage: cacls <filepath>\nWildcards supported.",
        )
        return
    p = Packer()
    p.addwstr(params[0])
    run_bof(info, "cacls", p.getbuffer())


# --- service query commands (sc_*) ---

def cmd_sc_query(params, info):
    hostname = ""
    servicename = ""
    if len(params) >= 1:
        servicename = params[0]
    if len(params) >= 2:
        hostname = params[1]
    p = Packer()
    p.addstr(hostname)
    p.addstr(servicename)
    run_bof(info, "sc_query", p.getbuffer())


def cmd_sc_qc(params, info):
    if len(params) < 1:
        nighthawk.console_write(
            CONSOLE_ERROR,
            "Usage: sc_qc <service_name> [hostname]",
        )
        return
    servicename = params[0]
    hostname = params[1] if len(params) >= 2 else ""
    p = Packer()
    p.addstr(hostname)
    p.addstr(servicename)
    run_bof(info, "sc_qc", p.getbuffer())


def cmd_sc_qdescription(params, info):
    if len(params) < 1:
        nighthawk.console_write(
            CONSOLE_ERROR,
            "Usage: sc_qdescription <service_name> [hostname]",
        )
        return
    servicename = params[0]
    hostname = params[1] if len(params) >= 2 else ""
    p = Packer()
    p.addstr(hostname)
    p.addstr(servicename)
    run_bof(info, "sc_qdescription", p.getbuffer())


def cmd_sc_qfailure(params, info):
    if len(params) < 1:
        nighthawk.console_write(
            CONSOLE_ERROR,
            "Usage: sc_qfailure <service_name> [hostname]",
        )
        return
    servicename = params[0]
    hostname = params[1] if len(params) >= 2 else ""
    p = Packer()
    p.addstr(hostname)
    p.addstr(servicename)
    run_bof(info, "sc_qfailure", p.getbuffer())


def cmd_sc_qtriggerinfo(params, info):
    if len(params) < 1:
        nighthawk.console_write(
            CONSOLE_ERROR,
            "Usage: sc_qtriggerinfo <service_name> [hostname]",
        )
        return
    servicename = params[0]
    hostname = params[1] if len(params) >= 2 else ""
    p = Packer()
    p.addstr(hostname)
    p.addstr(servicename)
    run_bof(info, "sc_qtriggerinfo", p.getbuffer())


# --- registry query ---

def cmd_reg_query(params, info):
    if len(params) < 2:
        nighthawk.console_write(
            CONSOLE_ERROR,
            "Usage: reg_query [hostname] <hive> <path> [key]\n"
            "Hive: HKLM, HKCU, HKU, HKCR",
        )
        return

    i = 0
    if params[0].upper() in REG_HIVES:
        hostname = ""
    else:
        hostname = "\\\\" + params[0]
        i = 1

    if i >= len(params) or params[i].upper() not in REG_HIVES:
        nighthawk.console_write(
            CONSOLE_ERROR, "Provided registry hive value is invalid",
        )
        return
    hive = REG_HIVES[params[i].upper()]
    i += 1

    if i >= len(params):
        nighthawk.console_write(
            CONSOLE_ERROR,
            "Usage: reg_query [hostname] <hive> <path> [key]",
        )
        return
    path = params[i]
    i += 1
    key = params[i] if i < len(params) else ""

    p = Packer()
    p.addstr(hostname)
    p.adduint32(hive)
    p.addstr(path)
    p.addstr(key)
    p.adduint32(0)
    run_bof(info, "reg_query", p.getbuffer())


def cmd_reg_query_recursive(params, info):
    if len(params) < 2:
        nighthawk.console_write(
            CONSOLE_ERROR,
            "Usage: reg_query_recursive [hostname] <hive> <path>\n"
            "Hive: HKLM, HKCU, HKU, HKCR",
        )
        return

    i = 0
    if params[0].upper() in REG_HIVES:
        hostname = ""
    else:
        hostname = "\\\\" + params[0]
        i = 1

    if i >= len(params) or params[i].upper() not in REG_HIVES:
        nighthawk.console_write(
            CONSOLE_ERROR, "Provided registry hive value is invalid",
        )
        return
    hive = REG_HIVES[params[i].upper()]
    i += 1

    if i >= len(params):
        nighthawk.console_write(
            CONSOLE_ERROR,
            "Usage: reg_query_recursive [hostname] <hive> <path>",
        )
        return
    path = params[i]

    p = Packer()
    p.addstr(hostname)
    p.adduint32(hive)
    p.addstr(path)
    p.addstr("")
    p.adduint32(1)
    run_bof(info, "reg_query", p.getbuffer())


# --- tasklist / WMI ---

def cmd_tasklist(params, info):
    if len(params) >= 1 and params[0]:
        resource = f"\\\\{params[0]}\\root\\cimv2"
    else:
        resource = "\\\\.\\root\\cimv2"
    p = Packer()
    p.addwstr(resource)
    run_bof(info, "tasklist", p.getbuffer())


def cmd_wmi_query(params, info):
    if len(params) < 1:
        nighthawk.console_write(
            CONSOLE_ERROR,
            "Usage: wmi_query <query> [system] [namespace]",
        )
        return
    query = params[0]
    system = params[1] if len(params) > 1 else "."
    namespace = params[2] if len(params) > 2 else "root\\cimv2"
    resource = f"\\\\{system}\\{namespace}"
    p = Packer()
    p.addwstr(system)
    p.addwstr(namespace)
    p.addwstr(query)
    p.addwstr(resource)
    run_bof(info, "wmi_query", p.getbuffer())


# --- net session ---

def cmd_netsession(params, info):
    if len(params) < 1:
        nighthawk.console_write(
            CONSOLE_ERROR, "Usage: netsession <computer>",
        )
        return
    p = Packer()
    p.addwstr(params[0])
    run_bof(info, "get-netsession", p.getbuffer())


def cmd_netsession2(params, info):
    hostname = params[0] if len(params) > 0 else ""
    method = int(params[1]) if len(params) > 1 else 1
    dnsserver = params[2] if len(params) > 2 else ""
    p = Packer()
    p.addwstr(hostname)
    p.addshort(method)
    p.addstr(dnsserver)
    run_bof(info, "get-netsession2", p.getbuffer())


# --- findLoadedModule ---

def cmd_findLoadedModule(params, info):
    if info.Agent.ProcessArch != info.Agent.MachineArch:
        nighthawk.console_write(
            CONSOLE_ERROR,
            "Unable to run this BOF properly when under WOW64 "
            "(32bit proc on 64bit host)",
        )
        return
    if len(params) < 1 or len(params) > 2:
        nighthawk.console_write(
            CONSOLE_ERROR,
            "Usage: findLoadedModule <dll_name> [proc_name]",
        )
        return
    modname = params[0]
    procname = params[1] if len(params) > 1 else ""
    p = Packer()
    p.addstr(modname)
    p.addstr(procname)
    run_bof(info, "findLoadedModule", p.getbuffer())


# --- vssenum ---

def cmd_vssenum(params, info):
    if len(params) < 1:
        nighthawk.console_write(
            CONSOLE_ERROR,
            "Usage: vssenum <hostname> [sharename]\n"
            "Sharename defaults to C$ if not specified.",
        )
        return
    hostname = params[0]
    sharename = params[1] if len(params) > 1 else "C$"
    p = Packer()
    p.addwstr(hostname)
    p.addwstr(sharename)
    run_bof(info, "vssenum", p.getbuffer())


# --- probe ---

def cmd_probe(params, info):
    if len(params) < 2:
        nighthawk.console_write(
            CONSOLE_ERROR, "Usage: probe <host> <port>",
        )
        return
    host = params[0]
    try:
        port = int(params[1])
    except ValueError:
        nighthawk.console_write(CONSOLE_ERROR, "Port must be a number")
        return
    if port < 1 or port > 65535:
        nighthawk.console_write(CONSOLE_ERROR, "Port out of range (1-65535)")
        return
    p = Packer()
    p.addstr(host)
    p.adduint32(port)
    run_bof(info, "probe", p.getbuffer())


# --- hash commands ---

def cmd_sha256(params, info):
    if len(params) < 1:
        nighthawk.console_write(
            CONSOLE_ERROR, "Usage: sha256 <filename>",
        )
        return
    p = Packer()
    p.addstr(params[0])
    run_bof(info, "sha256", p.getbuffer())


def cmd_md5(params, info):
    if len(params) < 1:
        nighthawk.console_write(
            CONSOLE_ERROR, "Usage: md5 <filename>",
        )
        return
    p = Packer()
    p.addstr(params[0])
    run_bof(info, "md5", p.getbuffer())


def cmd_sha1(params, info):
    if len(params) < 1:
        nighthawk.console_write(
            CONSOLE_ERROR, "Usage: sha1 <filename>",
        )
        return
    p = Packer()
    p.addstr(params[0])
    run_bof(info, "sha1", p.getbuffer())


# --- ldapsecuritycheck ---

def cmd_ldapsecuritycheck(params, info):
    dc = params[0] if len(params) >= 1 else ""
    p = Packer()
    p.addwstr(dc)
    run_bof(info, "ldapsecuritycheck", p.getbuffer())


# --- listpipes (special: not a BOF, uses directory listing) ---

def cmd_listpipes(params, info):
    api.ls("\\\\.\\pipe\\")


# =============================================================================
# Section 4: Command Registration
#
# Signature: register_command(function, name, long_description,
#                             short_description, usage, example)
# =============================================================================

# No-argument commands
nighthawk.register_command(cmd_env, "env",
    "Print environment variables for the current process",
    "Print environment variables",
    "env", "env")

nighthawk.register_command(cmd_ipconfig, "ipconfig",
    "Lists out adapters, system hostname and configured DNS server",
    "Runs an internal ipconfig command",
    "ipconfig", "ipconfig")

nighthawk.register_command(cmd_get_dpapi_system, "get_dpapi_system",
    "Print DPAPI_SYSTEM and boot key if able",
    "Print DPAPI_SYSTEM and boot key if able",
    "get_dpapi_system", "get_dpapi_system")

nighthawk.register_command(cmd_arp, "arp",
    "Lists out the ARP table",
    "Runs an internal ARP command",
    "arp", "arp")

nighthawk.register_command(cmd_listdns, "listdns",
    "Lists DNS cache entries. Note this will query each found hostname for its IP address",
    "Lists DNS cache entries",
    "listdns", "listdns")

nighthawk.register_command(cmd_locale, "locale",
    "Retrieve system locale information, date format, and country",
    "Retrieve system locale information",
    "locale", "locale")

nighthawk.register_command(cmd_notepad, "notepad",
    "Search for open notepad and notepad++ windows and grab text from the editor control object. "
    "Not reliant on clipboard. Not reliant on window being non-minimized",
    "Search for open notepad windows and grab text",
    "notepad", "notepad")

nighthawk.register_command(cmd_netstat, "netstat",
    "List listening and connected IPv4 UDP and TCP connections",
    "Get local IPv4 UDP/TCP listening and connected ports",
    "netstat", "netstat")

nighthawk.register_command(cmd_routeprint, "routeprint",
    "Lists target's IPv4 routes",
    "Prints IPv4 routes on the machine",
    "routeprint", "routeprint")

nighthawk.register_command(cmd_whoami, "whoami",
    "Get whoami /all output without starting cmd.exe",
    "Internal version of whoami /all",
    "whoami", "whoami")

nighthawk.register_command(cmd_driversigs, "driversigs",
    "Enumerate services and check binary signatures for known EDR vendor names",
    "Checks drivers for known EDR vendor names",
    "driversigs", "driversigs")

nighthawk.register_command(cmd_resources, "resources",
    "List available memory and space on the primary disk drive",
    "List available memory and disk space",
    "resources", "resources")

nighthawk.register_command(cmd_uptime, "uptime",
    "Lists system boot time",
    "Lists system boot time",
    "uptime", "uptime")

nighthawk.register_command(cmd_useridletime, "useridletime",
    "Shows the user's idle time",
    "Shows the user's idle time",
    "useridletime", "useridletime")

nighthawk.register_command(cmd_list_firewall_rules, "list_firewall_rules",
    "List all Windows firewall rules",
    "List all Windows firewall rules",
    "list_firewall_rules", "list_firewall_rules")

nighthawk.register_command(cmd_enumLocalSessions, "enumLocalSessions",
    "Enumerate the currently attached user sessions both local and over RDP",
    "Enumerate currently attached user sessions",
    "enumLocalSessions", "enumLocalSessions")

nighthawk.register_command(cmd_adcs_enum_com, "adcs_enum_com",
    "Enumerates the certificate authorities and certificate templates in AD CS "
    "using the ICertConfig, ICertRequest, and IX509CertificateTemplate COM objects",
    "Enumerates CAs and templates using ICertConfig COM object",
    "adcs_enum_com", "adcs_enum_com")

nighthawk.register_command(cmd_adcs_enum_com2, "adcs_enum_com2",
    "Enumerates the certificate authorities and certificate templates in AD CS "
    "using the IX509PolicyServerListManager COM objects",
    "Enumerates CAs and templates using IX509PolicyServerListManager",
    "adcs_enum_com2", "adcs_enum_com2")

nighthawk.register_command(cmd_aadjoininfo, "aadjoininfo",
    "Retrieve Azure AD/Entra ID join information",
    "Retrieve Azure AD/Entra ID join information",
    "aadjoininfo", "aadjoininfo")

nighthawk.register_command(cmd_get_session_info, "get_session_info",
    "Returns the auth package, logon server, and current session id of the user you are operating as",
    "Returns auth package, logon server, and session id",
    "get_session_info", "get_session_info")

# Single-argument commands
nighthawk.register_command(cmd_netview, "netview",
    "Lists local workstations and servers",
    "Lists local workstations and servers",
    "netview <optional netbios domain name>", "netview MYDOMAIN")

nighthawk.register_command(cmd_listmods, "listmods",
    "Lists process modules for the given PID (or current process if omitted)",
    "Lists process modules",
    "listmods <opt: pid>", "listmods 1234")

nighthawk.register_command(cmd_windowlist, "windowlist",
    "List windows visible on the user's desktop. "
    "Optionally specify \"all\" to see every possible window",
    "List visible windows",
    "windowlist [all]", "windowlist all")

nighthawk.register_command(cmd_sc_enum, "sc_enum",
    "Enumerate all service configs in depth",
    "Enumerate all service configs in depth",
    "sc_enum [opt: hostname]", "sc_enum dc01.domain.local")

nighthawk.register_command(cmd_schtasksenum, "schtasksenum",
    "Enumerates all scheduled tasks on the local or target machine",
    "Enumerates all scheduled tasks",
    "schtasksenum <opt: target>", "schtasksenum dc01.domain.local")

nighthawk.register_command(cmd_adcs_enum, "adcs_enum",
    "Enumerates the certificate authorities and certificate templates in AD CS "
    "using undocumented Win32 functions",
    "Enumerates CAs and templates using Win32 functions",
    "adcs_enum (domain)", "adcs_enum domain.local")

nighthawk.register_command(cmd_get_password_policy, "get_password_policy",
    "Gets a server or DC's configured password policy. "
    "If you target a DC this will be domain policies, otherwise local server policy",
    "Gets a server or DC's configured password policy",
    "get_password_policy <hostname>", "get_password_policy dc01.domain.local")

nighthawk.register_command(cmd_netloggedon, "netloggedon",
    "Returns users logged on the local (or a remote) machine. Administrative rights needed",
    "Returns users logged on (admin required)",
    "netloggedon <opt: computername>", "netloggedon \\\\server01")

nighthawk.register_command(cmd_netloggedon2, "netloggedon2",
    "Returns users logged on the local (or a remote) machine via NetWkstaUserEnum. "
    "Output is compatible with bofhound. Administrative rights needed",
    "Returns logged on users via NetWkstaUserEnum (bofhound compatible)",
    "netloggedon2 <opt: computername>", "netloggedon2 server01")

nighthawk.register_command(cmd_netuptime, "netuptime",
    "Returns information about the boot time on the local (or a remote) machine",
    "Returns boot time info on local or remote machine",
    "netuptime <opt: computername>", "netuptime \\\\server01")

nighthawk.register_command(cmd_nettime, "nettime",
    "Displays the current time on a remote host. Returns localhost time if target is null",
    "Returns the current time on a remote or local machine",
    "nettime <opt: target>", "nettime target.domain.local")

nighthawk.register_command(cmd_regsession, "regsession",
    "Returns users logged on the local (or a remote) machine via the registry. "
    "Output is compatible with bofhound. Administrative rights needed",
    "Returns logged on users via registry (bofhound compatible)",
    "regsession <opt: computername>", "regsession server01")

nighthawk.register_command(cmd_enum_filter_driver, "enum_filter_driver",
    "Displays a list of filter drivers installed on the system in CSV format "
    "with the type, name, and altitude number",
    "Lists filter drivers on the system",
    "enum_filter_driver <opt: system>", "enum_filter_driver server01")

nighthawk.register_command(cmd_adv_audit_policies, "adv_audit_policies",
    "Retrieves the advanced security audit policies set in the group policy "
    "of the local system and/or domain",
    "Retrieves advanced security audit policies",
    "adv_audit_policies", "adv_audit_policies")

# Multi-argument commands
nighthawk.register_command(cmd_dir, "dir",
    "Lists a target directory using BOF. Supports /s for recursive listing",
    "Lists a target directory using BOF",
    "dir [directory] [/s]", "dir C:\\Users /s")

nighthawk.register_command(cmd_ldapsearch, "ldapsearch",
    "Perform LDAP search with optional arguments:\n"
    "  --attributes [comma_separated] - attributes to retrieve (default: *)\n"
    "  --count [count] - result max size (default: None)\n"
    "  --scope [1|2|3] - 1=BASE, 2=LEVEL, 3=SUBTREE (default: 3)\n"
    "  --hostname [host] - DC hostname or IP (default: auto)\n"
    "  --dn [dn] - LDAP query base\n"
    "  --ldaps - use LDAPS\n\n"
    "To include ACLs for BofHound, add nTSecurityDescriptor in attributes:\n"
    "  ldapsearch <query> --attributes *,ntsecuritydescriptor\n\n"
    "If paging fails, try nonpagedldapsearch instead",
    "Perform LDAP search",
    "ldapsearch <query> [--attributes val] [--count val] [--scope val] "
    "[--hostname val] [--dn val] [--ldaps]",
    "ldapsearch \"(&(samAccountType=805306368)(servicePrincipalName=*))\" --attributes cn,servicePrincipalName")

nighthawk.register_command(cmd_nonpagedldapsearch, "nonpagedldapsearch",
    "Perform non-paged LDAP search. Same as ldapsearch but without paging support. "
    "Use if ldapsearch fails with a paging error",
    "Perform non-paged LDAP search",
    "nonpagedldapsearch <query> [attributes] [count] [hostname] [domain]",
    "nonpagedldapsearch \"(&(objectClass=user))\" cn,sAMAccountName")

nighthawk.register_command(cmd_nslookup, "nslookup",
    "Perform a DNS query.\n"
    "  <lookup value> - IP or hostname to query\n"
    "  <lookup server> - server to query (omit for system default)\n"
    "  <TYPE> - record type (A, NS, CNAME, SOA, PTR, MX, TEXT, AAAA, SRV, ANY, etc.)\n\n"
    "Note: x86 beacons do not support custom DNS nameservers",
    "Internally perform a DNS query",
    "nslookup <lookup> [server] [type]",
    "nslookup example.com 8.8.8.8 AAAA")

nighthawk.register_command(cmd_netuse_add, "netuse_add",
    "Connect a computer to a shared resource.\n"
    "  sharename - Required. Network name of the shared resource\n"
    "  username - Username for remote connection (\"\" for current context)\n"
    "  password - Password for remote connection (\"\" for default)\n"
    "  /DEVICE:<devname> - Optional. Local device name to bind\n"
    "  /PERSIST - Optional. Persist the connection\n"
    "  /REQUIREPRIVACY - Optional. Require SMBv3 encryption",
    "Connect to a shared resource",
    "netuse_add <share> <user> <password> [/DEVICE:devname] [/PERSIST] [/REQUIREPRIVACY]",
    "netuse_add \\\\\\\\server\\\\IPC$ \"\" \"\"")

nighthawk.register_command(cmd_netuse_list, "netuse_list",
    "Lists bound connections when run without arguments. "
    "Shows specific connection info when a device or remote share name is given",
    "Lists local bound connections",
    "netuse_list [opt: device | share]",
    "netuse_list Y:")

nighthawk.register_command(cmd_netuse_delete, "netuse_delete",
    "Disconnects a computer from a shared resource.\n"
    "  /PERSIST - Delete persistent connections\n"
    "  /FORCE - Force unmap even if resources are open\n\n"
    "Note: if share has a local device name, delete using the local name",
    "Disconnects from a shared resource",
    "netuse_delete <device|share> [/PERSIST] [/FORCE]",
    "netuse_delete F /PERSIST")

nighthawk.register_command(cmd_netuser, "netuser",
    "List user info. If domain is not given, queries the local computer",
    "List user info",
    "netuser <username> <opt: domain>",
    "netuser Administrator domain.local")

nighthawk.register_command(cmd_userenum, "userenum",
    "List user accounts on the current computer. "
    "Filter: all, active, locked, disabled (defaults to all)",
    "List computer user accounts",
    "userenum [all|active|locked|disabled]",
    "userenum active")

nighthawk.register_command(cmd_domainenum, "domainenum",
    "List domain user accounts. "
    "Filter: all, active, locked, disabled (defaults to all)",
    "List user accounts in the current domain",
    "domainenum [all|active|locked|disabled]",
    "domainenum disabled")

nighthawk.register_command(cmd_netshares, "netshares",
    "List shares on local or remote computer",
    "List shares on local or remote computer",
    "netshares <opt: computername>",
    "netshares \\\\\\\\server01")

nighthawk.register_command(cmd_netsharesAdmin, "netsharesAdmin",
    "List shares on local or remote computer and gets more info than standard netshares. "
    "Requires admin",
    "List shares with extended info (requires admin)",
    "netsharesAdmin <opt: computername>",
    "netsharesAdmin \\\\\\\\server01")

nighthawk.register_command(cmd_netGroupList, "netGroupList",
    "List groups in this domain (or specified domain if given)",
    "List groups in this domain",
    "netGroupList <opt: domain>",
    "netGroupList domain.local")

nighthawk.register_command(cmd_netGroupListMembers, "netGroupListMembers",
    "List the members of the specified group in this domain (or specified domain if given)",
    "List members of a domain group",
    "netGroupListMembers <group> <opt: domain>",
    "netGroupListMembers \"Domain Admins\"")

nighthawk.register_command(cmd_netLocalGroupList, "netLocalGroupList",
    "List local groups on this server (or specified server if given)",
    "List local groups on this server",
    "netLocalGroupList <opt: server>",
    "netLocalGroupList server01")

nighthawk.register_command(cmd_netLocalGroupListMembers, "netLocalGroupListMembers",
    "List the members of the specified local group on this server (or specified server if given)",
    "List members of a local group",
    "netLocalGroupListMembers <group> <opt: server>",
    "netLocalGroupListMembers Administrators")

nighthawk.register_command(cmd_netLocalGroupListMembers2, "netLocalGroupListMembers2",
    "List the members of the specified local group. Output is compatible with bofhound. "
    "Use \"\" for group name to query all interesting local groups",
    "List local group members (bofhound compatible)",
    "netLocalGroupListMembers2 <opt: group> <opt: server>",
    "netLocalGroupListMembers2 Administrators server01")

nighthawk.register_command(cmd_schtasksquery, "schtasksquery",
    "Lists the details of the requested scheduled task. "
    "Task name must be given by full path including taskname",
    "Lists details of a scheduled task",
    "schtasksquery <opt: server> <taskname>",
    "schtasksquery \\Microsoft\\Windows\\MUI\\LpRemove")

nighthawk.register_command(cmd_cacls, "cacls",
    "List user permissions for the specified file, wildcards supported.\n"
    "Key:\n"
    "  F: Full access\n"
    "  R: Read & Execute access\n"
    "  C: Read, Write, Execute, Delete\n"
    "  W: Write access",
    "Lists file permissions",
    "cacls <file path>",
    "cacls C:\\windows\\system32\\cmd.exe")

nighthawk.register_command(cmd_sc_query, "sc_query",
    "Queries a service's status. No parameters enumerates all services. "
    "Give just a service name to query that service. "
    "Give \"\" as service name and a remote host to enumerate all remote services",
    "Queries a service's status",
    "sc_query <opt: service_name> <opt: hostname>",
    "sc_query Spooler")

nighthawk.register_command(cmd_sc_qc, "sc_qc",
    "Queries a service's configuration. "
    "Hostname is optional; local system targeted if not given",
    "Queries a service's configuration",
    "sc_qc <service_name> <opt: hostname>",
    "sc_qc Spooler dc01.domain.local")

nighthawk.register_command(cmd_sc_qdescription, "sc_qdescription",
    "Queries a service's description. "
    "Hostname is optional; local system targeted if not given",
    "Queries a service's description",
    "sc_qdescription <service_name> <opt: hostname>",
    "sc_qdescription Spooler")

nighthawk.register_command(cmd_sc_qfailure, "sc_qfailure",
    "List service failure actions. "
    "Hostname is optional; local system targeted if not given",
    "List service failure actions",
    "sc_qfailure <service_name> <opt: hostname>",
    "sc_qfailure Spooler")

nighthawk.register_command(cmd_sc_qtriggerinfo, "sc_qtriggerinfo",
    "Lists service triggers. "
    "Hostname is optional; local system targeted if not given",
    "Lists service triggers",
    "sc_qtriggerinfo <service_name> <opt: hostname>",
    "sc_qtriggerinfo Spooler")

nighthawk.register_command(cmd_reg_query, "reg_query",
    "Queries a registry key or value.\n"
    "Hive: HKLM, HKCU, HKU, HKCR\n"
    "If a value to query is not specified, that key is enumerated",
    "Queries a registry key or value",
    "reg_query <opt: hostname> <hive> <path> <opt: value>",
    "reg_query HKLM SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run")

nighthawk.register_command(cmd_reg_query_recursive, "reg_query_recursive",
    "Recursively queries a registry key.\n"
    "Hive: HKLM, HKCU, HKU, HKCR",
    "Recursively queries a registry key",
    "reg_query_recursive <opt: hostname> <hive> <path>",
    "reg_query_recursive HKLM SOFTWARE\\Microsoft\\Windows\\CurrentVersion")

nighthawk.register_command(cmd_tasklist, "tasklist",
    "Displays a list of currently running processes on either a local or remote machine.\n"
    "You must have a valid login token for remote systems (use make_token)",
    "Lists currently running processes",
    "tasklist <opt: system>",
    "tasklist dc01.domain.local")

nighthawk.register_command(cmd_wmi_query, "wmi_query",
    "Runs a general WMI query on either a local or remote machine and displays "
    "the results in a comma separated table.\n"
    "Namespace defaults to root\\cimv2. Requires valid token for remote systems",
    "Runs a general WMI query",
    "wmi_query <query> <opt: system> <opt: namespace>",
    "wmi_query \"SELECT * FROM Win32_OperatingSystem\"")

nighthawk.register_command(cmd_netsession, "netsession",
    "List sessions on a server",
    "List sessions on server",
    "netsession <computer>",
    "netsession dc01.domain.local")

nighthawk.register_command(cmd_netsession2, "netsession2",
    "List sessions on server. Output is compatible with bofhound.\n"
    "Resolution methods:\n"
    "  1 = DNS (Default)\n"
    "  2 = NetWkstaGetInfo",
    "List sessions on server (bofhound compatible)",
    "netsession2 <opt: computer> <opt: resolution_method> <opt: dns_server>",
    "netsession2 dc01.domain.local 1")

nighthawk.register_command(cmd_findLoadedModule, "findLoadedModule",
    "Finds processes loading a specific DLL. "
    "Searches are done with partial matching. "
    "If a proc name is specified, only matching processes are searched. "
    "Cannot run under WOW64",
    "Finds processes loading a specific DLL",
    "findLoadedModule <dll_name> <opt: proc_name>",
    "findLoadedModule amsi.dll powershell")

nighthawk.register_command(cmd_vssenum, "vssenum",
    "Enumerate volume shadow copy snapshots on a remote machine. "
    "Sharename defaults to C$ if not specified. "
    "Likely only works on Windows Server 2012+ with specific configurations",
    "Enumerate snapshots on a remote machine",
    "vssenum <hostname> <opt: sharename>",
    "vssenum server01 C$")

nighthawk.register_command(cmd_probe, "probe",
    "Check if a TCP port is open on a remote host",
    "Check if a port is open",
    "probe <host> <port>",
    "probe 10.0.0.1 445")

nighthawk.register_command(cmd_sha256, "sha256",
    "Returns the SHA-256 hash of the selected file for integrity checks",
    "Returns the SHA-256 hash of a file",
    "sha256 <filename>",
    "sha256 C:\\windows\\system32\\cmd.exe")

nighthawk.register_command(cmd_md5, "md5",
    "Returns the MD5 hash of the selected file for integrity checks",
    "Returns the MD5 hash of a file",
    "md5 <filename>",
    "md5 C:\\windows\\system32\\cmd.exe")

nighthawk.register_command(cmd_sha1, "sha1",
    "Returns the SHA-1 hash of the selected file for integrity checks",
    "Returns the SHA-1 hash of a file",
    "sha1 <filename>",
    "sha1 C:\\windows\\system32\\cmd.exe")

nighthawk.register_command(cmd_ldapsecuritycheck, "ldapsecuritycheck",
    "Check whether the target DC requires LDAP signing for unencrypted connections "
    "and LDAPS channel binding for encrypted connections. "
    "DC auto-discovered if not provided. "
    "Note: may generate Event ID 2889 on the target DC",
    "Check LDAP signing and LDAPS channel binding requirements",
    "ldapsecuritycheck <opt: dc>",
    "ldapsecuritycheck dc01.domain.local")

nighthawk.register_command(cmd_listpipes, "listpipes",
    "Lists local named pipes",
    "Lists local named pipes",
    "listpipes", "listpipes")
