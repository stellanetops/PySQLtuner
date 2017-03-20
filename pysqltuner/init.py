import os
import re
import subprocess as sbpr

__version__= "0.0.1"

# XXX go back through and replace backticks with run

opt = {
    "silent": 0,
    "nobad": 0,
    "nogood": 0,
    "noinfo": 0,
    "debug": 0,
    "nocolor": 0,
    "forcemem": 0,
    "forceswap": 0,
    "host": 0,
    "socket": 0,
    "port": 0,
    "user": 0,
    "pass": 0,
    "password": 0,
    "skipsize": 0,
    "checkversion": 0,
    "updateversion": 0,
    "buffers": 0,
    "passwordfile": 0,
    "bannedports": "",
    "maxportallowed": 0,
    "outputfile": 0,
    "dbstat": 0,
    "idxstat": 0,
    "sysstat": 0,
    "pfstat": 0,
    "skippassword": 0,
    "noask": 0,
    "template": 0,
    "json": 0,
    "prettyjson": 0,
    "reportfile": 0,
    "verbose": 0,
    "defaults-file": "",
}

# Gather the options from the command line
(
    "nobad",
    "nogood",
    "noinfo",
    "debug",
    "nocolor",
    "forcemem=i",
    "forceswap=i",
    "host=s",
    "socket=s",
    "port=i",
    "user=s",
    "pass=s",
    "skipsize",
    "checkversion",
    "mysqladmin=s",
    "mysqlcmd=s",
    "help",
    "buffers",
    "skippassword",
    "passwordfile=s",
    "outputfile=s",
    "silent",
    "dbstat",
    "json",
    "prettyjson",
    "idxstat",
    "noask",
    "template=s",
    "reportfile=s",
    "cvefile=s",
    "bannedports=s",
    "updateversion",
    "maxportallowed=s",
    "verbose",
    "sysstat",
    "password=s",
    "pfstat",
    "passenv=s",
    "userenv=s",
    "defaults-file=s"
)

# Shown with --help option passed
def usage():
    print(
        f"   MySQLTuner {tunerversion} - MySQL High Performance Tuning Script\n"
        "   Bug reports, feature requests, and downloads at https://github.com/immanuelqrw/PySQLtuner\n"
        "   Maintained by Immanuel Washington (immanuelqrw@gmail.com) - Licensed under GPL\n"
        "\n"
        "   Important Usage Guidelines:\n"
        "      To run the script with the default options, run the script without arguments\n"
        "      Allow MySQL server to run for at least 24-48 hours before trusting suggestions\n"
        "      Some routines may require root level privileges (script will provide warnings)\n"
        "      You must provide the remote server's total memory when connecting to other servers\n"
        "\n"
        "   Connection and Authentication\n"
        "      --host <hostname>    Connect to a remote host to perform tests (default: localhost)\n"
        "      --socket <socket>    Use a different socket for a local connection\n"
        "      --port <port>Port to use for connection (default: 3306)\n"
        "      --user <username>    Username to use for authentication\n"
        "      --userenv <envvar>   Name of env variable which contains username to use for authentication\n"
        "      --pass <password>    Password to use for authentication\n"
        "      --passenv <envvar>   Name of env variable which contains password to use for authentication\n"
        "      --defaults-file <path>  Path to a custom .my.cnf\n"
        "      --mysqladmin <path>  Path to a custom mysqladmin executable\n"
        "      --mysqlcmd <path>    Path to a custom mysql executable\n" . "\n"
        "      --noask      Don't ask password if needed\n" . "\n"
        "   Performance and Reporting Options\n"
        "      --skipsize   Don't enumerate tables and their types/sizes (default: on)\n"
        "   (Recommended for servers with many tables)\n"
        "      --skippassword       Don't perform checks on user passwords(default: off)\n"
        "      --checkversion       Check for updates to MySQLTuner (default: don't check)\n"
        "      --updateversion      Check for updates to MySQLTuner and update when newer version is available (default: don't check)\n"
        "      --forcemem <size>    Amount of RAM installed in megabytes\n"
        "      --forceswap <size>   Amount of swap memory configured in megabytes\n"
        "      --passwordfile <path>Path to a password file list(one password by line)\n"
        "   Output Options:\n"
        "      --silent     Don't output anything on screen\n"
        "      --nogood     Remove OK responses\n"
        "      --nobad      Remove negative/suggestion responses\n"
        "      --noinfo     Remove informational responses\n"
        "      --debug      Print debug information\n"
        "      --dbstat     Print database information\n"
        "      --idxstat    Print index information\n"
        "      --sysstat    Print system information\n"
        "      --pfstat     Print Performance schema information\n"
        "      --bannedportsPorts banned separated by comma(,)\n"
        "      --maxportallowed     Number of ports opened allowed on this hosts\n"
        "      --cvefile    CVE File for vulnerability checks\n"
        "      --nocolor    Don't print output in color\n"
        "      --json       Print result as JSON string\n"
        "      --prettyjson Print result as human readable JSON\n"
        "      --buffers    Print global and per-thread buffer values\n"
        "      --outputfile <path>  Path to a output txt file\n" . "\n"
        "      --reportfile <path>  Path to a report txt file\n" . "\n"
        "      --template   <path>  Path to a template file\n" . "\n"
        "      --verbose    Prints out all options (default: no verbose) \n"
    )

basic_password_files = os.path.join(os.path.abspath(os.path.basedir(__file__)), "basic_passwords.txt") if opt[passwordfile] == 0 else os.path.abspath(os.path.basedir(opt[passwordfile]))

# Username from envvar
if opt[userenv] and os.environ[opt[userenv]]:
    opt[user] = os.environ[opt[userenv]]

# Related to password option
if opt[passenv] and os.environ[opt[passenv]]:
    opt[pass_] = os.environ[opt[passenv]]

if opt[pass_] and (opt[password] != 0):
    opt[pass_] = opt[password]

# for RPM distributions
if not os.path.isfile("basic_password_files"):
    basic_password_files = "/usr/share/mysqltuner/basic_passwords.txt"

# check if we need to enable verbose mode
def check_verbose():
    if opt[verbose"]:
        opt[checkversion] = 1 #Check for updates to MySQLTuner
        opt[dbstat] = 1 #Print database information
        opt[idxstat] = 1 #Print index information
        opt[sysstat] = 1 #Print index information
        opt[buffers] = 1 #Print global and per-thread buffer values
        opt[pfstat] = 1 #Print performance schema info.
        opt[cvefile] = "vulnerabilities.csv" #CVE File for vulnerability checks

# for RPM distributions
if not (opt[cvefile] and os.path.isfile(f"{opt[cvefile]}")):
    opt[cvefile] = "/usr/share/mysqltuner/vulnerabilities.csv"
if not os.path.isfile(f"{opt[cvefile]}"):
    opt[cvefile] = ""
if os.path.isfile("./vulnerabilities.csv"):
    opt[cvefile] = "./vulnerabilities.csv"

if not opt["bannedports"]:
    opt["bannedports"] = ""
banned_ports = opt["bannedports"].split(",")

if not (opt["outputfile"] == 0):
    outputfile = os.path.abspath(opt["outputfile"])

try:
    with open(outputfile, mode="w", encoding="utf-8") as fh:
        pass
except Exception as e:
    print(f"Failed opening {outputfile}")
    raise

if outputfile:
    opt[nocolor] = 1

# Setting up the colors for the print styles
color_pattern = r"s/\n//g"
me = sbpr.check_output(["whoami"], universal_newlines=True)
if re.match(color_pattern, me):
    print("Good")

# Setting up the colors for the print styles
good = r"[\e[0;32mOK\e[0m]" if opt[nocolor] == 0 else "[OK]"
bad = r"[\e[0;31m!!\e[0m]" if opt[nocolor] == 0 else "[!!]"
info = r"[\e[0;34m--\e[0m]" if opt[nocolor] == 0 else "[--]"
deb = r"[\e[0;31mDG\e[0m]" if opt[nocolor] == 0 else "[DG]"
cmd = r"\e[1;32m[CMD]($me)" if opt[nocolor] == 0 else f"[CMD]({me})"
end = r"\e[0m" if opt[nocolor"] == 0 else ""

# Super structure containing all information
result = {"MySQLtuner":
            {"version": tunerversion,
             "options": opt
            }
         }

# Functions that handle the print styles
def prettyprint(line):
    if not (opt["silent"] or opt["json"]):
        print(f"{line}\n")

def goodprint(line):
    if not opt[nogood] == 1:
        prettyprint(" ".join(good, line))

def infoprint(line):
    if not opt[noinfo] == 1:
        prettyprint(" ".join(info, line))

def badprint(line):
    if not opt[nobad] == 1:
        prettyprint(" ".join(bad, line))

def debugprint(line):
    if not opt[debug] == 1:
        prettyprint(" ".join(deb, line))

def redwrap(line):
    new_line = "".join((r"\e[0;31m", line, r"\e[0m"))
    return new_line if opt[nocolor] == 0 else line

def greenwrap(line):
    new_line = "".join((r"\e[0;32m", line, r"\e[0m"))
    return new_line if opt[nocolor] == 0 else line

def cmdprint(line):
    prettyprint("".join((cmd, " ", line, end)))

def infoprintml(*lines):
    info_pattern = r"s/\n//g"
    for line in lines:
        if re.match(info_pattern, line):
            infoprint(f"\t{line}")

def infoprintcmd(*lines):
    for line in lines:
        cmdprint(line)
        #infoprinttml matching again

def subheaderprint(*lines):
    tln = 100
    sln = 8
    ln = len(lines) + 2
    
    prettyprint(" ")

    new_line = "-" * sln + " ".join(lines) + "-" * (tln - ln - sln)
    prettyprint(new_line)

def infoprinthcmd(line, cmd):
    subheaderprint(line)
    infoprintcmd(cmd)

def hr_bytes(num=None):
    """Calculates the parameter passed in bytes
    Then rounds it to one decimal place
    """
    if num is None;
        return "OB"
    
    unit_name = (
        "B",
        "KB",
        "MB",
        "GB",
        "TB",
        "PB",
        "EB",
        "ZB",
        "YB",
    )
    index = int(math.floor(math.log(num, 1024)))
    power = math.pow(1024, index)
    amount = round(num / power, 2)
    unit = unit_name[index]
    return f"{amount} {unit}"

def hr_raw(num=None):
    """Calculates the parameter passed as a string
    Then turns it into a byte value
    """
    if num is None;
        return "O"
    
    units = (
        (0, r"/^(\d+)$/"),
        (1, r"/^(\d+)K$/"),
        (2, r"/^(\d+)M$/"),
        (3, r"/^(\d+)G$/"),
        (4, r"/^(\d+)T$/"),
        (5, r"/^(\d+)P$/"),
        (6, r"/^(\d+)E$/"),
        (7, r"/^(\d+)Z$/"),
        (8, r"/^(\d+)Y$/"),
    )

    for exp, unit in sorted(units, reverse=True):
        if re.match(unit, num):
            return str(math.pow(1024, exp) * num)

    return num

def hr_bytes_rnd(num=None):
    """Calculates the parameter passed in bytes
    Then rounds it to the nearest integer
    """
    if num is None;
        return "OB"
    
    unit_name = (
        "B",
        "K",
        "M",
        "G",
        "T",
        "P",
        "E",
        "Z",
        "Y",
    )
    index = int(math.floor(math.log(num, 1024)))
    power = math.pow(1024, index)
    amount = int(size_bytes / power)
    unit = unit_name[index]

    return f"{amount} {unit}"

def hr_num(num=None)
    """Calculates the parameter passed to the nearest power of 1000
    Then rounds it to the nearest integer
    """
    if num is None;
        return "OB"
    
    unit_name = (
        None,
        "K",
        "M",
        "B",
        "T",
        "Q",
    )
    index = int(math.floor(math.log(num, 1000)))
    power = math.pow(1000, index)
    amount = int(num / power)
    unit = unit_name[index]
    if unit is not None:
        return f"{amount} {unit}"
    else:
        return f"{amount}"

def percentage(value, total=None)
    """Calculates percentage
    """
    if (total is None) or (total == "NULL"):
        return (100, 0)
    percent = round(value * 100 / total, 2)

    return f"{percent}"

def pretty_uptime(uptime):
    """Calculates uptime to display in a more attractive form
    """
    seconds = uptime % 60
    minutes = int((uptime % 3600) / 60)
    hours = int((uptime % 86400) / 3600)
    days = int(uptime / 86400)
    
    if days > 0:
        uptime_string = f"{days}d {hours}h {minutes}m {seconds}s"
    elif hours > 0:
        uptime_string = f"{hours}h {minutes}m {seconds}s"
    elif minutes > 0:
        uptime_string = f"{minutes}m {seconds}s"
    else:
        uptime_string = f"{seconds}s"

    return uptime_string

# Retrieves the memory installed on this machine
def memerror():
    bad_msg = "Unable to determine total memory/swap; use '--forcemem' and '--forceswap'"
    badprint(bad_msg)
    raise MemoryError

def os_setup():
    linux_match = r"/Linux/"
    lin_cyg_match = r"/Linux|CYGWIN/"
    darwin_match = r"/Darwin/"
    sun_match = r"/SunOS/"
    aix_match = r"/AIX/"
    xbsd_match = r"/NetBSD|OpenBSD|FreeBSD/"
    bsd_match = r"/BSD/"
    win_match = r"/windows/i"
    
    os = sbpr.check_output(["uname"], universal_newlines=True)
    duflags = "-b" if re.match(linux_match, os) else ""
    if opt["forcemem"] > 0:
        physical_memory = opt["forcemem"] * 1024 ** 2
        info_msg = f"Assuming {opt['forcemem']} MB of physical memory"
        infoprint(info_msg)
        if opt["forceswap"] > 0:
            swap_memory = opt["forceswap"] * 1024 ** 2
            info_msg = f"Assuming {opt['forceswap']} MB of swap space"
            infoprint(info_msg)
        else:
            swap_memory = 0
            badprint("Assuming 0 MB of swap space (use --forceswap to specify)")
    else:
        if re.match(lin_cyg_match, os):
            physical_memory = sbpr.check_output(["grep", "-i", "memtotal:" "/proc/meminfo", "|", "awk", "'{print \$2}'"], universal_newlines=True)
            # or memerror idk
            physical_memory *= 1024

            swap_memory = sbpr.check_output(["grep", "-i", "swaptotal:" "/proc/meminfo", "|", "awk", "'{print \$2}'"], universal_newlines=True)
            # or memerror idk
            swap_memory *= 1024
        elif re.match(darwin_match, os):
            physical_memory = sbpr.check_output(["sysctl", "-n", "hw.memsize"], universal_newlines=True)
            # or memerror idk
            swap_memory = sbpr.check_output(["sysctl", "-n", "vm.swapusage", "|", "awk", "'{print \$3}'", "|", "sed", "'s/\..*\$//'"], universal_newlines=True)
            # or memerror idk
        elif re.match(xbsd_match, os):
            physical_memory = sbpr.check_output(["sysctl", "-n", "hw.physmem"], universal_newlines=True)
            # or memerror idk
            if physical_memory < 0:
                physical_memory = sbpr.check_output(["sysctl", "-n", "hw.physmem64"], universal_newlines=True)
                # or memerror idk
            swap_memory = sbpr.check_output(["swapctl", "-l", "|", "grep", "'^/'", "|", "awk", "'{ s+= \$2 } END { print s}'"], universal_newlines=True)
            # or memerror idk
        elif re.match(bsd_match, os):
            physical_memory = sbpr.check_output(["sysctl", "-n", "hw.realmem"], universal_newlines=True)
            # or memerror idk
            swap_memory = sbpr.check_output(["swapinfo", "|", "grep", "'^/'", "|", "awk", "'{ s+= \$2 } END { print s}'"], universal_newlines=True)
        elif re.match(sun_match, os):
            physical_memory = sbpr.check_output(["/usr/sbin/prtconf", "|", "grep", "Memory", "|", "cut", "-f", "3", "-d", "' '"], universal_newlines=True)
            # or memerror idk
            physical_memory = physical_memory.rstrip()
            physical_memory *= 1024 ** 2
        elif re.match(aix_match, os):
            physical_memory = sbpr.check_output(["lsattr", "-El", "sys0", "|", "grep", "realmem", "|", "awk", "'{print \$2}'"], universal_newlines=True)
            # or memerror idk
            physical_memory = physical_memory.rstrip()
            physical_memory *= 1024
            swap_memory = sbpr.check_output(["lsps", "-as", "|", "awk", "-F'(MB| +)'", "'/MB /'{print \$2}'"], universal_newlines=True)
            # or memerror idk
            swap_memory = swap_memory.rstrip()
            swap_memory *= 1024 ** 2
        elif re.match(win_match, os):
            physical_memory = sbpr.check_output(["wmic", "ComputerSystem", "get", "TotalPhysicalMemory", "|", "perl", "-ne", "'chomp; print if /[0-9]+/;'"], universal_newlines=True)
            # or memerror idk
            swap_memory = sbpr.check_output(["wmic", "OS", "get", "FreeVirtualMemory", "|", "perl", "-ne", "'chomp; print if /[0-9]+/;'"], universal_newlines=True)
            # or memerror idk


    debugprint(f"Physical Memory: {physical_memory}")
    debugprint(f"Swap Memory: {swap_memory}")
    physical_memory = physical_memory.rstrip()
    swap_memory = swap_memory.rstrip()
    os = os.rstrip()
    result["OS"]["OS Type"] = os
    result["OS"]["Physical Memory"]["bytes"] = physical_memory
    result["OS"]["Physical Memory"]["pretty"] = hr_bytes(physical_memory)
    result["OS"]["Swap Memory"]["bytes"] = swap_memory
    result["OS"]["Swap Memory"]["pretty"] = hr_bytes(swap_memory)
    result["OS"]["Other Processes"]["bytes"] = get_other_process_memory()
    result["OS"]["Other Processes"]["pretty"] = hr_bytes( get_other_process_memory())

def get_http_cli():
    httpcli = which("curl", os.environ["PATH"])
    httpcli = httpcli.rstrip()
    if httpcli:
        return httpcli
    
    httpcli = which("wget", os.environ["PATH"])
    httpcli = httpcli.rstrip()
    if httpcli:
        return httpcli

    return ""

# Checks for updates to MySQLTuner
def validate_tuner_version():
    curl_match = r"/curl$/"
    wget_match = r"/wget$/"
    if opt["checkversion"] == 0 and opt["updateversion"] == 0:
        if not (opt["silent"] or opt["json"]):
            print("\n")
        info_msg = "Skipped version check for MySQLTuner script"
        infoprint(info_msg)
        
        return
    
    url ="https://raw.githubusercontent.com/immanuelqrw/PySQLTuner/master/tuner.py"
    httpcli = get_http_cli()
    
    if re.match(curl_match, httpcli):
        debug_msg = f"{httpcli} is available"
        debugprint(debug_msg)
        debug_msg = f"{httpcli} --connect-timeout 5 -silent '{url}' 2>/dev/null | grep 'tunerversion'| cut -d\\\" -f2"
        debugprint(debug_msg)
        update = sbpr.check_output([debug_msg], universal_newlines=True)
        update = update.rstrip()
        debug_msg = f"VERSION: {update}"
        debugprint(debug_msg)
        
        compare_tuner_version(update)
        return

    if re.match(wget_match, httpcli):
        debug_msg = f"{httpcli} is available"
        debugprint(debug_msg)
        debug_msg = f"{httpcli} -e timestamping=off -t 1 -T 5 -O - '{url}' 2>/dev/null | grep 'tunerversion'| cut -d\\\" -f2"
        debugprint(debug_msg)
        update = sbpr.check_output([debug_msg], universal_newlines=True)
        update = update.rstrip()
        debug_msg = f"VERSION: {update}"
        debugprint(debug_msg)
        
        compare_tuner_version(update)
        return
    
    debugprint("curl and wget are not available.")
    infoprint("Unable to check for the latest MySQLTuner version")
    if opt["pass"]:
        infoprint("Using --pass and --password option is insecure during MySQLTuner execution(Password disclosure)")


# Checks for updates to MySQLTuner
def update_tuner_version():
    if opt["updateversion"] == 0:
        badprint("Skipped version update for MySQLTuner script")
        if not (opt["silent"] or opt["json"]):
            print("\n")
        return
    
    #use Cwd
    url ="https://raw.githubusercontent.com/immanuelqrw/PySQLTuner/master/tuner.py"
    scripts = (
        "tuner.py",
        "basic_passwords.txt",
        "vulnerabilities.csv"
    )
    totalScripts = len(scripts)
    receivedScripts = 0
    httpcli = get_http_cli()
    
    # OMITTED THIS PART BECAUSE IT WON'T BE USED AS WRITTEN
    # IT SIMPLY LOOKS FOR VERSION THEN REPLACES SCRIPT FILES
    # I NEED TO PULL ENTIRE REPO AGAIN
    # CAN DELETE REST OF FUNCTION TO REMAKE XXX
    

def compare_tuner_version(remoteversion):
    debug_msg = f"Remote data: {remoteversion}"
    
    #sys.exit()
    if remoteversion != tunerversion:
        bad_msg = f"There is a new version of PySQLTuner available ({remoteversion})"
        badprint(bad_msg)
        update_tuner_version()
    
    good_msg = f"You have teh latest version of PySQLTuner({tunerversion})"
    goodprint(good_msg)

osname = idk #get os name
if osname == "MSWin32":
    #get windows os
    full_osname =idk
    info_msg = f"* Windows OS({full_osname}) is not fully supported.\n"
    infoprint(info_msg)
    #sys.exit()

def mysql_setup():
    doremote = 0
    remotestring = ""

    if opt["mysqladmin"]:
        mysqladmincmd = opt["mysqladmin"]
    else:
        which("mysqladmin", env_path)

    mysqladmincmd = mysqladmincmd.rstrip()
    if not sbpr.run(mysqladmincmd) and opt["mysqladmin"]:
        bad_msg = f"Unable to find the mysqladmin command you specified: {mysqladmincmd}"
        badprint(bad_msg)
        sys.exit()
    elif not sbpr.run(mysqladmincmd):
        bad_msg = "Couldn't find mysqladmin in your \$PATH. Is MySQL installed?"
        badprint(bad_msg)
        sys.exit()

    if opt["mysql"]:
        mysqlcmd = opt["mysql"]
    else:
        which("mysql", env_path)

    mysqlcmd = mysqlcmd.rstrip()
    if not sbpr.run(mysqlcmd) and opt["mysql"]:
        bad_msg = f"Unable to find the mysql command you specified: {mysqlcmd}"
        badprint(bad_msg)
        sys.exit()
    elif not sbpr.run(mysqlcmd):
        bad_msg = "Couldn't find mysql in your \$PATH. Is MySQL installed?"
        badprint(bad_msg)
        sys.exit()

    mysql_pattern = r"s/\n$//g"
    if re.match(mysql_pattern, mysqlcmd):
        pass #idk
    
    mysqlclidefaults = f"{mysqlcmd} --print-defaults"
    debug_msg = f"MySQL Client: {mysqlclidefaults}"
    debugprint(debug_msg)
    cli_pattern = r"/auto-vertical-output."
    if re.match(cli_pattern, mysqlclidefaults):
        bad_msg = "Avoid auto-vertical-output in configuration file(s) for MySQL like"
        badprint(bad_msg)
        sys.exit()
    
    debug_msg = f"MySQL Client: {mysqlcmd}"
    debugprint(debug_msg)
    
    opt["port"] = 3306 if opt["port"] == 0 else opt["port"]
    
    #Are we being asked to connect via a socket
    if opt["socket"] != 0:
        remotestring = f" -S {opt['socket']} -P {opt['port']}"

    #Are we being asked to connect to a remote server
    if opt["host"] != 0:
        opt["host"] = opt["host"].rstrip()
    
    # If we're doing a remote connection, but forecemem wasn't specified, we need to exit
    if opt["forcemem"] == 0 and opt["host"] not in ("127.0.0.1", "localhost"):
        bad_msg = "The --forcemem option is required for remote connections"
        badprint(bad_msg)
        sys.exit()
    
    info_msg = f"Performing tests on {opt['host']}:{opt['port']}"
    infoprint(info_msg)
    remotestring = f" -h {opt['host']} -P {opt['port']}"
    if opt["host"] not in ("127.0.0.1"m "localhost":
        doremote = 1
    
    # Did we already get a username without password on the command line?
    if (opt["user"] != 0) and (opt["pass"] == 0):
        mysqllogin = f"-u {opt['user']} {remotestring}"
        #idk what 2>&1 means, i think it means inspect output
        loginstatus = f"{mysqladmincmd} ping {mysqllogin}"
        login_pattern = r"/mysqld is alive/"
        if re.match(login_pattern, login_status):
            good_msg = "Logged in using credentials passed on the command line"
            goodprint(good_msg)
            return 1
        else:
            bad_msg = "Attempted to use login credentials, but they were invalid"
            badprint(bad_msg)
            sys.exit()

    # Did we already get a username and password passed on the command line?
    if (opt["user"] != 0) and (opt["pass"] != 0):
        mysqllogin = f"-u {opt['user']} -p{opt['pass']}{remotestring}"
        #idk what 2>&1 means
        loginstatus = f"{mysqladmincmd} ping {mysqllogin}"
        login_pattern = r"/mysqld is alive/"
        if re.match(login_pattern, login_status):
            good_msg = "Logged in using credentials passed on the command line"
            goodprint(good_msg)
            return 1
        else:
            bad_msg = "Attempted to use login credentials, but they were invalid"
            badprint(bad_msg)
            sys.exit()

    #find which OS we are on
    svcprop = which("svcprop", env_path)
    if svcprop[0] = "/":
        # We are on solaris
        # ...

#MySQL Request Array
def select_array(req):
    debugprint(f"PERFORM: {req} ")
    result, err = sbpr.check_output([f"{mysqlcmd} {mysqllogin} -Bse \\w{req} >> /dev/null"])
    if err != 0:
        badprint(f"Failed to execute: {req}")
        badprint(f"FAIL Execute SQL / return code: {err})
        debugprint(f"CMD: {mysqlcmd}")
        debugprint(f"OPTIONS: {mysqllogin}")
        debugprint(f"{mysqlcmd} {mysqllogin} -Bse \\w{req} >> /dev/null")
        
        sys.exit()

    debugprint(f"select_array: return code : {err}"
    result = result.rstrip()
    return result

#MySQL Request one
def select_one(req):
    debugprint(f"PERFORM: {req} ")
    result, err = sbpr.check_output([f"{mysqlcmd} {mysqllogin} -Bse \\w{req} >> /dev/null"])
    if err != 0:
        badprint(f"Failed to execute: {req}")
        badprint(f"FAIL Execute SQL / return code: {err})
        debugprint(f"CMD: {mysqlcmd}")
        debugprint(f"OPTIONS: {mysqllogin}")
        debugprint(f"{mysqlcmd} {mysqllogin} -Bse \\w{req} >> /dev/null")
        
        sys.exit()

    debugprint(f"select_array: return code : {err}"
    result = result.rstrip()
    return result

def get_tuning_info():
    infoconn = select_array("\\s")
    #infoconn idk
    for line in infoconn:
        if re.match(r"/\s*(.*):\s*(.*)/", line):
            debugprint("idk")
            tkey, tval = line.split()
            tkey = tkey.rstrip()
            tval = tval.rstrip()
            result["MySQL Client"][tkey] = tval

    result["MySQL Client"]["Client Path"] = mysqlcmd
    result["MySQL Client"]["Admin Path"] = mysqladmincmd
    result["MySQL Client"]["Authentification Info"] = mysqllogin

def arr2hash(href, harr, sep=None):
    if sep is None:
        sep = "\s"
    for line in harr:
        if re.match(r"m/^\*\*\*\*\*\*\*/", line):
            continue
        hash_pattern = f"/([a-zA-Z_]*)\s*{sep}\s*(.*)/"
        if re.match(hash_pattern, line):
            href[idk] = [idk]
            debugprint(f"V {idk} = {idk}")

def get_all_vars():
    dummyselect = select_one("SELECT VERSION()")
    if not dummyselect:
        bad_msg = "You probably doesn't get enough privileges for running MySQLTuner ..."
        badprint(bad_msg)
        sys.exit()
    dummy_pattern = r"s/(.*?)\-.*/$1/"
    if re.match(dummy_pattern, dummyselect):
        debug_msg = f"VERSION: {dummyselect}"
        debugprint(debug_msg)
    result["MySQL Client"]["Version"] = dummyselect
    
    mysqlvarlist = select_array("SHOW VARIABLES")
    mysqlvarlist.extend(select_array("SHOW GLOBAL VARIABLES"))
    myvar = arr2hash(*mysqlvarlist) #maybe?
    result["Variables"] = myvar
    
    mysqlstatlist = select_array("SHOW STATUS")
    mysqlstatlist.extend(select_array("SHOW GLOBAL STATUS"))
    mystat = arr2hash(*mysqlstatlist) #maybe?
    result["Status"] = mystat
    
    myvar["have_galera"] = "NO"
    if myvar["wsrep_provider_options"]:
        myvar["have_galera"] = "YES"
        debug_msg = f"Galera options: {myvar['wsrep_provider_options'}"
        debugprint(debug_msg)
    
    # Workaround for MySQL bug #59393 wrt. ignore-builtin-innodb
    if myvar["ignore_builtin_innodb"] == "ON":
        myvar["have_innodb"] = "NO"
    
    # Support GTID MODE FOR MARIADB
    # Issue MariaDB GTID mode #272
    if myvar["gtid_strict_mode"]:
        myvar["gtid_mode"] = myvar["gtid_strict_mode"]
    
    myvar["have_threadpool"] = "NO"
    if myvar["thread_pool_size"]:
        myvar["have_threadpool"] = "YES"
    
    # have_* for engines is deprecated and will be removed in MySQL 5.6;
    # check SHOW ENGINES and set corresponding old style variables.
    # Also works around MySQL bug #59393 wrt. skip-innodb
    mysqlenginelist = select_array("SHOW ENGINES")
    engine_match = r"/^([a-zA-Z_]+)\s+(\S+)/"
    for line in mysqlenginelist:
        if re.match(engine_match, line):
            engine = line.lower()

            if engine in ("federated", "blackhole"):
                engine = f"{engine}_engine"
            elif engine == "berkeleydb":
                engine = "bdb"
            
            val = "YES" if idk else "DEFAULT"
            myvar{"have_engine"] = val
            result["Storage Engines"][engine] = idk
    
    debug_msg = ", ".join(mysqlenginelist)
    debugprint(debug_msg)
    mysqlslave = select_array("SHOW SLAVE STATUS")
    myrepl = arr2hash(*mysqlslave) #: ?
    result["Replication"]["Status"] = myrepl
    mysqlslaves = select_array("SHOW SLAVE HOSTS")
    for line in mysqlslaves:
        debug_msg = f"L: {line}"
        debugprint(debug_msg)
        lineitems = line.split(r"/\s+/")
        myslaves[lineitems[0]] = line
        result["Replication"]["Slaves"][lineitems[0]] = lineitems[4]

def remove_cr(array):
    match_1 = r"s/\n$//g"
    match_2 = r"s/^\s+$//g"
    new_array = []
    for line in array:
    if re.match(match_1, line) and re.match(match_2, line):
        new_array.append(line)
    return new_array

def remove_empty(array):
    new_array = [elem for elem in array if elem != ""]
    return new_array

def grep_file_contents(_file):
    pass

def get_file_contents(_file):
    with open(_file, mode="r", encoding="utf-8") as f:
        lines = fh.readlines()
        lines = remove_cr(lines)
    return lines

def get_basic_passwords(_file)
    return get_file_contents(_file)

def log_file_recommendations()
    subheaderprint("Log file Recommendations")
    info_msg = f"Log file: {myvar['log_error']} ({hr_bytes_rnd(stat(myvar['log_error'])[7])})"
    infoprint(info_msg)

    if os.path.isfile(myvar["log_error"]):
        good_msg = f"Log file {myvar['log_error']} exists"
        goodprint(good_msg)
    else:
        bad_msg = f"Log file {myvar['log_error']} doesn't exist"

    try:
        with open(myvar["log_error"], mode="r", encoding="utf-8") as mv:
            good_msg = f"Log file {myvar['log_error']} is readable"
            goodprint(good_msg)
    except IOError as e:
        bad_msg = f"Log file {myvar['log_error']} isn't readable"
        badprint(bad_msg)
        return
    
    if stat(myvar["log_error"])[7] > 0:
        good_msg = f"Log file {myvar['log_error']} isn't empty"
        goodprint(good_msg)
    else:
        bad_msg = f"Log file {myvar['log_error']} is empty"
        badprint(bad_msg)
    
    if stat(myvar["log_error"])[7] < 32 * 1024 * 1024:
        good_msg = f"Log file {myvar['log_error']} is smaller than 32 MB"
        goodprint(good_msg)
    else:
        bad_msg = f"Log file {myvar['log_error']} is bigger than 32 MB"
        badprint(bad_msg)
        generalrec.append(f"{myvar['log_error']} is > 32 MB, you should analyze why or implement a rotation log strategy such as logrotate!")
    
    log_content = get_file_contents(myvar['log_error'])
    numLi = 0
    nbWarnLog = 0
    nbErrLog = 0
    lastShutdowns = []
    lastStarts = []
    
    for logLi in log_content:
        numLi += 1
        log_match_1 = r"/warning|error/i"
        log_match_2 = r"/error/i"
        log_match_3 = r"/warning/i"
        debug_msg = f"{numLi}: {logLi}"
        
        if re.match(log_match_1, logLi):
            debugprint(debug_msg)
        if re.match(log_match_2, logLi):
            nbErrLog += 1
        if re.match(log_match_3, logLi):
            nbWarnLog += 1
        
        log_match_4 = r"/Shutdown complete/"
        log_match_5 = r"/Innodb/i"
        if re.match(log_match_4, logLi) and not re.match(log_match_5, logLi):
            lastShutdowns.append(logLi)
        
        log_match_6 = r"/ready for connections/"
        if re.match(log_match_6, logLi):
            lastStarts.append(logLi)
        
    if nbWarnLog > 0:
        bad_msg = f"{myvar['log_error']} contains {nbWarnLog} warning(s)."
        badprint(bad_msg)
        generalrec.append(f"Control warning line(s) into {myvar['log_error']} file")
    else:
        good_msg = f"{myvar['log_error']} doesn't contain any warning."
    
    if nbErrLog > 0:
        bad_msg = f"{myvar['log_error']} contains {nbErrLog} warning(s)."
        badprint(bad_msg)
        generalrec.append(f"Control error line(s) into {myvar['log_error']} file")
    else:
        good_msg = f"{myvar['log_error']} doesn't contain any error."

    info_msg = f"{len(lastStarts)} start(s) detected in {myvar['log_error']}"
    infoprint(info_msg)
    nStart = 0
    nEnd = 10
    if len(lastStarts) < nEnd:
        nEnd = len(lastStarts)
    
    for startd in lastStarts[::-1]:
        nStart += 1
        info_msg = f"{nStart}) {startd}"
        infoprint(info_msg)
        
    info_msg = f"{len(lastShutdowns)} start(s) detected in {myvar['log_error']}"
    infoprint(info_msg)
    nStart = 0
    nEnd = 10
    if len(lastShutdowns) < nEnd:
        nEnd = len(lastShutdowns)
    
    for shutd in lastShutdowns[::-1]:
        nStart += 1
        info_msg = f"{nStart}) {shutd}"
        infoprint(info_msg)

def cve_recommendations(cvefile):
    subheaderprint("CVE Security Recommendations")
    if opt["cvefile"] and os.path.isfile(opt["cvefile"]):
        info_msg = "Skipped due to --cvefile option undefined"
        infoprint(info_msg)

    #pretty_msg = f"Look for related CVE for {myvar['version']} or lower in {opt[cvefile]}";
    #prettyprint(pretty_msg)
    cvefound = 0
    try:
        with open(cvefile, mode="r", encoding="utf-8") as fh:
            for cveline in fh.readlines():
                cve = cveline.split(";")
                mvl = mysql_version_le(cve[1], cve[2], cve[3])
                debug_msg = f"Comparing {mysqlvermajor}.{mysqlverminor}.{mysqlvermicro} with {cve[1]}.{cve[2]}.{cve[3]} : {mvl}" #idk
                debugprint(debug_msg)
                
                if (int(cve[1]) != mysqlvermajor) or (int(cve[2]) != mysqlverminor):
                    continue
                if int(cve[3]) >= mysqlvermicro:
                    bad_msg = f"{cve[4]}(<= {cve[1]}.{cve[2]}.{cve[3]}) : {cve[6]}"
                    badprint(bad_msg)
                    result["CVE"]["List"][cvefound] = f"{cve[4]}(<= {cve[1]}.{cve[2]}.{cve[3]}) : {cve[6]}"
                    cvefound += 1
    except:
        die_msg = f"Can't open {opt[cvefile]} for read: $!"
        die(die_msg)
    
    result["CVE"]["nb"] = cvefound
    
    cve_warning_notes = ""
    if cvefound == 0:
        goodprint("NO SECURITY CVE FOUND FOR YOUR VERSION")
        return

    if (mysqlvermajor == 5) and (mysqlverminor == 5):
        infoprint("False positive CVE(s) for MySQL and MariaDB 5.5.x can be found.")
        infoprint("Check careful each CVE for those particular versions")
    
    bad_msg = f"{cvefound} CVE(s) found for your MySQL release."
    badprint(bad_msg)
    generalrec.append(f"{cvefound} CVE(s) found for your MySQL release. Consider upgrading your version !"

def get_opened_ports()
    opened_ports = sbpr.check_output(["netstat", "-ltn"], universal_newlines=True)
    op_match_1 = r"s/.*:(\d+)\s.*$/$1/"
    op_match_2 = r"s/\D//g"
    
    opened_ports = [op for op in opened_ports if re.match(op_match_1, op) and re.match(op_match_2, op)]
    
    opened_ports.sort()
    debug_msg = ", ".join(opened_ports)
    debugprint(debug_msg)
    result["Network"]["TCP Opened"] = opened_ports
    return opened_ports

def is_open_port(port):
    if f"{port}" not in get_opened_ports():
        return True
    return False

def get_process_memory(pid):
    mem = sbpr.check_output(["ps", "-p", pid, "-o", "rss"], universal_newlines=True)
    if len(mem) != 2:
        return 0
    return mem[1] * 1024

def get_other_process_memory():
    procs = sbpr.check_output(["ps", "eaxo", "pid,command"], universal_newlines=True)
    
    proc_matches = (
        r"s/.*PID.*//",
        r"s/.*mysqld.*//",
        r"s/.*\[.*\].*//",
        r"s/^\s+$//g",
        r"s/.*PID.*CMD.*//",
        r"s/.*systemd.*//",
        r"s/\s*?(\d+)\s*.*/$1/g"
    )
    
    procs = [proc if all(re.match(proc_match, proc) for proc_match in proc_matches for proc in procs]
    procs = remove_cr(procs)
    procs = remove_empty(procs)
    totalMemOther = 0
    for proc in procs:
        totalMemOther += get_process_memory(proc)
    return totalMemOther

def get_os_release():
    if os.path.isfile("/etc/lsb-release"):
        info_release = get_file_contents("/etc/lsb-release")
        os_relase = info_release[3]
        relase_matches = (
            r"s/.*="//",
            r"s/\"$//"
        )
        if all(re.match(relase_match, os_relase) for relase_match in relase_matches):
            return os_relase
    
    if os.path.isfile("/etc/system-release"):
        info_release = get_file_contents("/etc/system-release")
        return info_release[0]
    
    if os.path.isfile("/etc/os-release"):
        info_release = get_file_contents("/etc/os-release")
        os_relase = info_release[3]
        relase_matches = (
            r"s/.*="//",
            r"s/\"$//"
        )
        if all(re.match(relase_match, os_relase) for relase_match in relase_matches):
            return os_relase
            
    if os.path.isfile("/etc/issue"):
        info_release = get_file_contents("/etc/issue")
        os_relase = info_release[0]
        relase_match = r"s/\s+\\n.*//"
        if re.match(relase_match, os_relase):
            return os_relase

    return "Unknown OS release"

def get_fs_info():
    sinfo = sbpr.check_output(["df", "-P", "|", "grep", "'%'"], universal_newlines=True)
    iinfo = sbpr.check_output(["df", "-Pi", "|", "grep", "'%'"], universal_newlines=True)
    info_match = r"s/.*\s(\d+)%\s+(.*)/$1\t$2/g"
    sinfo = [info for info in sinfo if re.match(sinfo_match, info)]
    for info in sinfo:
        if re.match(r"m{(\d+)\t/(run|dev|sys|proc)($|/)}", info):
            continue
        if re.match(r"/(\d+)\t(.*)/", info):
            if $1 > 85:
                bad_msg = "mount point $2 is using $1 % total space"
                badprint(bad_msg)
                generalrec.append("Add some space to $2 mountpoint.")
            else:
                info_msg = "mount point $2 is using $1 % of total space";
                infoprint(info_msg)
            result["Filesystem"]["Space Pct"][$2] = $1
    
    iinfo =[info for info in iinfo if re.match(sinfo_match, info)]
    for info in iinfo:
        if re.match(r"m{(\d+)\t/(run|dev|sys|proc)($|/)}", info):
            continue
        if re.match(r"/(\d+)\t(.*)/", info):
            if $1 > 85:
                bad_msg = "mount point $2 is using $1 % of max allowed inodes"
                badprint(bad_msg)
                generalrec.append("Cleanup files from $2 mountpoint or reformat you filesystem.")
            else:
                info_msg = "mount point $2 is using $1 % of max allowed inodes";
                infoprint(info_msg)
            result["Filesystem"]["Inode Pct"][$2] = $1

def merge_hash(h1, h2):
    result = {}
    for key, val in zip(h1, h2):
        if key in result:
            continue
        result[key] = val
    return result

def is_virtual_machine()
    isVm = sbpr.check_output(["grep", "-Ec", "'^flags.*\ hypervisor\ '", "/proc/cpuinfo"], universal_newlines=True)
    return 0 if isVm == 0 else 1

def infocmd(cmd):
    debug_msg = f"CMD: {cmd}"
    debugprint(debug_msg)
    result = sbpr.check_output([cmd], universal_newlines=True)
    result = remove_cr(result)
    for line in result:
        info_msg = f"{line}"
        infoprint(info_msg)

def infocmd_tab(cmd):
    debug_msg = f"CMD: {cmd}"
    debugprint(debug_msg)
    result = sbpr.check_output([cmd], universal_newlines=True)
    result = remove_cr(result)
    for line in result:
        info_msg = f"\t{line}"
        infoprint(info_msg)

def infocmd_one(cmd):
    result = sbpr.check_output([cmd], universal_newlines=True)
    result = remove_cr(result)
    return ", ".join(result)

def get_kernel_info():
    params = (
        "fs.aio-max-nr",
        "fs.aio-nr",
        "fs.file-max",
        "sunrpc.tcp_fin_timeout",
        "sunrpc.tcp_max_slot_table_entries",
        "sunrpc.tcp_slot_table_entries",
        "vm.swappiness"
    )

    info_msg = "Information about kernel tuning:"
    infoprint(info_msg)
    
    for param in params:
        infotab_msg = f"sysctl {param} 2>/dev/null"
        infocmd_tab(infotab_msg)
        result["OS"]["Config"][param] = sbpr.check_output(["sysctl", "-n", param, "2>/dev/null"], universal_newlines=True)
    
    if int(sbpr.check_output("sysctl", "-n", "vm.swappiness"], universal_newlines=True)) > 10:
        badprint("Swappiness is > 10, please consider having a value lower than 10")
        generalrec.append("setup swappiness lower or equals to 10")
        adjvars.append("vm.swappiness <= 10 (echo 0 > /proc/sys/vm/swappiness)"
    else:
        infoprint("Swappiness is < 10.")
    
    # only if /proc/sys/sunrpc exists
    tcp_slot_entries = sbpr.check_output(["sysctl", "-n", "sunrpc.tcp_slot_table_entries", "2>/dev/null"], universal_newlines=True)
    if os.path.isfile("/proc/sys/sunrpc") and ((tcp_slot_entries == "") or (tcp_slot_entries < 100)):
        badprint("Initial TCP slot entries is < 1M, please consider having a value greater than 100")
        generalrec.append("setup Initial TCP slot entries greater than 100")
        adjvars.append("sunrpc.tcp_slot_table_entries > 100 (echo 128 > /proc/sys/sunrpc/tcp_slot_table_entries)')
    else:
        infoprint("TCP slot entries is > 100.")
    
    if int(sbpr.check_output("sysctl", "-n", "fs.aio-max-nr"], universal_newlines=True)) < 1000000:
        badprint("Max running total of the number of events is < 1M, please consider having a value greater than 1M")
        generalrec.append("setup Max running number events greater than 1M")
        adjvars.append("fs.aio-max-nr > 1M (echo 1048576 > /proc/sys/fs/aio-max-nr)")
    else:
        infoprint("Max Number of AIO events is > 1M.")

def get_system_info():
    result["OS"]["Release"] = get_os_release()
    infoprint(get_os_release())
    if is_virtual_machine:
        infoprint("Machine type          : Virtual machine")
        result["OS"]["Virtual Machine"] = "YES"
    else:
        infoprint("Machine type          : Physical machine")
        result["OS"]["Virtual Machine"] = "NO"
    
    result["Network"]["Connected"] = "NO"
    isConnected = sbpr.check_output(["ping", "-c", "1", "ipecho.net", "&>/dev/null"], universal_newlines=True)
    if isConnected == 0:
        infoprint("Internet              : Connected")
        result["Network"]["Connected"] = "YES"
    else:
        badprint("Internet              : Disconnected")
    
    result["OS"]["Type"]= sbpr.check_output(["uname", "-o"], universal_newlines=True)
    info_msg = "".join(("Operating System Type : ", infocmd_one("uname -o")))
    infoprint(info_msg)
    
    result["OS"]["Kernel"]= sbpr.check_output(["uname", "-r"], universal_newlines=True)
    info_msg = "".join(("Kernel Release        : ", infocmd_one("uname -r")))
    infoprint(info_msg)
    
    result["OS"]["Hostname"]= sbpr.check_output(["hostname"], universal_newlines=True)
    result["Network"["Internal Ip"]= sbpr.check_output(["hostname", "-I"], universal_newlines=True)
    info_msg = "".join(("Hostname              : ", infocmd_one("hostname")))
    infoprint(info_msg)
    
    infoprint("Network Cards         : ")
    infocmd_tab("ifconfig| grep -A1 mtu")
    info_msg = "".join(("Internal IP           : ", infocmd_one("hostname -I")))
    infoprint(info_msg)
    
    httpcli = get_http_cli()
    if httpcli:
        info_msg = f"HTTP client found: {httpcli}"
        infoprint(info_msg)
    
    ext_ip = ""
    curl_match = r"/curl$/"
    wget_match = r"/wget$/"
    
    if re.match(curl_match, httpcli):
        info_cmd = f"{httpcli} ipecho.net/plain"
        ext_ip = infocmd_one(info_cmd)
    elif re.match(wget_match, httpcli):
        info_cmd = f"{httpcli} -q -O - ipecho.net/plain"
        ext_ip = infocmd_one(info_cmd)
    
    info_msg = f"External IP           : {ext_ip}"
    infoprint(info_msg)
    result["Network"]["External Ip"] = ext_ip
    if not httpcli:
        badprint("External IP           : Can't check because of Internet connectivity")

    info_msg = "".join(("Name Servers          : ", infocmd_one("grep 'nameserver' /etc/resolv.conf \| awk '{print \$2}'")))
    infoprint(info_msg)
    
    infoprint("Logged In users       : ")
    infocmd_tab("who")
    result["OS"]["Logged users"] = "who"

    infoprint("Ram Usages in Mb      : ")
    infocmd_tab("free -m | grep -v +")
    result["OS"]["Free Memory RAM"] = sbpr.check_output(["free", "-m", "|", "grep", "-v", "+"], universal_newlines=True)
    
    infoprint("Load Average          : ")
    infocmd_tab("top -n 1 -b | grep 'load average:'")
    result["OS"]["Load Average"] = sbpr.check_output(["top", "-n", "1", "-b", "|", "grep", "'load average:'"], universal_newlines=True)

#uptime = sbpr.check_output(["uptime", "|", "awk", "'{print $3,$4}'", "|", "cut", "-f1", "-d,"], universal_newlines=True)
#info_msg = #f"System Uptime Days/(HH:MM) : {uptime}"
#infoprint(info_msg)

def system_recommendations():
    if opt[sysstat] == 0:
        return
    subheaderprint("System Linux Recommendations")
    os = sbpr.check_output(["uname"], universal_newlines=True)
    linux_match = r"/Linux/i"
    if not re.match(linux_match, os):
        infoprint("Skipped due to non Linux server")
        return

    #prettyprint("-" * 78)
    get_system_info()
    omem = get_other_process_memory()
    info_msg = f"User process except mysqld used {hr_bytes_rnd(omem)} RAM."
    infoprint(info_msg)
    if 0.15 * physical_memory < omem:
        bad_msg = "".join((
                "Other user process except mysqld used more than 15% of total physical memory "
                f"{percentage(omem, physical_memory)}% (",
                f"{hr_bytes_rnd(omem)} / {hr_bytes_rnd(physical_memory)})"
                ))
        badprint(bad_msg)
        generalrec.append("Consider stopping or dedicate server for additional process other than mysqld.")
        adjvars.append("DON'T APPLY SETTINGS BECAUSE THERE ARE TOO MANY PROCESSES RUNNING ON THIS SERVER. OOM KILL CAN OCCUR!")
    else:
        info_msg = "".join((
                "Other user process except mysqld used less than 15% of total physical memory "
                f"{percentage(omem, physical_memory)}% (",
                f"{hr_bytes_rnd(omem)} / {hr_bytes_rnd(physical_memory)})"
                ))
        infoprint(info_msg)
    
    if opt["maxportallowed"] > 0:
        opened_ports = get_opened_ports()
        info_msg = f"There is {len(opened_ports)} listening port(s) on this server"
        infoprint(info_msg)
        
        if len(opened_ports) > opt["maxportallowed"]:
            bad_msg = f"There is too many listening ports: {len(opened_ports)} opened > {opt['maxportallowed']} allowed"
            badprint(bad_msg)
            generalrec.append("Consider dedicating a server for your database installation with less services running on !")
        else:
            good_msg = f"There is less than {opt['maxportallowed']} opened port on this server"
            goodprint(good_msg)
    
    for banport in banned_ports:
        if is_open_port(banport):
            bad_msg = f"Banned port: {banport} is opened.."
            badprint(bad_msg)
            generalrec.append(f"Port {banport} is opened. Consider stopping program handling this port.")
        else:
            good_msg = f"{banport} is not opened"
            goodprint(good_msg)
    
    get_fs_info()
    get_kernal_info()

def security_recommendations():
    subheaderprint("Security Recommendations")
    if opt["skippassword"] == 1:
        infoprint("Skipped due to --skippassword option")
        return
    
    PASS_COLUMN_NAME = "password"
    version_match = r"/5.7/"
    if re.match(version_match, myvar["version"])
        PASS_COLUMN_NAME = "authentication_string"
    
    debeug_msg = f"Password column = {PASS_COLUMN_NAME}"
    
    # Looking for Anonymous users
    mysqlstatlist = select_array("SELECT CONCAT(user, '\@', host) FROM mysql.user WHERE TRIM(USER) = '' OR USER IS NULL")
    debugprint("".join(mysqlstatlist))
    
    #sys.exit()
    if mysqlstatlist:
        for line in sorted(mysqlstatlist):
            line = line.rstrip()
            bad_msg = f"User '{line}' is an anonymous account."
            badprint(bad_msg)
        generalrec.append(f"Remove Anonymous User accounts - there are {len(mysqlstatlist)} anonymous accounts.")
    else:
        goodprint(goodprint "There are no anonymous accounts for any database users")
    
    if mysql_version_le(5, 1):
        badprint("No more password checks for MySQL version <=5.1")
        badprint("MySQL version <=5.1 are deprecated and end of support.")
    
    # Looking for Empty Password
    if mysql_version_ge(5, 5):
        mysqlstatlist = select_array(f"SELECT CONCAT(user, '\@', host) FROM mysql.user WHERE ({PASS_COLUMN_NAME} = '' OR {PASS_COLUMN_NAME} IS NULL) AND plugin NOT IN ('unix_socket', 'win_socket')")
    else:
        mysqlstatlist = select_array(f"SELECT CONCAT(user, '\@', host) FROM mysql.user WHERE ({PASS_COLUMN_NAME} = '' OR {PASS_COLUMN_NAME} IS NULL)")
    
    if mysqlstatlist:
        for line in sorted(mysqlstatlist):
            line = line.rstrip()
            bad_msg = f"User '{line}' has no password set."
            badprint(bad_msg)
        generalrec.append("Set up a Password for user with the following SQL statement ( SET PASSWORD FOR 'user'\@'SpecificDNSorIp' = PASSWORD('secure_password'); )")
    else:
        goodprint("All database users have passwords assigned")

    if mysql_version_ge(5, 7):
        valPlugin = select_one("select count(*) from information_schema.plugins where PLUGIN_NAME='validate_password' AND PLUGIN_STATUS='ACTIVE'")
        
        if valPlugin >= 1:
            infoprint("Bug #80860 MySQL 5.7: Avoid testing password when validate_password is activated")
            return
    
    # Looking for User with user/ uppercase /capitalise user as password
    mysqlstatlist = select_array(f"SELECT CONCAT(user, '\@', host) FROM mysql.user WHERE CAST({PASS_COLUMN_NAME} as Binary) = PASSWORD(user) OR CAST({PASS_COLUMN_NAME} as Binary) = PASSWORD(UPPER(user)) OR CAST({PASS_COLUMN_NAME} as Binary) = PASSWORD(CONCAT(UPPER(LEFT(User, 1)), SUBSTRING(User, 2, LENGTH(User))))")
    if mysqlstatlist:
        for line in sorted(mysqlstatlist):
            line = line.rstrip()
            bad_msg = "User '{line}' has user name as password."
            badprint(bad_msg)
        generalrec.append("Set up a Secure Password for user\@host ( SET PASSWORD FOR 'user'\@'SpecificDNSorIp' = PASSWORD('secure_password'); )")
    
    mysqlstatlist = select_array("SELECT CONCAT(user, '\@', host) FROM mysql.user WHERE HOST='%'")
    if mysqlstatlist:
        for line in sorted(mysqlstatlist):
            line = line.rstrip()
            bad_msg = "User '{line}' hasn't specific host restriction."
        generalrec.append("Restrict Host for user\@% to user\@SpecificDNSorIp")
    
    if not os.path.isfile(basic_password_files):
        badprint("There is no basic password file list!")
        return

    passwords = get_basic_passwords(basic_password_Files)
    info_msg = f"There are {len(passwords)} basic passwords in the list."
    infoprint(info_msg)
    
    nbins = 0
    
    if passwords:
        nbInterPass = 0
        pass_matches = (
            r"s/\s//g",
            r"s/\'/\\\'/g"
        )
        for pass_ in passwords:
            nbInterPass += 1
            if all(re.match(pass_match, pass_) for pass_match in pass_matches):
                pass_ = pass_.rstrip()
                
                array_query = f"SELECT CONCAT(user, '\@', host) FROM mysql.user WHERE {PASS_COLUMN_NAME} = PASSWORD('{pass_}') OR {PASS_COLUMN_NAME} = PASSWORD(UPPER('{pass_}')) OR {PASS_COLUMN_NAME} = PASSWORD(CONCAT(UPPER(LEFT('{pass_}', 1)), SUBSTRING('{pass_}', 2, LENGTH('{pass_}'))))"
                mysqlstatlist = select_array(array_query)
                debug_msg = f"There is {len(mysqlstatlist)} items."
                debugprint(debug_msg)
                
                if mysqlstatlist:
                    for line in mysqlstatlist:
                        line = line.rstrip()
                        bad_msg = f"User '{line}' is using weak password: {pass_} in a lower, upper or capitalize derivative version."
                        badprint(bad_msg)
                        nbins += 1
                
                if nbInterpass % 1000 == 0:
                    debug_msg = f"{nbInterPass} / {len(passwords)}"
                    debugprint(debug_msg)
    
    if nbins > 0:
        generalrec.append(f"{nbins} user(s) used basic or weak password.")

def get_replication_status():
    subheaderprint("Replication Metrics")
    info_msg = f"Galera Synchronous replication: {myvar['have_galera']}"
    infoprint(info_msg)
    
    if len(myslaves.keys()): == 0:
        infoprint("No replication slave(s) for this server.")
    else:
        info_msg = f"This server is acting as master for {len(myslaves)} server(s)."
        infoprint(info_msg)
    
    if (len(myrepl.keys()) == 0) and (len(myslaves,keys()) == 0):
        infoprint("This is a standalone server.")
        return
    if len(myrepl.keys()) == 0:
        infoprint("No replication setup for this server.")
        return
    
    result["Replication"]["status"] = myrepl
    
    io_running = myrepl["Slave_IO_Running"]
    debug_msg = f"IO RUNNING: {io_running}"
    debugprint(debug_msg)
    
    sql_running = myrepl["Slave_SQL_Running"]
    debug_msg = f"SQL RUNNING: {sql_running}"
    debugprint(debug_msg)
    
    seconds_behind_master = myrepl["Seconds_Behind_Master"]
    debug_msg = f"SECONDS: {seconds_behind_master}"
    debugprint(debug_msg)
    
    run_match = r"/yes/i"
    if io_running and ((not re.match(run_match, io_running)) or (not re.match(run_match, sql_running))):
        badprint("This replication slave is not running but seems to be configured.")

    if io_running and re.match(run_match, io_running) and re.match(run_match, sql_running):
        if myvar["read_only"] == "OFF":
            badprint("This replication slave is running with the read_only option disabled.")
        else:
            goodprint("This replication slave is running with the read_only option enabled.")
        
        if seconds_behind_master > 0:
            bad_msg = f"This replication slave is lagging and slave has {seconds_behind_master} second(s) behind master host."
            badprint(bad_msg)
        else:
            goodprint("This replication slave is up to date with master.")
            
def validate_mysql_version():
    version_match = r"This replication slave is up to date with master."
    mysqlvermajor, mysqlverminor, mysqlvermicro = re.split(version_match, myvar["version"])
    mysqlverminor = mysqlverminor if mysqlverminor else 0
    mysqlvermicro = mysqlvermicro if mysqlvermicro else 0
    
    if not mysql_version_ge(5, 1):
        bad_msg = f"Your MySQL version {myvar['version']} is EOL software!  Upgrade soon!"
        badprint(bad_msg)
    elif (mysql_version_ge(6) and mysql_version_le(9)) or (mysql_version_ge(12)):
        bad_msg = f"Currently running unsupported MySQL version {myvar['version']}"
        badprint(bad_msg)
    else:
        good_msg = f"Currently running supported MySQL version {myvar['version']}"
        goodprint(good_msg)

# Checks if MySQL version is greater than equal to (major, minor, micro)
def mysql_version_ge(maj, min_=0, mic=0):
    is_greater = (
                    (int(mysqlvermajor) > int(maj)) or
                    ((int(mysqlvermajor) == int(maj)) and (int(mysqlverminor) > int(min_))) or
                    ((int(mysqlverminor) == int(min_)) and (int(mysqlvermicro) >= int(mic)))
    )
    return is_greater

# Checks if MySQL version is lower than equal to (major, minor, micro)
# Checks if MySQL version is greater than equal to (major, minor, micro)
def mysql_version_le(maj, min_=0, mic=0):
    is_lesser = (
        (int(mysqlvermajor) < int(maj)) or
        ((int(mysqlvermajor) == int(maj)) and (int(mysqlverminor) < int(min_))) or
        ((int(mysqlverminor) == int(min_)) and (int(mysqlvermicro) <= int(mic)))
    )
    return is_lesser
    

# Checks if MySQL micro version is lower than equal to (major, minor, micro)
def mysql_micro_version_le(maj, min_, mic):
    is_lesser = (
        (mysqlvermajor == maj) and
        (mysqlverminor == min_) and
        (mysqlvermicro <= mic)
    )
    return is_lesser

# Checks for 32-bit boxes with more than 2GB of RAM
def check_architecture():
    if doremote == 1:
        return
    sun_match = r"/SunOS/"
    aix_match = r"/AIX/"
    bsd_match = r"/NetBSD|OpenBSD/"
    fbsd_match = r"/FreeBSD/"
    dar_match = r"/Darwin/"
    mac_match = r"/Power Macintosh/"
    win_match = r"/x86_64/"

    bit64_match = r"/64/"
    
    OS = sbpr.check_output(["uname"], universal_newlines=True)

    sun_bit = sbpr.check_output(["isainfo", "-b"], universal_newlines=True)
    aix_bit = sbpr.check_output(["bootinfo", "-K"], universal_newlines=True)
    bsd_bit = sbpr.check_output(["sysctl", "-b", "hw.machine"], universal_newlines=True)
    fbsd_bit = sbpr.check_output(["sysctl", "-b", "hw.machine_arch"], universal_newlines=True)
    bit = sbpr.check_output(["uname", "-m"], universal_newlines=True)
    
    
    if re.match(sun_match, OS) and re.match(bit64_match, sun_bit):
        arch = 64
        goodprint("Operating on 64-bit architecture")
    elif not re.match(sun_match, OS) and re.match(bit64_match, bit):
        arch = 64
        goodprint("Operating on 64-bit architecture")
    elif re.match(aix_match, OS) and re.match(bit64_match, aix_bit):
        arch = 64
        goodprint("Operating on 64-bit architecture")
    elif re.match(bsd_match, OS) and re.match(bit64_match, bsd_bit):
        arch = 64
        goodprint("Operating on 64-bit architecture")
    elif re.match(fbsd_match, OS) and re.match(bit64_match, fbsd_bit):
        arch = 64
        goodprint("Operating on 64-bit architecture")
    elif re.match(dar_match, OS) and re.match(mac_match, bit):
        # Darwin box.local 9.8.0 Darwin Kernel Version 9.8.0: Wed Jul 15 16:57:01 PDT 2009; root:xnu1228.15.4~1/RELEASE_PPC Power Macintosh
        arch = 64
        goodprint("Operating on 64-bit architecture")
    elif re.match(dar_match, OS) and re.match(win_match, bit):
        # Darwin gibas.local 12.3.0 Darwin Kernel Version 12.3.0: Sun Jan 6 22:37:10 PST 2013; root:xnu-2050.22.13~1/RELEASE_X86_64 x86_64
        arch = 64
        goodprint("Operating on 64-bit architecture")
    else:
        arch = 32
        if physical_memory > 2147483648:
            badprint("Switch to 64-bit OS - MySQL cannot currently use all of your RAM")
        else:
            goodprint("Operating on 32-bit architecture with less than 2GB RAM")

    result["OS"]["Architecture"] = f"{arch} bits"

tblist = []
# Start up a ton of storage engine counts/statistics
def check_storage_engines():
    if opt[skipsize] == 1:
        subheaderprint("Storage Engine Statistics")
        infoprint("Skipped due to --skipsize option")
        return

    subheaderprint("Storage Engine Statistics")
    
    engine_match = r"/([a-zA-Z_]*)\s+([a-zA-Z]+)/"
    if mysql_version_ge(5, 5):
        engineresults = select_array("SELECT ENGINE,SUPPORT FROM information_schema.ENGINES ORDER BY ENGINE ASC")
        for line in engineresults:
            engine, engineenabled = re.split(engine_match, line)
            result["Engine"][engine]["Enabled"] = engineenabled
            if engineenabled in ("YES", "DEFAULT"):
                engines += f"{greenwrap('+')}{engine} "
            else:
                engines += f"{redwrap('-')}{engine} "
    elif mysql_version_ge(5, 1, 5):
        engineresults = select_array("SELECT ENGINE,SUPPORT FROM information_schema.ENGINES WHERE ENGINE NOT IN ('performance_schema','MyISAM','MERGE','MEMORY') ORDER BY ENGINE ASC")
        for line in engineresults:
            engine, engineenabled = re.split(engine_match, line)
            result["Engine"][engine]["Enabled"] = engineenabled
            if engineenabled in ("YES", "DEFAULT"):
                engines += f"{greenwrap('+')}{engine} "
            else:
                engines += f"{redwrap('-')}{engine} "
    else:
        if myvar["have_archive"] and (myvar["have_archive"] == "YES"):
            engines += f"{greenwrap('+Archive')"
        else:
            engines += f"{redwrap('-Archive')"
        
        if myvar["have_bdb"] and (myvar["have_bdb"] == "YES"):
            engines += f"{greenwrap('+BDB')"
        else:
            engines += f"{redwrap('-BDB')"
        
        if myvar["have_federated_engine"] and (myvar["have_federated_engine"] == "YES"):
            engines += f"{greenwrap('+Federated')"
        else:
            engines += f"{redwrap('-Federated')"
        
        if myvar["have_innodb"] and (myvar["have_innodb"] == "YES"):
            engines += f"{greenwrap('+InnoDB')"
        else:
            engines += f"{redwrap('-InnoDB')"
        
        if myvar["have_isam"] and (myvar["have_isam"] == "YES"):
            engines += f"{greenwrap('+ISAM')"
        else:
            engines += f"{redwrap('-ISAM')"
        
        if myvar["have_ndbcluster"] and (myvar["have_ndbcluster"] == "YES"):
            engines += f"{greenwrap('+NDBCluster')"
        else:
            engines += f"{redwrap('-NDBCluster')"
    
    dblist = [db for db in select_array("SHOW DATABASES") if db != "lost+found"
    
    result["Databases"]["List"] = [dblist]
    info_msg = f"Status {engines}"
    infoprint(info_msg)
    
    size_match = r"/([a-zA-Z_]+)\s+(\d+)\s+(\d+)\s+(\d+)\s+(\d+)/"
    if mysql_version_ge(5, 1, 5):
        # MySQL 5 servers can have table sizes calculated quickly from information schema
        templist = select_array("SELECT ENGINE,SUM(DATA_LENGTH+INDEX_LENGTH),COUNT(ENGINE),SUM(DATA_LENGTH),SUM(INDEX_LENGTH) FROM information_schema.TABLES WHERE TABLE_SCHEMA NOT IN ('information_schema', 'performance_schema', 'mysql') AND ENGINE IS NOT NULL GROUP BY ENGINE ORDER BY ENGINE ASC;")
        
        for line in templist:
            engine, size, count, dsize, isize = re.split(size_match, line)
            debug_msg = f"Engine Found: {engine}"
            debugprint(debug_msg)
        
            if not engine:
                continue
            
            if not size:
                size = 0
            if not isize:
                isize = 0
            if not dsize:
                dsize = 0
            if not count:
                count = 0
            
            enginestats[engine] = size
            enginecount[engine] = count
            result["Engine"][engine]["Table Number"] = count
            result["Engine"][engine]["Total Size"] = size
            result["Engine"][engine]["Data Size"] = dsize
            result["Engine"][engine]["Index Size"] = isize
        
        not_innodb = ""
        if not result["Variables"]["innodb_file_per_table"]:
            not_innodb = "AND NOT ENGINE='InnoDB'
        elif result["Variables"]["innodb_file_per_table"] == "OFF":
            not_innodb = "AND NOT ENGINE='InnoDB'
        
        result["Tables"]["Fragmented tables"] = [
            select_array(f"SELECT CONCAT(CONCAT(TABLE_SCHEMA, '.'), TABLE_NAME),DATA_FREE FROM information_schema.TABLES WHERE TABLE_SCHEMA NOT IN ('information_schema','performance_schema', 'mysql') AND DATA_LENGTH/1024/1024>100 AND DATA_FREE*100/(DATA_LENGTH+INDEX_LENGTH+DATA_FREE) > 10 AND NOT ENGINE='MEMORY' {not_innodb}")
        ]
        
        fragtables = len(list(result["Tables"]["Fragmented tables"]))

    else:
        # MySQL < 5 servers take a lot of work to get table sizes
        # Now we build a database list, and loop through it to get storage engine stats for tables
        for db in dblist:
            db = db.rstrip()
            if db in (
                "information_schema",
                "performance_schema",
                "mysql"
                "lost+found"
            ):
                continue
            
            ixs = (1, 6, 9)
            
            if not mysql_version_ge(4, 1):
                # MySQL 3.23/4.0 keeps Data_Length in the 5th (0-based) column
                ixs = (1, 5, 8)
            table_status = select_array(f"SHOW TABLE STATUS FROM `{db}`")
            for ix in ixs:
                tblist.append(table_status[ix])
    
        # Parse through the table list to generate storage engine counts/statistics
        fragtables = 0
        for tbl in tblist
            debug_msg = f"Data dump {', '.join(tbl)}"
            debugprint(debug_msg)
            engine, size, datafree = tbl
            
            if engine == "NULL"
                continue
            
            if size == "NULL":
                size = 0
            
            if datafree = "NULL":
                datafree = 0
            
            if enginestats[engine]:
                enginestats[engine] += size
                enginecount[engine] += 1
            else:
                enginestats[engine] = size
                enginestats[engine] = 1
            
            if datafree > 0:
                fragtables += 1
    
    for engine, size in enginestats:
        info_msg = f"Data in $engine tables: {hr_bytes_rnd(size)} (Tables: {enginecount[engine]})"
        infoprint(info_msg)
    
    # If the storage engine isn't being used, recommend it to be disabled
    if not enginestats["InnoDB"] and myvar["have_innodb"] and (myvar["have_innodb"] =="YES"):
        badprint("InnoDB is enabled but isn't being used")
        generalrec.append("Add skip-innodb to MySQL configuration to disable InnoDB")
    
    if not enginestats["BerkeleyDB"] and myvar["have_bdb"] and (myvar["have_bdb"] =="YES"):
        badprint("BDB is enabled but isn't being used")
        generalrec.append("Add skip-bdb to MySQL configuration to disable BDB")
    
    if not enginestats["ISAM"] and myvar["have_isam"] and (myvar["have_isam"] =="YES"):
        badprint("MyISAM is enabled but isn't being used")
        generalrec.append("Add skip-isam to MySQL configuration to disable ISAM (MySQL > 4.1.0)")
    
    table_match = r"/\s+/"
    # Fragmented tables
    if fragtables > 0:
        bad_msg = f"Total fragmented tables: {fragtables}"
        badprint(bad_msg)
        generalrec.append("Run OPTIMIZE TABLE to defragment tables for better performance")
        total_free = 0
        
        for table_line in result["Tables"]["Fragmented tables"]:
            table_name, data_free = re.split(table_match, table_line)
            if not data_free:
                data_free = data_free / 1024 / 1024
            total_free += data_free
            generalrec.append(f"  OPTIMIZE TABLE {table_name}; -- can free {data_free} MB")
        generalrec.append(f"Total freed space after theses OPTIMIZE TABLE : {total_free} Mb")
    else:
        good_msg = f"Total fragmented tables: {fragtables}"
        goodprint(good_msg)
        
    # Auto increments
    # Find the maximum integer
    maxint = select_one("SELECT ~0")
    result["MaxInt"] = maxint
    
    # Now we use a database list, and loop through it to get storage engine stats for tables
    
    for db in dblist:
        db = db.rstrip()
        
        if not tblist[db]:
            tblist[db] = []
        
        if db == "information_schema":
            continue
        
        ia = (0, 10)
        if not mysql_version_ge(4, 1):
            # MySQL 3.23/4.0 keeps Data_Length in the 5th (0-based) column
            ia = (0, 9)
        
        table_status = select_array(f"SHOW TABLE STATUS FROM `{db}`")
            for i in ia:
                tblist.append(table_status[i])
    
    auto_match = r"/^\d+?$/"
    dbnames = tblist.keys()
    for db in dbnames:
        for tbl in tblist[db]:
            name, autoincrement = tbl
            if re.match(auto_match, autoincrement):
                percent = percentage(autoincrement, maxint)
                result["PctAutoIncrement"][f"{db.name}"] = percent
                if percent >= 75:
                    bad_msg = f"Table '{db.name}' has an autoincrement value near max capacity ({percent}%)"
                    badprint(bad_msg)

def calculations():
    mycalc = {}
    if mystat["Questions"] < 1:
        badprint("Your server has not answered any queries - cannot continue...")
        sys.exit()
    
    # Per-thread memory
    if mysql_version_ge(4):
        mycalc["per_thread_buffers"] = \
            myvar["read_buffer_size"] +\
            myvar["read_rnd_buffer_size"] +\
            myvar["sort_buffer_size"] +\
            myvar["thread_stack"] +\
            myvar["join_buffer_size"]
    else:
        mycalc["per_thread_buffers"] = \
            myvar["record_buffer_size"] +\
            myvar["record_rnd_buffer"] +\
            myvar["sort_buffer_size"] +\
            myvar["thread_stack"] +\
            myvar["join_buffer_size"]
    
    mycalc["total_per_thread_buffers"] = mycalc["per_thread_buffers"] * myvar["max_connections"]
    mycalc["max_total_per_thread_buffers"] = mycalc["per_thread_buffers"] * myvar["Max_used_connections"]
    
    # Server-wide memory
    mycalc["max_tmp_table_size"] = max(myvar["tmp_table_size"], myvar["max_heap_table_size"])
    mycalc["server_buffers"] = myvar["key_buffer_size"] + mycalc["max_tmp_table_size"]
    
    if myvar["innodb_buffer_pool_size"]:
        mycalc["server_buffers"] = myvar["innodb_buffer_pool_size"]
    else:
        mycalc["server_buffers"] = 0
    
    if myvar["innodb_additional_mem_pool_size"]:
        mycalc["server_buffers"] = myvar["innodb_additional_mem_pool_size"]
    else:
        mycalc["server_buffers"] = 0
    
    if myvar["innodb_log_buffer_size"]:
        mycalc["server_buffers"] = myvar["innodb_log_buffer_size"]
    else:
        mycalc["server_buffers"] = 0
        
    if myvar["query_cache_size"]:
        mycalc["server_buffers"] = myvar["query_cache_size"]
    else:
        mycalc["server_buffers"] = 0
        
    if myvar["aria_pagecache_buffer_size"]:
        mycalc["server_buffers"] = myvar["aria_pagecache_buffer_size"]
    else:
        mycalc["server_buffers"] = 0
    
    # Global memory
    # Max used memory is memory used by MySQL based on Max_used_connections
    # This is the max memory used theorically calculated with the max concurrent connection number reached by mysql
    mycalc["max_used_memory"] = \
        mycalc["server_buffers"] +\
        mycalc["max_total_per_thread_buffers"] +\
        get_pf_memory() +\
        get_gcache_memory()
    
    mycalc["pct_max_used_memory"] = percentage(mycalc["max_used_memory"], physical_memory)
    
    # Total possible memory is memory needed by MySQL based on max_connections
    # This is the max memory MySQL can theorically used if all connections allowed has opened by mysql
    mycalc["max_peak_memory"] = \
        mycalc["server_buffers"] +\
        mycalc["total_per_thread_buffers"] +\
        get_pf_memory() +\
        get_gcache_memory()
    
    mycalc["pct_max_physical_memory"] = percentage(mycalc["max_peak_memory"], physical_memory)
    
    debug_msg = f"Max Used Memory: {hr_bytes(mycalc['max_used_memory']})"
    debugprint(debug_msg)
    debug_msg = f"Max Used Percentage RAM: {mycalc['pct_max_used_memory']}%"
    debugprint(debug_msg)
    
    debug_msg = f"Max Peal Memory: {hr_bytes(mycalc['max_peak_memory']})"
    debugprint(debug_msg)
    debug_msg = f"Max Peak Percentage RAM: {mycalc['pct_max_physical_memory']}%"
    debugprint(debug_msg)
    
    # Slow queries
    mycalc["pct_slow_queries"] = int(mystat["Slow_queries"] / mystat["Questions"] * 100)
    
    # Connections
    mycalc["pct_connections_used"] = int(mystat["Max_used_connections"] / myvar["max_connections"] * 100)
    if mycalc["pct_connections_used"] > 100:
        mycalc["pct_connections_used"] = 100
    
    # Aborted Connections
    mycalc["pct_connections_aborted"] = percentage(mystat["Aborted_connects"], mystat["Connections"])
    debug_msg = f"Aborted_connects: {mystat['Aborted_connects']}"
    debugprint(debug_msg)
    debug_msg = f"Connections: {mystat['Connections']}"
    debugprint(debug_msg)
    debug_msg = f"pct_connections_aborted: {mycalc['pct_connections_aborted']}"
    debugprint(debug_msg)

    # Key buffers
    if mysql_version_ge(4, 1) and myvar["key_buffer_size"] > 0:
        pkbu = (1 - (mystat["Key_blocks_unused"] * myvar["key_cache_block_size"]) / myvar["key_buffer_size"]) * 100
        mycalc["pct_key_buffer_used"] = f"{round(pkbu, 1)}"
    else:
        mycalc["pct_key_buffer_used"] = 0
    
    if mystat["Key_read_requests"] > 0:
        pkfm = 100 - (mystat["Key_reads"] / mystat["Key_read_requests"] * 100)
        mycalc["pct_keys_from_mem"] = f"{round(pkfm, 1)}"
    else:
        mycalc["pct_keys_from_mem"] = 0
    
    if mystat["Aria_pagecache_read_requests"] and mystat["Aria_pagecache_read_requests"] > 0:
        
        pakfm = 100 - (mystat["Aria_pagecache_reads"] / mystat["Aria_pagecache_read_requests"] * 100)
        mycalc["pct_aria_keys_from_mem"] = f"{round(pakfm, 1)}"
    else:
        mycalc["pct_aria_keys_from_mem"] = 0
        
    if mystat["Key_write_requests"] > 0:
        pwkfm = 100 - (mystat["Key_writes"] / mystat["Key_write_requests"] * 100)
        mycalc["pct_wkeys_from_mem"] = f"{round(pwkfm, 1)}"
    else:
        mycalc["pct_wkeys_from_mem"] = 0
    
    if (doremote == 0) and (not mysql_version_ge(5)):
        size = 0
        all_sizes = sbpr.check_output(["find", myvar["datadir"], "-name", "'*MYI'", "2>&1", "|", "xargs", "du", "-L", duflags, "2>&1"], universal_newlines=True)
        for all_size in all_sizes.split():
            size += all_size[0]
        mycalc["total_myisam_indexes"] = size
        mycalc["total_aria_indexes"] = 0
    elif mysql_version_ge(5):
        mycalc["total_myisam_indexes"] = select_one("SELECT IFNULL(SUM(INDEX_LENGTH),0) FROM information_schema.TABLES WHERE TABLE_SCHEMA NOT IN ('information_schema') AND ENGINE = 'MyISAM';")
        mycalc["total_aria_indexes"] = select_one("SELECT IFNULL(SUM(INDEX_LENGTH),0) FROM information_schema.TABLES WHERE TABLE_SCHEMA NOT IN ('information_schema') AND ENGINE = 'Aria';")
    
    if mycalc["total_myisam_indexes"] and (mycalc["total_myisam_indexes"] == 0):
        mycalc["total_myisam_indexes"] = "fail"
    elif mycalc["total_myisam_indexes"]:
        mycalc["total_myisam_indexes"] = mycalc["total_myisam_indexes"].rstrip()
    
    if mycalc["total_aria_indexes"] and (mycalc["total_aria_indexes"] == 0):
        mycalc["total_aria_indexes"] = 1
    elif mycalc["total_aria_indexes"]:
        mycalc["total_aria_indexes"] = mycalc["total_aria_indexes"].rstrip()
    
    # Query cache
    if mysql_version_ge(4):
        qce = mystat["Qcache_hits"] / (mystat["Com_select"] + mystat["Qcache_hits"]) * 100
        mycalc["query_cache_efficiency"] = f"{round(qce, 1)}"
        
        if myvar["query_cache_size"]:
            pqcu = 100 - (mystat["Qcache_free_memory"] / myvar["query_cache_size"]) * 100
            mycalc["pct_query_cache_used"] = f"{round(pqcu, 1)}"
        
        if mystat["Qcache_lowmem_prunes"] == 0:
            mycalc["query_cache_prunes_per_day"] = 0
        else:
            mycalc["query_cache_prunes_per_day"] = int(mystat["Qcache_lowmem_prunes"] / mystat["Uptime"] / 86400)
    # Sorting
    mycalc["total_sorts"] = mystat["Sort_scan"] + mystat["Sort_range"]
    if mycalc["total_sorts"] > 0:
        mycalc["pct_temp_sort_table"] = int(mystat["Sort_merge_passes"] / mycalc["total_sorts"] * 100)
    
    # Joins
    mycalc["joins_without_indexes"] = mystat["Select_range_check"] + mystat["Select_full_join"]
    mycalc["joins_without_indexes_per_day"] = int(mycalc["joins_without_indexes"] / mystat["Uptime"] / 86400)
    
    # Temporary tables
    if mystat["Created_tmp_tables"] > 0:
        if mystat["Created_tmp_disk_tables"] > 0:
            mycalc["pct_temp_disk"] = int(mystat["Created_tmp_disk_tables"] / mystat["Created_tmp_tables"] * 100)
        else:
            mycalc["pct_temp_disk"] = 0
    
    # Table cache
    if mystat["Opened_tables"] > 0:
        mycalc["table_cache_hit_rate"] = int(mystat["Open_tables"] / mystat["Opened_tables"] * 100)
    else:
        mycalc["table_cache_hit_rate"] = 100
    
    # Open files
    if myvar["open_files_limit"] > 0:
        mycalc["pct_files_open"] = int(mystat["Open_files"] / mystat["open_files_limits"] * 100)
    
    # Table locks
    if mystat["Table_locks_immediate"] > 0:
        if mystat["Table_locks_waited"] == 0:
            mycalc["pct_table_locks_immediate"] = 100
        else:
            mycalc["pct_table_locks_immediate"] = int(mystat["Table_locks_immediate"] / (mystat["Table_locks_waited"] + mystat["Table_locks_immediate"]) * 100)
    
    # Thread cache
    mycalc["thread_cache_hit_rate"] = int(100 - (mystat["Threads_created"] / mystat["Connections"] * 100))
    
    # Other
    if mystat["Connections"] > 0:
        mycalc["pct_aborted_connections"] = int(mystat["Aborted_connects"] / mystat["Connections"] * 100)
    
    if mystat["Questions"] > 0:
        mycalc["total_reads"] = mystat["Com_select"]
        mycalc["total_writes"] = \
            mystat["Com_delete"] +\
            mystat["Com_insert"] +\
            mystat["Com_update"] +\
            mystat["Com_replace"]
        if mycalc["total_reads"] == 0:
            mycalc["pct_reads"] = 0
            mycalc["pct_writes"] = 100
        else:
            mycalc["pct_reads"] = int(mycalc["total_reads"] / (mycalc["total_reads"] + mycalc["total_writes"]) * 100)
            mycalc["pct_writes"] = 100 - mycalc["pct_reads"]
    
    # InnoDB
    if myvar["have_innodb"] == "YES":
        mycalc["innodb_log_file_pct"] = myvar["innodb_log_file_size"] * myvar["innodb_log_files_in_group"] * 100 / myvar["innodb_buffer_pool_size"]
    
    # InnoDB Buffer pool read cache efficiency
    if not mystat["Innodb_buffer_pool_reads"]:
        mystat["Innodb_buffer_pool_read_requests"] = 1
        mystat["Innodb_buffer_pool_reads"] = 1
    
    mycalc["pct_read_efficiency"] = percentage(mystat["Innodb_buffer_pool_read_requests"], mystat["Innodb_buffer_pool_reads"])
    debug_msg = f"pct_read_efficiency {mycalc['pct_read_efficiency']}"
    debugprint(debug_msg)
    debug_msg = f"Innodb_buffer_pool_reads: {mystat['Innodb_buffer_pool_reads']}"
    debugprint(debug_msg)
    debug_msg = f"Innodb_buffer_pool_read_requests: {mystat['Innodb_buffer_pool_read_requests']}"
    debugprint(debug_msg)
    
    # InnoDB log write cache effiency
    if not mystat["Innodb_log_writes"]:
        mystat["Innodb_log_write_requests"] = 1
        mystat["Innodb_log_writes"] = 1
    
    mycalc["pct_write_efficiency"] = percentage(mystat["Innodb_log_write_requests"], mystat["Innodb_log_writes"])
    debug_msg = f"pct_write_efficiency {mycalc['pct_write_efficiency']}"
    debugprint(debug_msg)
    debug_msg = f"Innodb_log_writes: {mystat['Innodb_log_writes']}"
    debugprint(debug_msg)
    debug_msg = f"Innodb_log_write_requests: {mystat['Innodb_log_write_requests']}"
    debugprint(debug_msg)
    
    if mystat["Innodb_buffer_pool_pages_total"]:
        mycalc["pct_innodb_buffer_used"] = percentage(mystat["Innodb_buffer_pool_pages_total"] - mystat["Innodb_buffer_pool_pages_free"], mystat["Innodb_buffer_pool_pages_total"])
    
    # Binlog Cache
    if myvar["log_bin"] != "OFF":
        mycalc["pct_binlog_cache"] = percentage(mystat["Binlog_cache_use"] - mystat["Binlog_cache_disk_use"], mystat["Binlog_cache_use"])
    
def mysql_stats():
    subheaderprint("Performance Metrics")
    
    # Show uptime, queries per second, connections, traffic stats
    if mystat["Uptime"] > 0:
        qps = f"{round(mystat['Questions'] / mystat['Uptime'], 3)}"
    if mystat["Uptime"] < 86400:
        generalrec.append("MySQL started within last 24 hours - recommendations may be inaccurate")
    info_msg = f"Up for {pretty_uptime(mystat['Questions'])} ({hr_num(mystat['Questions'])} q[{hr_num(qps)} qps] {hr_num(mystat['Connections'])} conn, TX: {hr_bytes_rnd(mystat['Bytes_sent'])}, RX: {hr_bytes_rnd(mystat['Bytes_received'])})"
    infoprint(info_msg)
    info_msg = f"Reads / Writes: {mycalc['pct_reads']}% / {mycalc['pct_writes']}%"
    infoprint(info_msg)
    
    # Binlog Cache
    if myvar["log_bin"] == "OFF":
        infoprint("Binary logging is disabled")
    else:
        if myvar["gtid_mode"]:
            gm = myvar["gtid_mode"]
        else:
            gm = "OFF"
        info_msg = f"Binary logging is enabled (GTID MODE: {gm})"
        infoprint(info_msg)
    
    # Memory usage
    info_msg = f"Physical Memory     : {hr_bytes(physical_memory)}"
    infoprint(info_msg)
    info_msg = f"Max MySQL memory    : {hr_bytes(mycalc['max_peak_memory'])}"
    infoprint(info_msg)
    info_msg = f"Other process memory: {hr_bytes(get_other_process_memory())}"
    infoprint(info_msg)
    
    #print(hr_bytes(mycalc['server_buffers'])
    
    info_msg = f"Total buffers:{hr_bytes(mycalc['server_buffers'])} global + {hr_bytes(mycalc['per_thread_buffers'])} per thread ({myvar['max_connections']} max threads)"
    infoprint(info_msg)
    
    info_msg = f"P_S Max memory usage: {hr_bytes_rnd(get_pf_memory())}"
    infoprint(info_msg)
    result["P_S"]["memory"] = get_other_process_memory()
    result["P_S"]["pretty_memory"] = hr_bytes_rnd(get_other_process_memory())
    
    info_msg = f"Galera GCache Max memory usage: {hr_bytes_rnd(get_gcache_memory())}"
    infoprint(info_msg)
    result["Galera"]["GCache"]["memory"] = get_gcache_memory()
    result["Galera"]["GCache"]["pretty_memory"] = hr_bytes_rnd(get_gcache_memory())
    
    if opt[buffers] != 0:
        infoprint("Global Buffers")
        info_msg = f" +-- Key Buffer: {hr_bytes(myvar['key_buffer_size'])}
        infoprint(info_msg)
        info_msg = f" +-- Max Tmp Table: {hr_bytes(myvar['max_tmp_table_size'])}
        infoprint(info_msg)
        
        if myvar["query_cache_type"]:
            infoprint("Query Cache Buffers")
            if myvar["query_cache_type"] in (0, "OFF"):
                qct = "DISABLED"
            elif myvar["query_cache_type"] == 1:
                qct = "ALL REQUESTS"
            else:
                qct = "ON DEMAND"
            info_msg = " +-- Query Cache: {myvar['query_cache_type']} - {qct}"
            infoprint(info_msg)
            info_msg = f" +-- Query Cache Size: {hr_bytes(myvar['query_cache_size'])}"
        
        infoprint("Per Thread Buffers")
        info_msg = f" +-- Read Buffer: {hr_bytes(myvar['read_buffer_size'])}"
        infoprint(info_msg)
        info_msg = f" +-- Read RND Buffer: {hr_bytes(myvar['read_rnd_buffer_size'])}"
        infoprint(info_msg)
        info_msg = f" +-- Sort Buffer: {hr_bytes(myvar['sort_buffer_size'])}"
        infoprint(info_msg)
        info_msg = f" +-- Thread stack: {hr_bytes(myvar['thread_stack'])}"
        infoprint(info_msg)
        info_msg = f" +-- Join Buffer: {hr_bytes(myvar['join_buffer_size'])}"
        infoprint(info_msg)
        
        if myvar["log_bin"] != "OFF":
            infoprint("Binlog Cache Buffers")
            info_msg = f" +-- Binlog Cache: {hr_bytes(myvar['binlog_cache_size'])}"
            infoprint(info_msg)
    
    if arch and (arch == 32) and (mycalc["max_used_memory"] > 2 * 1024 ** 3:
        badprint("Allocating > 2GB RAM on 32-bit systems can cause system instability")
        bad_msg = f"Maximum reached memory usage: {hr_bytes(mycalc['max_used_memory'])} {mycalc['pct_max_used_memory']}% of installed RAM"
        badprint(bad_msg)
    elif mycalc["pct_max_used_memory"] > 85:
        bad_msg = f"Maximum reached memory usage: {hr_bytes(mycalc['max_used_memory'])} {mycalc['pct_max_used_memory']}% of installed RAM"
        badprint(bad_msg)
    else:
        good_msg = f"Maximum reached memory usage: {hr_bytes(mycalc['max_used_memory'])} {mycalc['pct_max_used_memory']}% of installed RAM"
        goodprint(good_msg)
    
    if mycalc["pct_max_physical_memory"] > 85:
        bad_msg = f"Maximum possible memory usage: {hr_bytes(mycalc['max_peak_memory'])} {mycalc['pct_max_physical_memory']}% of installed RAM"
        badprint(bad_msg)
        generalrec.append("Reduce your overall MySQL memory footprint for system stability")
    else:
        good_msg = f"Maximum possible memory usage: {hr_bytes(mycalc['max_peak_memory'])} {mycalc['pct_max_physical_memory']}% of installed RAM"
        goodprint(good_msg)
    
    if physical_memory < (mycalc["max_peak_memory"] + get_other_process_memory()):
        badprint("Overall possible memory usage with other process exceeded memory")
        generalrec.append("Dedicate this server to your database for highest performance.")
    else:
        goodprint("Overall possible memory usage with other process is compatible with memory available")
    
    # Slow queries
    if mycalc["pct_slow_queries"] > 5:
        bad_msg = f"Slow queries: {mycalc['pct_slow_queries']}% ({hr_num(mystat['Slow_queries'])}/{hr_num(mystat['Questions'])})"
        badprint(bad_msg)
    else:
        good_msg = f"Slow queries: {mycalc['pct_slow_queries']}% ({hr_num(mystat['Slow_queries'])}/{hr_num(mystat['Questions'])})"
        goodprint(good_msg)
    
    if myvar["long_query_time"] > 10:
        adjvars.append("long_query_time (<= 10)")
    
    if myvar["log_slow_queries"]:
        if myvar["log_slow_queries"] == "OFF":
            generalrec.append("Enable the slow query log to troubleshoot bad queries")
    
    # Connections
    if mycalc["pct_connections_used"] > 85:
        bad_msg = f"High connection usage: {mycalc['pct_connections_used']}% ({hr_num(mystat['Max_used_connections'])}/{myvar['max_connections']})"
        badprint(bad_msg)
        adjvars.extend((
            f"max_connections (> {myvar['max_connections']})",
            f"wait_timeout (< {myvar['wait_timeout']})",
            f"interactive_timeout (< {myvar['interactive_timeout']})"
        ))
        generalrec.append("Reduce or eliminate persistent connections to reduce connection usage")
    else:
        good_msg = f"High connection usage: {mycalc['pct_connections_used']}% ({hr_num(mystat['Max_used_connections'])}/{myvar['max_connections']})"
        goodprint(good_msg)
    
    # Aborted Connections
    if mycalc["pct_connections_aborted"] > 3:
        bad_msg = f"Aborted connections: {mycalc['pct_connections_abored']}% ({hr_num(mystat['Aborted_connects'])}/{myvar['Connections']})"
        badprint(bad_msg)
        generalrec.append("Reduce or eliminate unclosed connections and network issues")
    else:
        good_msg = f"Aborted connections: {mycalc['pct_connections_abored']}% ({hr_num(mystat['Aborted_connects'])}/{myvar['Connections']})"
        goodprint(good_msg)
    
    # name resolution
    if not result["Variables"]["skip_name_resolve"]:
        infoprint("Skipped name resolution test due to missing skip_name_resolve in system variables.")
    elif result["Variables"]["skip_name_resolve"] == "YES":
        badprint("name resolution is active : a reverse name resolution is made for each new connection and can reduce performance")
        generalrec.append("Configure your accounts with ip or subnets only, then update your configuration with skip-name-resolve=1")
    
    # Query cache
    if not mysql_version_ge(4):
        # MySQL versions < 4.01 don't support query caching
        generalrec.append("Upgrade MySQL to version 4+ to utilize query caching")
    elif mysql_version_ge(5, 5) and not mysql_version_ge(10, 1) and (myvar["query_cache_type"] == "OFF"):
        goodprint("Query cache is disabled by default due to mutex contention on multiprocessor machines.")
    elif myvar["query_cache_size"] < 1:
        badprint("Query cache is disabled")
        adjvars.append("query_cache_size (>= 8M)")
    elif myvar["query_cache_size"] < "OFF":
        badprint("Query cache is disabled")
        adjvars.append("query_cache_type (=1)")
    else:
        badprint("Query cache may be disabled by default due to mutex contention.")
        adjvars.append("query_cache_type (=0)")
        if mycalc["query_cache_efficiency"] < 20:
            bad_msg = f"Query cache efficiency: {mycalc['query_cache_efficiency']}% ({hr_num(mystat['Qcache_hits'])} cached / {hr_num(mystat['Qcache_hits'] + mystat['Com_select'])} selects)"
            badprint(bad_msg)
            adjvars.append(f"query_cache_limit (> {hr_bytes_rnd(myvar['query_cache_limit'])}, or use smaller result sets)")
        else:
            good_msg = f"Query cache efficiency: {mycalc['query_cache_efficiency']}% ({hr_num(mystat['Qcache_hits'])} cached / {hr_num(mystat['Qcache_hits'] + mystat['Com_select'])} selects)"
            goodprint(good_msg)
        
        if mycalc["query_cache_prunes_per_day"] > 98:
            bad_msg = f"Query cache prunes per day: {mycalc['query_cache_prunes_per_day']}"
            badprint(bad_msg)
            if myvar["query_cache_size"] > 128 * 1024 ** 2:
                generalrec.append("Increasing the query_cache size over 128M may reduce performance")
                adjvars.append(f"query_cache_size (> {hr_bytes_rnd(myvar['query_cache_size'])}) [see warning above]")
            else:
                adjvars.append(f"query_cache_size (> {hr_bytes_rnd(myvar['query_cache_size'])})")
        else:
            good_msg = f"Query cache prunes per day: {mycalc['query_cache_prunes_per_day']}"
            goodprint(good_msg)
        
    # Sorting
    if mycalc["total_sorts"] == 0:
        goodprint("No Sort requiring temporary tables")
    elif mycalc["pct_temp_sort_table"] > 10:
        bad_msg = f"Sorts requiring temporary tables: {mycalc['pct_temp_sort_table']}% ({hr_num(mystat['Sort_merge_passes'])} temp sorts / {hr_num(mycalc['total_sorts'])} sorts)"
        badprint(bad_msg)
        adjvars.append(f"sort_buffer_size (> {hr_bytes_rnd(myvar['sort_buffer_size'])})")
        adjvars.append(f"read_rnd_buffer_size (> {hr_bytes_rnd(myvar['read_rnd_buffer_size'])})")
    else:
        good_msg = f"Sorts requiring temporary tables: {mycalc['pct_temp_sort_table']}% ({hr_num(mystat['Sort_merge_passes'])} temp sorts / {hr_num(mycalc['total_sorts'])} sorts)"
        goodprint(good_msg)
    
    # Joins
    if mycalc["joins_without_indexes_per_day"] > 250:
        bad_msg = f"Joins performed without indexes: {mycalc['joins_without_indexes']}"
        badprint(bad_msg)
        adjvars.append(f"join_buffer_size (> {hr_bytes_rnd(myvar['join_buffer_size'])}, or always use indexes with joins)")
        generalrec.append("Adjust your join queries to always utilize indexes")
    else:
        goodprint("No joins without indexes")
        # No joins have run without indexes
    
    # Temporary tables
    if mystat["Created_tmp_tables"] > 0:
        if (mycalc["pct_temp_disk"] > 25) and (mycalc["max_tmp_table_size"] < 256 * 1024 ** 2):
            bad_msg = f"Temporary tables created on disk: {mycalc['pct_temp_disk']}% ({hr_num(mystat['Created_tmp_disk_tables'])} on disk / {hr_num(mystat['Created_tmp_tables'])} totals)"
            badprint(bad_msg)
            adjvars.append(f"tmp_table_size (> {hr_bytes_rnd(myvar['tmp_table_size'])})")
            adjvars.append(f"max_heap_table_size (> {hr_bytes_rnd(myvar['max_heap_table_size'])})")
            generalrec.append("When making adjustments, make tmp_table_size/max_heap_table_size equal")
            generalrec.append("Reduce your SELECT DISTINCT queries which have no LIMIT clause")
        elif (mycalc["pct_temp_disk"] > 25) and (mycalc["max_tmp_table_size"] >= 256 * 1024 ** 2):
            bad_msg = f"Temporary tables created on disk: {mycalc['pct_temp_disk']}% ({hr_num(mystat['Created_tmp_disk_tables'])} on disk / {hr_num(mystat['Created_tmp_tables'])} totals)"
            badprint(bad_msg)
            generalrec.append("Temporary table size is already large - reduce result set size")
            generalrec.append("Reduce your SELECT DISTINCT queries which have no LIMIT clause")
        else:
            good_msg = f"Temporary tables created on disk: {mycalc['pct_temp_disk']}% ({hr_num(mystat['Created_tmp_disk_tables'])} on disk / {hr_num(mystat['Created_tmp_tables'])} totals)"
            goodprint(good_msg)
    else:
        goodprint("No tmp tables created on disk")
    
    # Thread cache
    if myvar["thread_cache_size"] == 0:
        badprint("Thread cache is disabled")
        generalrec.append("Set thread_cache_size to 4 as a starting value")
        adjvars.append("thread_cache_size (start at 4)")
    else:
        if myvar["thread_handling"] and myvar["thread_handling"] == "pools-of-threads":
            infoprint("Thread cache hit rate: not used with pool-of-threads")
        else:
            if mycalc["thread_cache_hit_rate"] <= 50:
                bad_msg = f"Thread cache hit rate: {mycalc['thread_cache_hit_rate']}% ({hr_num(mystat['Threads_created'])} created / {hr_num(mystat['Connections'])} connections)"
                badprint(bad_msg)
                adjvars.append(f"thread_cache_size (> {myvar['thread_cache_size']})")
            else:
                good_msg = f"Thread cache hit rate: {mycalc['thread_cache_hit_rate']}% ({hr_num(mystat['Threads_created'])} created / {hr_num(mystat['Connections'])} connections)"
                goodprint(good_msg)

    # Table cache
    table_cache_var = ""
    if mystat["Open_tables"] > 0:
        if mycalc["table_cache_hit_rate"] < 20:
            bad_msg = f"Table cache hit rate: {mycalc['table_cache_hit_rate']}% ({hr_num(mystat['Open_tables'])} open / {hr_num(mystat['Opened_tables'])} opened)"
            badprint(bad_msg)
            if mysql_version_ge(5, 1):
                table_cache_var = "table_open_cache"
            else:
                table_cache_var = "table_cache"
            
            adjvars.append(f"{table_cache_var} (> {myvar[table_cache_var]})")
            generalrec.append(f"Increase {table_cache_var} gradually to avoid file descriptor limits")
            generalrec.append(f"Read this before increasing {table_cache_var} over 64 http://bit.ly/1mi7c4C")
            generalrec.append(f"Beware the open_files_limit ({myvar['open_files_limit']}) variable")
            generalrec.append(f"should be greater than {table_cache_var} ({myvar[table_cache_var]})")
        else:
            good_msg = f"Table cache hit rate: {mycalc['table_cache_hit_rate']}% ({hr_num(mystat['Open_tables'])} open / {hr_num(mystat['Opened_tables'])} opened)"
            goodprint(good_msg)
    
    
    # Open files
    if mycalc["pct_files_open"]:
        if mycalc["pct_files_open"] > 85:
            bad_msg = f"Open file limit used: {mycalc['pct_files_open']}% ({hr_num(mystat['Open_files'])} / {hr_num(myvar['open_files_limit'])})"
            badprint(bad_msg)
            adjvars.append(f"open_files_limit (> {myvar['open_files_limit']})")
        else:
            good_msg = f"Open file limit used: {mycalc['pct_files_open']}% ({hr_num(mystat['Open_files'])} / {hr_num(myvar['open_files_limit'])})"
            goodprint(good_msg)
    
    # Table locks
    if mycalc["pct_table_locks_immediate"]:
        if mycalc["pct_table_locks_immediate"] < 95:
            bad_msg = f"Table locks acquired immediately: {mycalc['pct_table_locks_immediate']}%"
            badprint(bad_msg)
            generalrec.append("Optimize queries and/or use InnoDB to reduce lock wait")
        else:
            good_msg = f"Table locks acquired immediately: {mycalc['pct_table_locks_immediate']}% ({hr_num(mystat['Table_locks_immediate'])} immediate/ {hr_num(mystat['Table_locks_waited'] + mystat['Table_locks_immediate'])} locks)"
            goodprint(good_msg)
        
    # Binlog cache
    if mycalc["pct_binlog_cache"]:
        if (mycalc["pct_binlog_cache"] > 90) and (mystat["Binlog_cache_use"] > 0):
            bad_msg = f"Binlog cache memory access: {mycalc['pct_binlog_cache']}% ({mystat['Binlog_cache_use'] - mystat['Binlog_cache_disk_use']} Memory / {mystat['Binlog_cache_use']} Total)"
            badprint(bad_msg)
            generalrec.append(f"Increase binlog_cache_size (Actual value: {myvar['binlog_cache_size']})")
            adjvars.append(f"binlog_cache_size ({hr_bytes(myvar['binlog_cache_size'] + 16 * 1024 ** 2)})")
        else:
            good_msg = f"Binlog cache memory access: {mycalc['pct_binlog_cache']}% ({mystat['Binlog_cache_use'] - mystat['Binlog_cache_disk_use']} Memory / {mystat['Binlog_cache_use']} Total)"
            goodprint(good_msg)
            if mystat["Binlog_cache_use"] < 10:
                debug_msg = "Not enough data to validate binlog cache size\n"
                debugprint(debug_msg)
    
    # Performance options
    if not mysql_version_ge(5, 1):
        generalrec.append("Upgrade to MySQL 5.5+ to use asynchronous write")
    elif myvar["concurrent_insert"] == "OFF":
        generalrec.append("Enable concurrent_insert by setting it to 'ON'")
    elif myvar["concurrent_insert"] == 0:
        generalrec.append("Enable concurrent_insert by setting it to 1")

# Recommendations for MyISAM
def mysql_myisam():
    subheaderprint("MyISAM Metrics")
    
    # Key buffer usage
    if mycalc['pcy_key_buffer_used']:
        if mycalc['pcy_key_buffer_used'] < 90:
            bad_msg = f"Key buffer used: {mycalc['pct_key_buffer_used']}% ({hr_num(myvar['key_buffer_size'] * mycalc['pct_key_buffer_used'] / 100)} used / {hr_num(myvar['key_buffer_size'])} cache)"
            badprint(bad_msg)
            #adjvars.append(f"Key_buffer_size (\~ {hr_num(myvar['key_buffer_size'] * mycalc['pct_key_buffer_used'] / 100)})")
        else:
            good_msg = f"Key buffer used: {mycalc['pct_key_buffer_used']}% ({hr_num(myvar['key_buffer_size'] * mycalc['pct_key_buffer_used'] / 100)} used / {hr_num(myvar['key_buffer_size'])} cache)"
            goodprint(good_msg)
    else:
        # No queries have run that would use keys
        debug_msg = f"Key buffer used: {mycalc['pct_key_buffer_used']}% ({hr_num(myvar['key_buffer_size'] * mycalc['pct_key_buffer_used'] / 100)} used / {hr_num(myvar['key_buffer_size'])} cache)"
        debugprint(debug_msg)
    
    fail_match = r"/^fail$/"
    # Key buffer
    if (not mycalc["total_myisam_indexes"]) and (doremote == 1):
        generalrec.append("Unable to calculate MyISAM indexes on remote MySQL server < 5.0.0")
    elif re.match(fail_match, mycalc["total_myisam_indexes"]):
        badprint("Cannot calculate MyISAM index size - re-run script as root user")
    else:
        if (myvar["key_buffer_size"] < mycalc["total_myisam_indexes"]) and (mycalc["pct_keys_from_mem"] < 95):
            bad_msg = f"Key buffer size / total MyISAM indexes: {hr_bytes(myvar['key_buffer_size'])}/{hr_bytes(mycalc['total_myisam_indexes'])}"
            badprint(bad_msg)
            adjvars.append(f"key_buffer_size (> {hr_bytes(mycalc['total_myisam_indexes'])})")
        else:
            good_msg = f"Key buffer size / total MyISAM indexes: {hr_bytes(myvar['key_buffer_size'])}/{hr_bytes(mycalc['total_myisam_indexes'])}"
            goodprint(good_msg)
        if mystat['Key_read_requests'] > 0:
            if mycalc['pct_keys_from_mem'] < 95:
                bad_msg = f"Read Key buffer hit rate: {mycalc['pct_keys_from_mem']}% ({hr_num(mystat['Key_read_requests'])} cached / {hr_num(mystat['Key_reads'])} reads"
                badprint(bad_msg)
            else:
                good_msg = f"Read Key buffer hit rate: {mycalc['pct_keys_from_mem']}% ({hr_num(mystat['Key_read_requests'])} cached / {hr_num(mystat['Key_reads'])} reads"
                goodprint(good_msg)
        else:
            # No queries have run that would use keys
            debug_msg = f"Key buffer size / total MyISAM indexes: {hr_bytes(myvar['key_buffer_size'])}/{hr_bytes(mycalc['total_myisam_indexes'])}"
            debugprint(debug_msg)
        if mystat['Key_write_requests'] > 0:
            if mycalc['pct_wkeys_from_mem'] < 95:
                bad_msg = f"Write Key buffer hit rate: {mycalc['pct_wkeys_from_mem']}% ({hr_num(mystat['Key_write_requests'])} cached / {hr_num(mystat['Key_writes'])} writes"
                badprint(bad_msg)
            else:
                good_msg = f"Write Key buffer hit rate: {mycalc['pct_wkeys_from_mem']}% ({hr_num(mystat['Key_write_requests'])} cached / {hr_num(mystat['Key_writes'])} writes"
                goodprint(good_msg)
        else:
            # No queries have run that would use keys
            debug_msg = f"Write Key buffer hit rate: {mycalc['pct_wkeys_from_mem']}% ({hr_num(mystat['Key_write_requests'])} cached / {hr_num(mystat['Key_writes'])} writes"
            debugprint(debug_msg)

# Recommendations for ThreadPool
def mariadb_threadpool():
    subheaderprint("ThreadPool Metrics")
    
    # AriaDB
    if not ((myvar["have_threadpool"]) and (myvar["have_threadpool"] == "YES")):
        infoprint("ThreadPool stat is disabled.")
        return
    infoprint("ThreadPool stat is enabled.")
    info_msg = f"Thread Pool Size: {myvar['thread_pool_size']} thread(s)"
    infoprint(info_msg)
    
    maria_match = r"/mariadb|percona/i"
    if re.match(maria_match, myvar["version"]):
        info_msg = f"Using default value is good enough for your version ({myvar['version']})"
        infoprint(info_msg)
        return

    if myvar["have_innodb"] == "YES":
        if (myvar["thread_pool_size"] < 16) or (myvar["thread_pool_size"] > 36):
            badprint("thread_pool_size between 16 and 36 when using InnoDB storage engine.")
            generalrec.append(f"Thread pool size for InnoDB usage ({myvar['thread_pool_size']})")
            adjvars.append("thread_pool_size between 16 and 36 for InnoDB usage")
        else:
            goodprint("thread_pool_size between 16 and 36 when using InnoDB storage engine.")
        return
    if myvar["have_isam"] == "YES":
        if (myvar["thread_pool_size"] < 4) or (myvar["thread_pool_size"] > 8):
            badprint("thread_pool_size between 4 and 8 when using MyIsam storage engine.")
            generalrec.append(f"Thread pool size for MyIsam usage ({myvar['thread_pool_size']})")
            adjvars.append("thread_pool_size between 4 and 8 when using MyIsam storage engine.")
        else:
            goodprint("thread_pool_size between 4 and 8 when using MyIsam storage engine.")

def get_pf_memory():
    # Performance Schema
    if (not myvar["performance_schema"]) or (myvar["performance_schema"] == 0):
        return 0
    
    infoPFSMemory = [info for info in select_array("SHOW ENGINE PERFORMANCE_SCHEMA STATUS") if info in "performance_schema.memory"]
    if len(infoPFSMemory) == 0:
        return 0
    
    return infoPFSMemory[0]

# Recommendations for Performance Schema
def mysqsl_pfs()
    subheaderprint("Performance schema")
    
    # Performance Schema
    if not myvar["performance_schema"]:
        myvar["performance_schema"] = "OFF"
    if not (myvar["performance_schema"] == "ON"):
        infoprint("Performance schema is disabled.")
        if mysql_version_ge(5, 5):
            generalrec.append("Performance should be activated for better diagnostics")
            adjvars.append("performance_schema = ON enable PFS")
        else:
            generalrec.append("Performance shouldn't be activated for MySQL and MariaDB 5.5 and lower version")
            adjvars.append("performance_schema = OFF disable PFS")
    debug_msg = f"Performance schema is {myvar['performance_schema']}"
    debugprint(debug_msg)
    info_msg = f"Memory used by P_S: {hr_bytes(get_pf_memory())}"
    infoprint(info_msg)
    
    sys_schemas = [db for db in select_array("SHOW DATABASES") if db == "sys"]
    if not sys_schemas:
        infoprint("Sys schema isn't installed.")
        generalrec.append("Consider installing Sys schema from https://github.com/mysql/mysql-sys")
        return
    else:
        infoprint("Sys schema is installed.")
    
    if (opt[pfstat] == 0) or (myvar["performance_schema"] != "ON"):
        return
    
    info_msg = f"Sys schema Version: {select_one('select sys_version from sys.version')}"
    infoprint(info_msg)
    
    # Top user per connection
    subheaderprint("Performance schema: Top 5 user per connection")
    nbL = 1
    for lQuery in select_array("select user, total_connections from sys.user_summary order by total_connections desc LIMIT 5"):
        info_msg = f" +-- {nbL}: {lQuery} conn(s)"
        infoprint(info_msg)
        nbL += 1
    if nbL == 1:
        infoprint("No information found or indicators desactivated.")
    
    # Top user per statement
    subheaderprint("Performance schema: Top 5 user per statement")
    nbL = 1
    for lQuery in select_array("select user, statements from sys.user_summary order by statements desc LIMIT 5"):
        info_msg = f" +-- {nbL}: {lQuery} stmt(s)"
        infoprint(info_msg)
        nbL += 1
    if nbL == 1:
        infoprint("No information found or indicators desactivated.")
    
    # Top user per statement latency
    subheaderprint("Performance schema: Top 5 user per statement latency")
    nbL = 1
    for lQuery in select_array("select user, statement_avg_latency from sys.user_summary order by statement_avg_latency desc LIMIT 5"):
        info_msg = f" +-- {nbL}: {lQuery}"
        infoprint(info_msg)
        nbL += 1
    if nbL == 1:
        infoprint("No information found or indicators desactivated.")
    
    # Top user per lock latency
    subheaderprint("Performance schema: Top 5 user per lock latency")
    nbL = 1
    for lQuery in select_array("select user, lock_latency from sys.user_summary_by_statement_latency order by lock_latency desc LIMIT 5"):
        info_msg = f" +-- {nbL}: {lQuery}"
        infoprint(info_msg)
        nbL += 1
    if nbL == 1:
        infoprint("No information found or indicators desactivated.")
        
    # Top user per full scans
    subheaderprint("Performance schema: Top 5 user per nb full scans")
    nbL = 1
    for lQuery in select_array("select user, full_scans from sys.user_summary_by_statement_latency order by full_scans desc LIMIT 5"):
        info_msg = f" +-- {nbL}: {lQuery}"
        infoprint(info_msg)
        nbL += 1
    if nbL == 1:
        infoprint("No information found or indicators desactivated.")
        
    # Top user per row_sent
    subheaderprint("Performance schema: Top 5 user per rows sent")
    nbL = 1
    for lQuery in select_array("select user, rows_sent from sys.user_summary_by_statement_latency order by rows_sent desc LIMIT 5"):
        info_msg = f" +-- {nbL}: {lQuery}"
        infoprint(info_msg)
        nbL += 1
    if nbL == 1:
        infoprint("No information found or indicators desactivated.")
    
    # Top user per row modified
    subheaderprint("Performance schema: Top 5 user per rows modified")
    nbL = 1
    for lQuery in select_array("select user, rows_affected from sys.user_summary_by_statement_latency order by rows_affected desc LIMIT 5"):
        info_msg = f" +-- {nbL}: {lQuery}"
        infoprint(info_msg)
        nbL += 1
    if nbL == 1:
        infoprint("No information found or indicators desactivated.")
        
    # Top user per io
    subheaderprint("Performance schema: Top 5 user per io")
    nbL = 1
    for lQuery in select_array("select user, file_ios from sys.user_summary order by file_ios desc LIMIT 5"):
        info_msg = f" +-- {nbL}: {lQuery}"
        infoprint(info_msg)
        nbL += 1
    if nbL == 1:
        infoprint("No information found or indicators desactivated.")
    
    # Top user per io latency
    subheaderprint("Performance schema: Top 5 user per io latency")
    nbL = 1
    for lQuery in select_array("select user, file_io_latency from sys.user_summary order by file_io_latency desc LIMIT 5"):
        info_msg = f" +-- {nbL}: {lQuery}"
        infoprint(info_msg)
        nbL += 1
    if nbL == 1:
        infoprint("No information found or indicators desactivated.")
    
    # Top host per connection
    subheaderprint("Performance schema: Top 5 host per connection")
    nbL = 1
    for lQuery in select_array("select host, total_connections from sys.host_summary order by total_connections desc LIMIT 5"):
        info_msg = f" +-- {nbL}: {lQuery} conn(s)"
        infoprint(info_msg)
        nbL += 1
    if nbL == 1:
        infoprint("No information found or indicators desactivated.")
    
    # Top host per statement
    subheaderprint("Performance schema: Top 5 host per statement")
    nbL = 1
    for lQuery in select_array("select host, statements from sys.host_summary order by statements desc LIMIT 5"):
        info_msg = f" +-- {nbL}: {lQuery} stmt(s)"
        infoprint(info_msg)
        nbL += 1
    if nbL == 1:
        infoprint("No information found or indicators desactivated.")
    
    # Top host per statement latency
    subheaderprint("Performance schema: Top 5 host per statement latency")
    nbL = 1
    for lQuery in select_array("select host, statement_avg_latency from sys.host_summary order by statement_avg_latency desc LIMIT 5"):
        info_msg = f" +-- {nbL}: {lQuery} stmt(s)"
        infoprint(info_msg)
        nbL += 1
    if nbL == 1:
        infoprint("No information found or indicators desactivated.")
    
    # Top host per lock latency
    subheaderprint("Performance schema: Top 5 host per lock latency")
    nbL = 1
    for lQuery in select_array("select host, lock_latency from sys.host_summary_by_statement_latency order by lock_latency desc LIMIT 5"):
        info_msg = f" +-- {nbL}: {lQuery}"
        infoprint(info_msg)
        nbL += 1
    if nbL == 1:
        infoprint("No information found or indicators desactivated.")
    
    # Top host per full scans
    subheaderprint("Performance schema: Top 5 host per nb full scans")
    nbL = 1
    for lQuery in select_array("select host, full_scans from sys.host_summary_by_statement_latency order by full_scans desc LIMIT 5"):
        info_msg = f" +-- {nbL}: {lQuery}"
        infoprint(info_msg)
        nbL += 1
    if nbL == 1:
        infoprint("No information found or indicators desactivated.")
    
    # Top host per rows sent
    subheaderprint("Performance schema: Top 5 host per rows sent")
    nbL = 1
    for lQuery in select_array("select host, rows_sent from sys.host_summary_by_statement_latency order by rows_sent desc LIMIT 5"):
        info_msg = f" +-- {nbL}: {lQuery}"
        infoprint(info_msg)
        nbL += 1
    if nbL == 1:
        infoprint("No information found or indicators desactivated.")
    
    # Top host per rows modified
    subheaderprint("Performance schema: Top 5 host per rows modified")
    nbL = 1
    for lQuery in select_array("select host, rows_affected from sys.host_summary_by_statement_latency order by rows_affected desc LIMIT 5"):
        info_msg = f" +-- {nbL}: {lQuery}"
        infoprint(info_msg)
        nbL += 1
    if nbL == 1:
        infoprint("No information found or indicators desactivated.")
    
    # Top host per io
    subheaderprint("Performance schema: Top 5 host per rows modified")
    nbL = 1
    for lQuery in select_array("select host, file_ios from sys.host_summary order by file_ios desc LIMIT 5"):
        info_msg = f" +-- {nbL}: {lQuery}"
        infoprint(info_msg)
        nbL += 1
    if nbL == 1:
        infoprint("No information found or indicators desactivated.")
    
    # Top 5 host per io latency
    subheaderprint("Performance schema: Top 5 host per io latency")
    nbL = 1
    for lQuery in select_array("select host, file_io_latency from sys.host_summary order by file_io_latency desc LIMIT 5"):
        info_msg = f" +-- {nbL}: {lQuery}"
        infoprint(info_msg)
        nbL += 1
    if nbL == 1:
        infoprint("No information found or indicators desactivated.")
    
    # Top IO type order by total io
    subheaderprint("Performance schema: Top IO type order by total io")
    nbL = 1
    for lQuery in select_array("use sys;select substring(event_name,14), SUM(total)AS total from sys.host_summary_by_file_io_type GROUP BY substring(event_name,14) ORDER BY total DESC;"):
        info_msg = f" +-- {nbL}: {lQuery}"
        infoprint(info_msg)
        nbL += 1
    if nbL == 1:
        infoprint("No information found or indicators desactivated.")
    
    # Top IO type order by total latency
    subheaderprint("Performance schema: Top IO type order by total latency")
    nbL = 1
    for lQuery in select_array("use sys;select substring(event_name,14), format_time(ROUND(SUM(total_latency),1)) AS total_latency from sys.host_summary_by_file_io_type GROUP BY substring(event_name,14) ORDER BY total_latency DESC;"):
        info_msg = f" +-- {nbL}: {lQuery}"
        infoprint(info_msg)
        nbL += 1
    if nbL == 1:
        infoprint("No information found or indicators desactivated.")
    
    # Top IO type order by max latency
    subheaderprint("Performance schema: Top IO type order by max latency")
    nbL = 1
    for lQuery in select_array("use sys;select substring(event_name,14), MAX(max_latency) as max_latency from sys.host_summary_by_file_io_type GROUP BY substring(event_name,14) ORDER BY max_latency DESC;"):
        info_msg = f" +-- {nbL}: {lQuery}"
        infoprint(info_msg)
        nbL += 1
    if nbL == 1:
        infoprint("No information found or indicators desactivated.")
    
    # Top Stages order by total io
    subheaderprint("Performance schema: Top Stages order by total io")
    nbL = 1
    for lQuery in select_array("use sys;select substring(event_name,7), SUM(total)AS total from sys.host_summary_by_stages GROUP BY substring(event_name,7) ORDER BY total DESC;"):
        info_msg = f" +-- {nbL}: {lQuery} i/o"
        infoprint(info_msg)
        nbL += 1
    if nbL == 1:
        infoprint("No information found or indicators desactivated.")
    
    # Top Stages order by total latency
    subheaderprint("Performance schema: Top Stages order by total latency")
    nbL = 1
    for lQuery in select_array("use sys;select substring(event_name,7), format_time(ROUND(SUM(total_latency),1)) AS total_latency from sys.host_summary_by_stages GROUP BY substring(event_name,7) ORDER BY total_latency DESC;"):
        info_msg = f" +-- {nbL}: {lQuery}"
        infoprint(info_msg)
        nbL += 1
    if nbL == 1:
        infoprint("No information found or indicators desactivated.")
    
    # Top Stages order by avg latency
    subheaderprint("Performance schema: Top Stages order by avg latency")
    nbL = 1
    for lQuery in select_array("use sys;select substring(event_name,7), MAX(avg_latency) as avg_latency from sys.host_summary_by_stages GROUP BY substring(event_name,7) ORDER BY avg_latency DESC;"):
        info_msg = f" +-- {nbL}: {lQuery}"
        infoprint(info_msg)
        nbL += 1
    if nbL == 1:
        infoprint("No information found or indicators desactivated.")
    
    # Top host per table scans
    subheaderprint("Performance schema: Top 5 host per table scans")
    nbL = 1
    for lQuery in select_array("select host, table_scans from sys.host_summary order by table_scans desc LIMIT 5"):
        info_msg = f" +-- {nbL}: {lQuery}"
        infoprint(info_msg)
        nbL += 1
    if nbL == 1:
        infoprint("No information found or indicators desactivated.")
    
    # InnoDB Buffer Pool by schema
    subheaderprint("Performance schema: InnoDB Buffer Pool by schema")
    nbL = 1
    for lQuery in select_array("select object_schema, allocated, data, pages from sys.innodb_buffer_stats_by_schema ORDER BY pages DESC"):
        info_msg = f" +-- {nbL}: {lQuery} page(s)"
        infoprint(info_msg)
        nbL += 1
    if nbL == 1:
        infoprint("No information found or indicators desactivated.")
    
    # InnoDB Buffer Pool by table
    subheaderprint("Performance schema: InnoDB Buffer Pool by table")
    nbL = 1
    for lQuery in select_array("select CONCAT(object_schema,CONCAT('.', object_name)), allocated,data, pages from sys.innodb_buffer_stats_by_table ORDER BY pages DESC"):
        info_msg = f" +-- {nbL}: {lQuery} page(s)"
        infoprint(info_msg)
        nbL += 1
    if nbL == 1:
        infoprint("No information found or indicators desactivated.")
    
    # Process per allocated memory
    subheaderprint("Performance schema: Process per allocated memory")
    nbL = 1
    for lQuery in select_array("select concat(user,concat('/', IFNULL(Command,'NONE'))) AS PROC, current_memory from sys.processlist ORDER BY current_memory DESC;"):
        info_msg = f" +-- {nbL}: {lQuery}"
        infoprint(info_msg)
        nbL += 1
    if nbL == 1:
        infoprint("No information found or indicators desactivated.")
    
    # InnoDB Lock Waits
    subheaderprint("Performance schema: InnoDB Lock Waits")
    nbL = 1
    for lQuery in select_array("use sys;select wait_age_secs, locked_table, locked_type, waiting_query from innodb_lock_waits order by wait_age_secs DESC;"):
        info_msg = f" +-- {nbL}: {lQuery}"
        infoprint(info_msg)
        nbL += 1
    if nbL == 1:
        infoprint("No information found or indicators desactivated.")
    
    # Threads IO Latency
    subheaderprint("Performance schema: Thread IO Latency")
    nbL = 1
    for lQuery in select_array("use sys;select user, total_latency, max_latency from io_by_thread_by_latency order by total_latency;"):
        info_msg = f" +-- {nbL}: {lQuery}"
        infoprint(info_msg)
        nbL += 1
    if nbL == 1:
        infoprint("No information found or indicators desactivated.")
    
    # High Cost SQL statements
    subheaderprint("Performance schema: Top 5 Most latency statements")
    nbL = 1
    for lQuery in select_array("select query, avg_latency from sys.statement_analysis order by avg_latency desc LIMIT 5"):
        info_msg = f" +-- {nbL}: {lQuery}"
        infoprint(info_msg)
        nbL += 1
    if nbL == 1:
        infoprint("No information found or indicators desactivated.")
    
    # Top 5% slower queries
    subheaderprint("Performance schema: Top 5 slower queries")
    nbL = 1
    for lQuery in select_array("select query, exec_count from sys.statements_with_runtimes_in_95th_percentile order by exec_count desc LIMIT 5"):
        info_msg = f" +-- {nbL}: {lQuery} s"
        infoprint(info_msg)
        nbL += 1
    if nbL == 1:
        infoprint("No information found or indicators desactivated.")
    
    # Top 10 nb statement type
    subheaderprint("Performance schema: Top 10 nb statement type")
    nbL = 1
    for lQuery in select_array("use sys;select statement, sum(total) as total from host_summary_by_statement_type group by statement order by total desc LIMIT 10;"):
        info_msg = f" +-- {nbL}: {lQuery}"
        infoprint(info_msg)
        nbL += 1
    if nbL == 1:
        infoprint("No information found or indicators desactivated.")
    
    # Top statement by total latency
    subheaderprint("Performance schema: Top statement by total latency")
    nbL = 1
    for lQuery in select_array("use sys;select statement, sum(total_latency) as total from sys.host_summary_by_statement_type group by statement order by total desc LIMIT 10;"):
        info_msg = f" +-- {nbL}: {lQuery}"
        infoprint(info_msg)
        nbL += 1
    if nbL == 1:
        infoprint("No information found or indicators desactivated.")
    
    # Top statement by lock latency
    subheaderprint("Performance schema: Top statement by lock latency")
    nbL = 1
    for lQuery in select_array("use sys;select statement, sum(lock_latency) as total from sys.host_summary_by_statement_type group by statement order by total desc LIMIT 10;"):
        info_msg = f" +-- {nbL}: {lQuery}"
        infoprint(info_msg)
        nbL += 1
    if nbL == 1:
        infoprint("No information found or indicators desactivated.")
    
    # Top statement by full scans
    subheaderprint("Performance schema: Top statement by full scans")
    nbL = 1
    for lQuery in select_array("use sys;select statement, sum(full_scans) as total from sys.host_summary_by_statement_type group by statement order by total desc LIMIT 10;"):
        info_msg = f" +-- {nbL}: {lQuery}"
        infoprint(info_msg)
        nbL += 1
    if nbL == 1:
        infoprint("No information found or indicators desactivated.")
    
    # Top statement by rows sent
    subheaderprint("Performance schema: Top statement by rows sent")
    nbL = 1
    for lQuery in select_array("use sys;select statement, sum(rows_sent) as total from sys.host_summary_by_statement_type group by statement order by total desc LIMIT 10;"):
        info_msg = f" +-- {nbL}: {lQuery}"
        infoprint(info_msg)
        nbL += 1
    if nbL == 1:
        infoprint("No information found or indicators desactivated.")
    
    # Top statement by rows modified
    subheaderprint("Performance schema: Top statement by rows modified")
    nbL = 1
    for lQuery in select_array("use sys;select statement, sum(rows_affected) as total from sys.host_summary_by_statement_type group by statement order by total desc LIMIT 10;"):
        info_msg = f" +-- {nbL}: {lQuery}"
        infoprint(info_msg)
        nbL += 1
    if nbL == 1:
        infoprint("No information found or indicators desactivated.")
    
    # Use temporary tables
    subheaderprint("Performance schema: Some queries using temp table")
    nbL = 1
    for lQuery in select_array("use sys;select query from sys.statements_with_temp_tables LIMIT 20"):
        info_msg = f" +-- {nbL}: {lQuery}"
        infoprint(info_msg)
        nbL += 1
    if nbL == 1:
        infoprint("No information found or indicators desactivated.")
    
    # Unused Indexes
    subheaderprint("Performance schema: Unused indexes")
    nbL = 1
    for lQuery in select_array("select * from sys.schema_unused_indexes"):
        info_msg = f" +-- {nbL}: {lQuery}"
        infoprint(info_msg)
        nbL += 1
    if nbL == 1:
        infoprint("No information found or indicators desactivated.")
    
    # Full table scans
    subheaderprint("Performance schema: Tables with full table scans")
    nbL = 1
    for lQuery in select_array("select * from sys.schema_tables_with_full_table_scans order by rows_full_scanned DESC"):
        info_msg = f" +-- {nbL}: {lQuery}"
        infoprint(info_msg)
        nbL += 1
    if nbL == 1:
        infoprint("No information found or indicators desactivated.")
    
    # Latest file IO by latency
    subheaderprint("Performance schema: Latest FILE IO by latency")
    nbL = 1
    for lQuery in select_array("use sys;select thread, file, latency, operation from latest_file_io ORDER BY latency LIMIT 10;"):
        info_msg = f" +-- {nbL}: {lQuery}"
        infoprint(info_msg)
        nbL += 1
    if nbL == 1:
        infoprint("No information found or indicators desactivated.")
    
    # FILE by IO read bytes
    subheaderprint("Performance schema: FILE by IO read bytes")
    nbL = 1
    for lQuery in select_array("use sys;(select file, total_read from io_global_by_file_by_bytes where total_read like '%MiB' order by total_read DESC) UNION (select file, total_read from io_global_by_file_by_bytes where total_read like '%KiB' order by total_read DESC LIMIT 15);"):
        info_msg = f" +-- {nbL}: {lQuery}"
        infoprint(info_msg)
        nbL += 1
    if nbL == 1:
        infoprint("No information found or indicators desactivated.")
    
    # FILE by IO written bytes
    subheaderprint("Performance schema: FILE by IO read bytes")
    nbL = 1
    for lQuery in select_array("use sys;(select file, total_written from io_global_by_file_by_bytes where total_written like '%MiB' order by total_written DESC) UNION (select file, total_written from io_global_by_file_by_bytes where total_written like '%KiB' order by total_written DESC LIMIT 15);"):
        info_msg = f" +-- {nbL}: {lQuery}"
        infoprint(info_msg)
        nbL += 1
    if nbL == 1:
        infoprint("No information found or indicators desactivated.")
    
    # file per IO total latency
    subheaderprint("Performance schema: file per IO total latency")
    nbL = 1
    for lQuery in select_array("use sys;select file, total_latency from io_global_by_file_by_latency ORDER BY total_latency DESC LIMIT 20;"):
        info_msg = f" +-- {nbL}: {lQuery}"
        infoprint(info_msg)
        nbL += 1
    if nbL == 1:
        infoprint("No information found or indicators desactivated.")
    
    # file per IO read latency
    subheaderprint("Performance schema: file per IO read latency")
    nbL = 1
    for lQuery in select_array("use sys;select file, read_latency from io_global_by_file_by_latency ORDER BY read_latency DESC LIMIT 20;"):
        info_msg = f" +-- {nbL}: {lQuery}"
        infoprint(info_msg)
        nbL += 1
    if nbL == 1:
        infoprint("No information found or indicators desactivated.")
    
    # file per IO write latency
    subheaderprint("Performance schema: file per IO write latency")
    nbL = 1
    for lQuery in select_array("use sys;select file, write_latency from io_global_by_file_by_latency ORDER BY write_latency DESC LIMIT 20;"):
        info_msg = f" +-- {nbL}: {lQuery}"
        infoprint(info_msg)
        nbL += 1
    if nbL == 1:
        infoprint("No information found or indicators desactivated.")
    
    # Event Wait by read bytes
    subheaderprint("Performance schema: Event Wait by read bytes")
    nbL = 1
    for lQuery in select_array("use sys;(select event_name, total_read from io_global_by_wait_by_bytes where total_read like '%MiB' order by total_read DESC) UNION (select event_name, total_read from io_global_by_wait_by_bytes where total_read like '%KiB' order by total_read DESC LIMIT 15);"):
        info_msg = f" +-- {nbL}: {lQuery}"
        infoprint(info_msg)
        nbL += 1
    if nbL == 1:
        infoprint("No information found or indicators desactivated.")
    
    # Event Wait by write bytes
    subheaderprint("Performance schema: Event Wait by read bytes")
    nbL = 1
    for lQuery in select_array("use sys;(select event_name, total_written from io_global_by_wait_by_bytes where total_written like '%MiB' order by total_written DESC) UNION (select event_name, total_written from io_global_by_wait_by_bytes where total_written like '%KiB' order by total_written DESC LIMIT 15);"):
        info_msg = f" +-- {nbL}: {lQuery}"
        infoprint(info_msg)
        nbL += 1
    if nbL == 1:
        infoprint("No information found or indicators desactivated.")
    
    # event per wait total latency
    subheaderprint("Performance schema: event per wait total latency")
    nbL = 1
    for lQuery in select_array("use sys;select event_name, total_latency from io_global_by_wait_by_latency ORDER BY total_latency DESC LIMIT 20;"):
        info_msg = f" +-- {nbL}: {lQuery}"
        infoprint(info_msg)
        nbL += 1
    if nbL == 1:
        infoprint("No information found or indicators desactivated.")
    
    # event per wait read latency
    subheaderprint("Performance schema: event per wait read latency")
    nbL = 1
    for lQuery in select_array("use sys;select event_name, read_latency from io_global_by_wait_by_latency ORDER BY read_latency DESC LIMIT 20;"):
        info_msg = f" +-- {nbL}: {lQuery}"
        infoprint(info_msg)
        nbL += 1
    if nbL == 1:
        infoprint("No information found or indicators desactivated.")
    
    # event per wait write latency
    subheaderprint("Performance schema: event per wait read latency")
    nbL = 1
    for lQuery in select_array("use sys;select event_name, write_latency from io_global_by_wait_by_latency ORDER BY write_latency DESC LIMIT 20;"):
        info_msg = f" +-- {nbL}: {lQuery}"
        infoprint(info_msg)
        nbL += 1
    if nbL == 1:
        infoprint("No information found or indicators desactivated.")
    
    #schema_index_statistics
    # TOP 15 most read index
    subheaderprint("Performance schema: TOP 15 most read indexes")
    nbL = 1
    for lQuery in select_array("use sys;select table_schema, table_name,index_name, rows_selected from schema_index_statistics ORDER BY ROWs_selected DESC LIMIT 15;"):
        info_msg = f" +-- {nbL}: {lQuery}"
        infoprint(info_msg)
        nbL += 1
    if nbL == 1:
        infoprint("No information found or indicators desactivated.")
    
    # TOP 15 most used index
    subheaderprint("Performance schema: TOP 15 most modified indexes")
    nbL = 1
    for lQuery in select_array("use sys;select table_schema, table_name,index_name, rows_inserted+rows_updated+rows_deleted AS changes from schema_index_statistics ORDER BY rows_inserted+rows_updated+rows_deleted DESC LIMIT 15;"):
        info_msg = f" +-- {nbL}: {lQuery}"
        infoprint(info_msg)
        nbL += 1
    if nbL == 1:
        infoprint("No information found or indicators desactivated.")
    
    # TOP 15 high read latency index
    subheaderprint("Performance schema: TOP 15 high read latency index")
    nbL = 1
    for lQuery in select_array("use sys;select table_schema, table_name,index_name, select_latency from schema_index_statistics ORDER BY select_latency DESC LIMIT 15;"):
        info_msg = f" +-- {nbL}: {lQuery}"
        infoprint(info_msg)
        nbL += 1
    if nbL == 1:
        infoprint("No information found or indicators desactivated.")
    
    # TOP 15 high insert latency index
    subheaderprint("Performance schema: TOP 15 most modified indexes")
    nbL = 1
    for lQuery in select_array("use sys;select table_schema, table_name,index_name, insert_latency from schema_index_statistics ORDER BY insert_latency DESC LIMIT 15;"):
        info_msg = f" +-- {nbL}: {lQuery}"
        infoprint(info_msg)
        nbL += 1
    if nbL == 1:
        infoprint("No information found or indicators desactivated.")
    
    # TOP 15 high update latency index
    subheaderprint("Performance schema: TOP 15 high update latency index")
    nbL = 1
    for lQuery in select_array("use sys;select table_schema, table_name,index_name, update_latency from schema_index_statistics ORDER BY update_latency DESC LIMIT 15;"):
        info_msg = f" +-- {nbL}: {lQuery}"
        infoprint(info_msg)
        nbL += 1
    if nbL == 1:
        infoprint("No information found or indicators desactivated.")
    
    # TOP 15 high delete latency index
    subheaderprint("Performance schema: TOP 15 high delete latency index")
    nbL = 1
    for lQuery in select_array("use sys;select table_schema, table_name,index_name, delete_latency from schema_index_statistics ORDER BY delete_latency DESC LIMIT 15;"):
        info_msg = f" +-- {nbL}: {lQuery}"
        infoprint(info_msg)
        nbL += 1
    if nbL == 1:
        infoprint("No information found or indicators desactivated.")
    
    # TOP 15 most read tables
    subheaderprint("Performance schema: TOP 15 most read tables")
    nbL = 1
    for lQuery in select_array("use sys;select table_schema, table_name, rows_fetched from schema_table_statistics ORDER BY ROWs_fetched DESC LIMIT 15;"):
        info_msg = f" +-- {nbL}: {lQuery}"
        infoprint(info_msg)
        nbL += 1
    if nbL == 1:
        infoprint("No information found or indicators desactivated.")
    
    # TOP 15 most used tables
    subheaderprint("Performance schema: TOP 15 most modified tables")
    nbL = 1
    for lQuery in select_array("use sys;select table_schema, table_name, rows_inserted+rows_updated+rows_deleted AS changes from schema_table_statistics ORDER BY rows_inserted+rows_updated+rows_deleted DESC LIMIT 15;"):
        info_msg = f" +-- {nbL}: {lQuery}"
        infoprint(info_msg)
        nbL += 1
    if nbL == 1:
        infoprint("No information found or indicators desactivated.")
    
    # TOP 15 high read latency tables
    subheaderprint("Performance schema: TOP 15 high read latency tables")
    nbL = 1
    for lQuery in select_array("use sys;select table_schema, table_name, fetch_latency from schema_table_statistics ORDER BY fetch_latency DESC LIMIT 15;"):
        info_msg = f" +-- {nbL}: {lQuery}"
        infoprint(info_msg)
        nbL += 1
    if nbL == 1:
        infoprint("No information found or indicators desactivated.")
    
    # TOP 15 high insert latency tables
    subheaderprint("Performance schema: TOP 15 high insert latency tables")
    nbL = 1
    for lQuery in select_array("use sys;select table_schema, table_name, insert_latency from schema_table_statistics ORDER BY insert_latency DESC LIMIT 15;"):
        info_msg = f" +-- {nbL}: {lQuery}"
        infoprint(info_msg)
        nbL += 1
    if nbL == 1:
        infoprint("No information found or indicators desactivated.")
    
    # TOP 15 high update latency tables
    subheaderprint("Performance schema: TOP 15 high update latency tables")
    nbL = 1
    for lQuery in select_array("use sys;select table_schema, table_name, update_latency from schema_table_statistics ORDER BY update_latency DESC LIMIT 15;"):
        info_msg = f" +-- {nbL}: {lQuery}"
        infoprint(info_msg)
        nbL += 1
    if nbL == 1:
        infoprint("No information found or indicators desactivated.")
    
    # TOP 15 high delete latency tables
    subheaderprint("Performance schema: TOP 15 high delete latency tables")
    nbL = 1
    for lQuery in select_array("use sys;select table_schema, table_name, delete_latency from schema_table_statistics ORDER BY delete_latency DESC LIMIT 15;"):
        info_msg = f" +-- {nbL}: {lQuery}"
        infoprint(info_msg)
        nbL += 1
    if nbL == 1:
        infoprint("No information found or indicators desactivated.")
    
    # Redundant indexes
    subheaderprint("Performance schema: Redundant indexes")
    nbL = 1
    for lQuery in select_array("use sys;select * from schema_redundant_indexes;"):
        info_msg = f" +-- {nbL}: {lQuery}"
        infoprint(info_msg)
        nbL += 1
    if nbL == 1:
        infoprint("No information found or indicators desactivated.")
    
    subheaderprint("Performance schema: Tables not using InnoDB buffer")
    nbL = 1
    for lQuery in select_array("' Select table_schema, table_name from sys.schema_table_statistics_with_buffer where innodb_buffer_allocated IS NULL;"):
        info_msg = f" +-- {nbL}: {lQuery}"
        infoprint(info_msg)
        nbL += 1
    if nbL == 1:
        infoprint("No information found or indicators desactivated.")
    
    #redundant? idk
    subheaderprint("Performance schema: Table not using InnoDB buffer")
    nbL = 1
    for lQuery in select_array("' Select table_schema, table_name from sys.schema_table_statistics_with_buffer where innodb_buffer_allocated IS NULL;"):
        info_msg = f" +-- {nbL}: {lQuery}"
        infoprint(info_msg)
        nbL += 1
    if nbL == 1:
        infoprint("No information found or indicators desactivated.")
    
    subheaderprint("Performance schema: Top 15 Tables using InnoDB buffer")
    nbL = 1
    for lQuery in select_array("select table_schema,table_name,innodb_buffer_allocated from sys.schema_table_statistics_with_buffer where innodb_buffer_allocated IS NOT NULL ORDER BY innodb_buffer_allocated DESC LIMIT 15;"):
        info_msg = f" +-- {nbL}: {lQuery}"
        infoprint(info_msg)
        nbL += 1
    if nbL == 1:
        infoprint("No information found or indicators desactivated.")
    
    subheaderprint("Performance schema: Top 15 Tables with InnoDB buffer free")
    nbL = 1
    for lQuery in select_array("select table_schema,table_name,innodb_buffer_free from sys.schema_table_statistics_with_buffer where innodb_buffer_allocated IS NOT NULL ORDER BY innodb_buffer_free DESC LIMIT 15;"):
        info_msg = f" +-- {nbL}: {lQuery}"
        infoprint(info_msg)
        nbL += 1
    if nbL == 1:
        infoprint("No information found or indicators desactivated.")
    
    subheaderprint("Performance schema: Top 15 Most executed queries")
    nbL = 1
    for lQuery in select_array("select db, query, exec_count from sys.statement_analysis order by exec_count DESC LIMIT 15;"):
        info_msg = f" +-- {nbL}: {lQuery}"
        infoprint(info_msg)
        nbL += 1
    if nbL == 1:
        infoprint("No information found or indicators desactivated.")
    
    subheaderprint("Performance schema: Latest SQL queries in errors or warnings")
    nbL = 1
    for lQuery in select_array("select query, last_seen from sys.statements_with_errors_or_warnings ORDER BY last_seen LIMIT 100;"):
        info_msg = f" +-- {nbL}: {lQuery}"
        infoprint(info_msg)
        nbL += 1
    if nbL == 1:
        infoprint("No information found or indicators desactivated.")
    
    subheaderprint("Performance schema: Top 20 queries with full table scans")
    nbL = 1
    for lQuery in select_array("select db, query, exec_count from sys.statements_with_full_table_scans order BY exec_count DESC LIMIT 20;"):
        info_msg = f" +-- {nbL}: {lQuery}"
        infoprint(info_msg)
        nbL += 1
    if nbL == 1:
        infoprint("No information found or indicators desactivated.")
    
    subheaderprint("Performance schema: Last 50 queries with full table scans")
    nbL = 1
    for lQuery in select_array("select db, query, last_seen from sys.statements_with_full_table_scans order BY last_seen DESC LIMIT 50;"):
        info_msg = f" +-- {nbL}: {lQuery}"
        infoprint(info_msg)
        nbL += 1
    if nbL == 1:
        infoprint("No information found or indicators desactivated.")
    
    subheaderprint("Performance schema: TOP 15 reader queries (95% percentile)")
    nbL = 1
    for lQuery in select_array("use sys;select db, query , rows_sent from statements_with_runtimes_in_95th_percentile ORDER BY ROWs_sent DESC LIMIT 15;"):
        info_msg = f" +-- {nbL}: {lQuery}"
        infoprint(info_msg)
        nbL += 1
    if nbL == 1:
        infoprint("No information found or indicators desactivated.")
    
    subheaderprint("Performance schema: TOP 15 most row look queries (95% percentile)")
    nbL = 1
    for lQuery in select_array("use sys;select db, query, rows_examined AS search from statements_with_runtimes_in_95th_percentile ORDER BY rows_examined DESC LIMIT 15;"):
        info_msg = f" +-- {nbL}: {lQuery}"
        infoprint(info_msg)
        nbL += 1
    if nbL == 1:
        infoprint("No information found or indicators desactivated.")
    
    subheaderprint("Performance schema: TOP 15 total latency queries (95% percentile)")
    nbL = 1
    for lQuery in select_array("use sys;select db, query, total_latency AS search from statements_with_runtimes_in_95th_percentile ORDER BY total_latency DESC LIMIT 15;"):
        info_msg = f" +-- {nbL}: {lQuery}"
        infoprint(info_msg)
        nbL += 1
    if nbL == 1:
        infoprint("No information found or indicators desactivated.")
    
    subheaderprint("Performance schema: TOP 15 max latency queries (95% percentile)")
    nbL = 1
    for lQuery in select_array("use sys;select db, query, max_latency AS search from statements_with_runtimes_in_95th_percentile ORDER BY max_latency DESC LIMIT 15;"):
        info_msg = f" +-- {nbL}: {lQuery}"
        infoprint(info_msg)
        nbL += 1
    if nbL == 1:
        infoprint("No information found or indicators desactivated.")
    
    subheaderprint("Performance schema: TOP 15 average latency queries (95% percentile)")
    nbL = 1
    for lQuery in select_array("use sys;select db, query, avg_latency AS search from statements_with_runtimes_in_95th_percentile ORDER BY avg_latency DESC LIMIT 15;"):
        info_msg = f" +-- {nbL}: {lQuery}"
        infoprint(info_msg)
        nbL += 1
    if nbL == 1:
        infoprint("No information found or indicators desactivated.")
    
    subheaderprint("Performance schema: Top 20 queries with sort")
    nbL = 1
    for lQuery in select_array("select db, query, exec_count from sys.statements_with_sorting order BY exec_count DESC LIMIT 20;"):
        info_msg = f" +-- {nbL}: {lQuery}"
        infoprint(info_msg)
        nbL += 1
    if nbL == 1:
        infoprint("No information found or indicators desactivated.")
    
    subheaderprint("Performance schema: Last 50 queries with sort")
    nbL = 1
    for lQuery in select_array("select db, query, last_seen from sys.statements_with_sorting order BY last_seen DESC LIMIT 50;"):
        info_msg = f" +-- {nbL}: {lQuery}"
        infoprint(info_msg)
        nbL += 1
    if nbL == 1:
        infoprint("No information found or indicators desactivated.")
    
    subheaderprint("Performance schema: TOP 15 row sorting queries with sort")
    nbL = 1
    for lQuery in select_array("use sys;select db, query , rows_sorted from statements_with_sorting ORDER BY ROWs_sorted DESC LIMIT 15;"):
        info_msg = f" +-- {nbL}: {lQuery}"
        infoprint(info_msg)
        nbL += 1
    if nbL == 1:
        infoprint("No information found or indicators desactivated.")
    
    subheaderprint("Performance schema: TOP 15 total latency queries with sort")
    nbL = 1
    for lQuery in select_array("use sys;select db, query, total_latency AS search from statements_with_sorting ORDER BY total_latency DESC LIMIT 15;"):
        info_msg = f" +-- {nbL}: {lQuery}"
        infoprint(info_msg)
        nbL += 1
    if nbL == 1:
        infoprint("No information found or indicators desactivated.")
    
    subheaderprint("Performance schema: TOP 15 merge queries with sort")
    nbL = 1
    for lQuery in select_array("use sys;select db, query, sort_merge_passes AS search from statements_with_sorting ORDER BY sort_merge_passes DESC LIMIT 15;"):
        info_msg = f" +-- {nbL}: {lQuery}"
        infoprint(info_msg)
        nbL += 1
    if nbL == 1:
        infoprint("No information found or indicators desactivated.")
    
    subheaderprint("Performance schema: TOP 15 average sort merges queries with sort")
    nbL = 1
    for lQuery in select_array("use sys;select db, query, avg_sort_merges AS search from statements_with_sorting ORDER BY avg_sort_merges DESC LIMIT 15;"):
        info_msg = f" +-- {nbL}: {lQuery}"
        infoprint(info_msg)
        nbL += 1
    if nbL == 1:
        infoprint("No information found or indicators desactivated.")
        
    subheaderprint("Performance schema: TOP 15 scans queries with sort")
    nbL = 1
    for lQuery in select_array("use sys;select db, query, sorts_using_scans AS search from statements_with_sorting ORDER BY sorts_using_scans DESC LIMIT 15;"):
        info_msg = f" +-- {nbL}: {lQuery}"
        infoprint(info_msg)
        nbL += 1
    if nbL == 1:
        infoprint("No information found or indicators desactivated.")
    
    subheaderprint("Performance schema: TOP 15 range queries with sort")
    nbL = 1
    for lQuery in select_array("use sys;select db, query, sort_using_range AS search from statements_with_sorting ORDER BY sort_using_range DESC LIMIT 15;"):
        info_msg = f" +-- {nbL}: {lQuery}"
        infoprint(info_msg)
        nbL += 1
    if nbL == 1:
        infoprint("No information found or indicators desactivated.")
    
    ##################################################################################

    #statements_with_temp_tables
    
    #mysql> desc statements_with_temp_tables;
    #+--------------------------+---------------------+------+-----+---------------------+-------+
    #| Field                    | Type                | Null | Key | Default             | Extra |
    #+--------------------------+---------------------+------+-----+---------------------+-------+
    #| query                    | longtext            | YES  |     | NULL                |       |
    #| db                       | varchar(64)         | YES  |     | NULL                |       |
    #| exec_count               | bigint(20) unsigned | NO   |     | NULL                |       |
    #| total_latency            | text                | YES  |     | NULL                |       |
    #| memory_tmp_tables        | bigint(20) unsigned | NO   |     | NULL                |       |
    #| disk_tmp_tables          | bigint(20) unsigned | NO   |     | NULL                |       |
    #| avg_tmp_tables_per_query | decimal(21,0)       | NO   |     | 0                   |       |
    #| tmp_tables_to_disk_pct   | decimal(24,0)       | NO   |     | 0                   |       |
    #| first_seen               | timestamp           | NO   |     | 0000-00-00 00:00:00 |       |
    #| last_seen                | timestamp           | NO   |     | 0000-00-00 00:00:00 |       |
    #| digest                   | varchar(32)         | YES  |     | NULL                |       |
    #+--------------------------+---------------------+------+-----+---------------------+-------+
    #11 rows in set (0,01 sec)#
    #
    
    subheaderprint("Performance schema: Top 20 queries with temp table")
    nbL = 1
    for lQuery in select_array("select db, query, exec_count from sys.statements_with_temp_tables order BY exec_count DESC LIMIT 20;"):
        info_msg = f" +-- {nbL}: {lQuery}"
        infoprint(info_msg)
        nbL += 1
    if nbL == 1:
        infoprint("No information found or indicators desactivated.")
    
    subheaderprint("Performance schema: Last 50 queries with temp table")
    nbL = 1
    for lQuery in select_array("select db, query, last_seen from sys.statements_with_temp_tables order BY last_seen DESC LIMIT 50;"):
        info_msg = f" +-- {nbL}: {lQuery}"
        infoprint(info_msg)
        nbL += 1
    if nbL == 1:
        infoprint("No information found or indicators desactivated.")
    
    subheaderprint("Performance schema: TOP 15 total latency queries with temp table")
    nbL = 1
    for lQuery in select_array("use sys;select db, query, total_latency AS search from statements_with_temp_tables ORDER BY total_latency DESC LIMIT 15;"):
        info_msg = f" +-- {nbL}: {lQuery}"
        infoprint(info_msg)
        nbL += 1
    if nbL == 1:
        infoprint("No information found or indicators desactivated.")
    
    subheaderprint("Performance schema: TOP 15 queries with temp table to disk")
    nbL = 1
    for lQuery in select_array("use sys;select db, query, disk_tmp_tables from statements_with_temp_tables ORDER BY disk_tmp_tables DESC LIMIT 15;"):
        info_msg = f" +-- {nbL}: {lQuery}"
        infoprint(info_msg)
        nbL += 1
    if nbL == 1:
        infoprint("No information found or indicators desactivated.")
    
    ##################################################################################
    #wait_classes_global_by_latency

    #mysql> select * from wait_classes_global_by_latency;
    #-----------------+-------+---------------+-------------+-------------+-------------+
    # event_class     | total | total_latency | min_latency | avg_latency | max_latency |
    #-----------------+-------+---------------+-------------+-------------+-------------+
    # wait/io/file    | 15381 | 1.23 s        | 0 ps        | 80.12 us    | 230.64 ms   |
    # wait/io/table   |    59 | 7.57 ms       | 5.45 us     | 128.24 us   | 3.95 ms     |
    # wait/lock/table |    69 | 3.22 ms       | 658.84 ns   | 46.64 us    | 1.10 ms     |
    #-----------------+-------+---------------+-------------+-------------+-------------+
    # rows in set (0,00 sec)
    
    subheaderprint("Performance schema: TOP 15 class events by number")
    nbL = 1
    for lQuery in select_array("use sys;select event_class, total from wait_classes_global_by_latency ORDER BY total DESC LIMIT 15;"):
        info_msg = f" +-- {nbL}: {lQuery}"
        infoprint(info_msg)
        nbL += 1
    if nbL == 1:
        infoprint("No information found or indicators desactivated.")
    
    subheaderprint("Performance schema: TOP 30 events by number")
    nbL = 1
    for lQuery in select_array("use sys;select events, total from waits_global_by_latency ORDER BY total DESC LIMIT 30;"):
        info_msg = f" +-- {nbL}: {lQuery}"
        infoprint(info_msg)
        nbL += 1
    if nbL == 1:
        infoprint("No information found or indicators desactivated.")
    
    subheaderprint("Performance schema: TOP 15 class events by total latency")
    nbL = 1
    for lQuery in select_array("use sys;select event_class, total_latency from wait_classes_global_by_latency ORDER BY total_latency DESC LIMIT 15;"):
        info_msg = f" +-- {nbL}: {lQuery}"
        infoprint(info_msg)
        nbL += 1
    if nbL == 1:
        infoprint("No information found or indicators desactivated.")
    
    subheaderprint("Performance schema: TOP 30 events by total latency")
    nbL = 1
    for lQuery in select_array("use sys;select events, total_latency from waits_global_by_latency ORDER BY total_latency DESC LIMIT 30;"):
        info_msg = f" +-- {nbL}: {lQuery}"
        infoprint(info_msg)
        nbL += 1
    if nbL == 1:
        infoprint("No information found or indicators desactivated.")
    
    subheaderprint("Performance schema: TOP 15 class events by max latency")
    nbL = 1
    for lQuery in select_array("use sys;select event_class, max_latency from wait_classes_global_by_latency ORDER BY max_latency DESC LIMIT 15;"):
        info_msg = f" +-- {nbL}: {lQuery}"
        infoprint(info_msg)
        nbL += 1
    if nbL == 1:
        infoprint("No information found or indicators desactivated.")
    
    subheaderprint("Performance schema: TOP 30 events by max latency")
    nbL = 1
    for lQuery in select_array("use sys;select events, max_latency from waits_global_by_latency ORDER BY max_latency DESC LIMIT 30;"):
        info_msg = f" +-- {nbL}: {lQuery}"
        infoprint(info_msg)
        nbL += 1
    if nbL == 1:
        infoprint("No information found or indicators desactivated.")

# Recommendations for Ariadb
def mariadb_ariadb()
    subhreaderprint("AriaDB Metrics")
    
    # AriaDB
    if not (myvar["have_aria"] and (myvar["have_aria"] == "YES")):
        infoprint("AriaDB is disabled.")
        return
    infoprint("AriaDB is enabled.")
    
    fail_match = r"/^fail$/"
    # Aria pagecache
    if (not mycalc["total_aria_indexes"]) and (doremote == 1):
        generalrec.append("Unable to calculate Aria indexes on remote MySQL server < 5.0.0")
    elif re.match(fail_match, mycalc["total_aria_indexes"]):
        badprint("Cannot calculate Aria index size - re-run script as root user")
    elif mycalc["total_aria_indexes"] == "0":
        badprint("None of your Aria tables are indexed - add indexes immediately")
    else:
        if (myvar["aria_pagecache_buffer_size"] < mycalc["total_aria_indexes"]) and (mycalc["pct_aria_keys_from_mem"] < 95):
            bad_msg = f"Aria pagecache size / total Aria indexes: {hr_bytes(myvar['aria_pagecache_buffer_size'])}/{hr_bytes(mycalc['total_aria_indexes'])}"
            badprint(bad_msg)
            adjvars.append(f"aria_pagecache_buffer_size (> {hr_bytes(mycalc['total_aria_indexes'])})")
        else:
            good_msg = f"Aria pagecache size / total Aria indexes: {hr_bytes(myvar['aria_pagecache_buffer_size'])}/{hr_bytes(mycalc['total_aria_indexes'])}"
            goodprint(bad_msg)
        
        if mystat["Aria_pagecache_read_requests"] < 0:
            if (mycalc["pct_aria_keys_from_mem"] < 95):
                bad_msg = f"Aria pagecache hit rate: {mycalc['pct_aria_keys_from_mem']}% ({hr_num(mystat['Aria_pagecache_read_requests'])} cached /{hr_num(mystat['Aria_pagecache_reads'])} reads"
                badprint(bad_msg)
                adjvars.append(f"aria_pagecache_buffer_size (> {hr_bytes(mycalc['total_aria_indexes'])})")
            else:
                good_msg = f"Aria pagecache hit rate: {mycalc['pct_aria_keys_from_mem']}% ({hr_num(mystat['Aria_pagecache_read_requests'])} cached /{hr_num(mystat['Aria_pagecache_reads'])} reads"
                goodprint(bad_msg)
        else:
            # No queries have run that would use keys

# Recommendations for TokuDB
def mariadb_tokudb()
    subhreaderprint("TokuDB Metrics")
    
    # TokuDB
    if not (myvar["have_tokudb"] and (myvar["have_tokudb"] == "YES")):
        infoprint("TokuDB is disabled.")
        return
    infoprint("TokuDB is enabled.")
    
    # All is to done here

# Recommendations for XtraDB
def mariadb_xtradb()
    subhreaderprint("XtraDB Metrics")
    
    # XtraDB
    if not (myvar["have_xtradb"] and (myvar["have_xtradb"] == "YES")):
        infoprint("XtraDB is disabled.")
        return
    infoprint("XtraDB is enabled.")
    
    # All is to done here

# Recommendations for RocksDB
def mariadb_rockdb()
    subhreaderprint("RocksDB Metrics")
    
    # AriaDB
    if not (myvar["have_rocksdb"] and (myvar["have_rocksdb"] == "YES")):
        infoprint("RocksDB is disabled.")
        return
    infoprint("RocksDB is enabled.")
    
    # All is to done here

# Recommendations for Spider
def mariadb_spider()
    subhreaderprint("Spider Metrics")
    
    # Spider
    if not (myvar["have_spider"] and (myvar["have_spider"] == "YES")):
        infoprint("Spider is disabled.")
        return
    infoprint("Spider is enabled.")
    
    # All is to done here

# Recommendations for Connect
def mariadb_connect()
    subhreaderprint("Connect Metrics")
    
    # AriaDB
    if not (myvar["have_connect"] and (myvar["have_connect"] == "YES")):
        infoprint("Connect is disabled.")
        return
    infoprint("Connect is enabled.")
    
    # All is to done here

# Perl trim function to remove whitespace from the start and end of the string
def trim(string):
    return string.strip()

def get_wsrep_options()
    if not myvar["wsrep_provider_options"]:
        return []
    galera_options = myvar["wsrep_provider_options"].split(";")
    galera_options = remove_cr(galera_options)
    galera_options = remove_empty(galera_options)
    debugprint(", ".join(galera_options))
    return galera_options

def get_gcache_memory():
    gCacheMem = hr_raw(get_wsrep_option("gcache.size"))
    if not ((gCacheMem) and (gCacheMem != "")):
        return 0
    return gCacheMem

def get_wsrep_option(key):
    if not myvar["wsrep_provider_options"]:
        return ""
    galera_options = get_wsrep_options()
    if len(galera_options) == 0:
        return ""
    memValues = [g_opt for g_opt in galera_options if "key =" in g_opt]
    memValue = memValues[0]
    mem_match = r"s/.*=\s*(.+)$/$1/g"
    if re.match(mem_match, memValue):
        return memValue

# Recommendations for Galera
def mariadb_galera()
    subhreaderprint("Galera Metrics")
    
    # Galera Cluster
    if not (myvar["have_galera"] and (myvar["have_galera"] == "YES")):
        infoprint("Galera is disabled.")
        return
    infoprint("Galera is enabled.")
    
    wsrep_match = r"/^wsrep.*/"
    debugprint("Galera variables:")
    for gvar in myvar.keys():
        if not re.match(wsrep_match, gvar):
            continue
        if gvar == "wsrep_provider_options":
            continue
        debug_msg = f"\t{trim(gvar)} = {myvar[gvar]}"
        debugprint(debug_msg)
    
    debugprint("Galera wsrep provider Options:")
    galera_options = get_wsrep_options()
    result["Galera"]["wsrep_options"] = get_wsrep_options()
    for gpara in galera_options:
        debug_msg = f"\t{trim(gparam)}"
        debugprint(debug_msg)
    
    debugprint("Galera status:")
    for gstatus in mystat.keys():
        if not re.match(wsrep_match, gstatus):
            continue
        debug_msg = f"\t{trim(gstatus)} = {mystat[gstatus]}"
        debugprint(debug_msg)
        result["Galera"]["status"][gstatus] = myvar[gstatus]
    info_msg = f"GCache is using {hr_bytes_rnd(get_wsrep_option('gcache.mem_size'))}"
    infoprint(info_msg)
    
    primaryKeysNbTables = select_array("Select CONCAT(c.table_schema,CONCAT('.', c.table_name)) from information_schema.columns c join information_schema.tables t using (TABLE_SCHEMA, TABLE_NAME) where c.table_schema not in ('mysql', 'information_schema', 'performance_schema') and t.table_type != 'VIEW' group by c.table_schema,c.table_name having sum(if(c.column_key in ('PRI','UNI'), 1,0)) = 0")
    
    if len(primaryKeysNbTables) > 0:
        badprint("Following table(s) don't have primary key:")
        for badtable in primaryKeyNbTables:
            bad_msg = f"\t{badtable}"
            badprint(bad_msg)
    else:
        goodprint("All tables get a primary key")
    
    nonInnoDBTables = select_array("select CONCAT(table_schema,CONCAT('.', table_name)) from information_schema.tables where ENGINE <> 'InnoDB' and table_schema not in ('mysql', 'performance_schema', 'information_schema')")
    
    if len(nonInnoDBTables) > 0:
        badprint("Following table(s) are not InnoDB table:")
        generalrec.append("Ensure that all table(s) are InnoDB tables for Galera replication")
        for badtable in nonInnoDBTables:
            bad_msg = f"\t{badtable}"
            badprint(bad_msg)
    else:
        goodprint("All tables are InnoDB tables")
    
    if myvar["binlog_format"] != "ROW":
        badprint("Binlog format should be in ROW mode.")
        adjvars.append("binlog_format = ROW")
    else:
        goodprint("Binlog format is in ROW mode.")
    
    if myvar["innodb_flush_log_at_trx_commit"] != 0:
        badprint("InnoDB flush log at each commit should be disabled.")
        adjvars.append("innodb_flush_log_at_trx_commit = 0")
    else:
        goodprint("InnoDB flush log at each commit is disabled for Galera.")
    
    info_msg = f"Read consistency mode : {myvar['wsrep_causal_reads']}"
    infoprint(info_msg)
    
    if (myvar["wsrep_cluster_name"]) and (myvar["wsrep_on"] == "ON"):
        goodprint("Galera WsREP is enabled.")
        if (myvar["wsrep_cluster_address"]) and (trim(myvar["wsrep_cluster_address"]) != ""):
            good_msg = f"Galera Cluster address is defined: {myvar['wsrep_cluster_address']}"
            goodprint(good_msg)
            NodesTemp = myvar["wsrep_cluster_address"].split(",")
            nbNodes = NodesTemp
            info_msg = f"There are {nbNodes} nodes in wsrep_cluster_address"
            infoprint(info_msg)
            nbNodesSize = trim(mystat["wsrep_cluster_size"])
            if nbNodesSize in (3, 5):
                good_msg = f"There are {nbNodesSize} nodes in wsrep_cluster_size."
                goodprint(good_msg)
            else:
                bad_msg = f"There are {nbNodesSize} nodes in wsrep_cluster_size. Prefer 3 or 5 nodes architecture."
                badprint(bad_msg)
                generalrec.append("Prefer 3 or 5 nodes architecture.")
            
            # wsrep_cluster_address doesn't include garbd nodes
            if nbNodes > nbNodesSize:
                badprint("All cluster nodes are not detected. wsrep_cluster_size less then node count in wsrep_cluster_address")
            else:
                goodprint("All cluster nodes detected.")
        else:
            badprint("Galera Cluster address is undefined")
            adjvars.append("set up wsrep_cluster_address variable for Galera replication")
        if (myvar["wsrep_cluster_name"]) and (trim(myvar["wsrep_cluster_name"]) != ""):
            good_msg = f"Galera Cluster name is defined : {myvar['wsrep_cluster_name']}"
            goodprint(good_msg)
        else:
            badprint("Galera Cluster name is undefined")
            adjvars.append("set up wsrep_cluster_name variable for Galera replication")
        if (myvar["wsrep_node_name"]) and (trim(myvar["wsrep_node_name"]) != ""):
            good_msg = f"Galera Node name is defined : {myvar['wsrep_node_name']}"
            goodprint(good_msg)
        else:
            badprint("Galera Node name is undefined")
            adjvars.append("set up wsrep_node_name variable for Galera replication")
        if trim(myvar["wsrep_notify_cmd"]) != "":
            goodprint("Galera Notify command is defined.")
        else:
            badprint("Galera Notify command is not defined")
            adjvars.append("set up parameter wsrep_notify_cmd to be notify")
        xtra_match = r"^xtrabackup.*"
        if not re.match(xtra_match, trim(myvar["wsrep_sst_method"])):
            badprint("Galera SST method is not xtrabackup based.")
            adjvars.append("set up parameter wsrep_sst_method to xtrabackup based parameter")
        else:
            goodprint("SST Method is based on xtrabackup.")
        if ((myvar["wsrep_OSU_method"]) and (trim(myvar["wsrep_OSU_method"]) == "TOI")) or ((myvar["wsrep_osu_method"]) and (trim(myvar["wsrep_osu_method"]) == "TOI")):
            goodprint("TOI is default mode for upgrade.")
        else:
            badprint("Schema upgrade are not replicated automatically")
            adjvars.append("set up parameter wsrep_OSU_method to TOI")
        info_msg = f"Max WsRep message : {hr_bytes(myvar['wsrep_max_ws_size']}"
        infoprint(info_msg)
    else:
        badprint("Galera WsREP is disabled")
    
    if (mystat["wsrep_connected"]) and (mystat["wsrep_connected"] == "ON"):
        goodprint("Node is connected")
    else:
        baddprint("Node is disconnected")
    if (mystat["wsrep_ready"]) and (mystat["wsrep_ready"] == "ON"):
        goodprint("Node is ready")
    else:
        baddprint("Node is not ready")
    
    info_msg = f"Cluster status :{mystat['wsrep_cluster_status']}"
    infoprint(info_msg)
    if (mystat["wsrep_cluster_status"]) and (mystat["wsrep_cluster_status"] == "Primary"):
        goodprint("Galera cluster is consistent and ready for operations")
    else:
        badprint("Cluster is not consistent and ready")
    if mystat["wsrep_local_state_uuid"] == mystat["wsrep_cluster_state_uuid"]:
        good_msg = f"Node and whole cluster at the same level: {mystat['wsrep_cluster_state_uuid']}"
        goodprint(good_msg)
    else:
        badprint("Node and whole cluster not the same level")
        info_msg = f"Node    state uuid: {mystat['wsrep_local_state_uuid']}"
        infoprint(info_msg)
        info_msg = f"Cluster state uuid: {mystat['wsrep_cluster_state_uuid']}"
        infoprint(info_msg)
    if mystat["wsrep_local_state_comment"] == "Synced":
        goodprint("Node is synced with whole cluster.")
    else:
        badprint("Node is not synced")
        info_msg = f"Node State : {mystat['wsrep_local_state_comment']}"
        infoprint(info_msg)
    if mystat["wsrep_local_cert_failures"] == 0:
        goodprint("There is no certification failures detected.")
    else:
        bad_msg = f"There is {mystat['wsrep_local_cert_failure']} certification failure(s) detected."
        badprint(bad_msg)
    
    wsrep_galera_match = r"/wsrep_|galera/i"
    for key in mystat.keys():
        if re.match(wsrep_galera_match, key):
            debug_msg = f"WSREP: {key} = {mystat[key]}"
            debugprint(debug_msg)
    debugprint(", ".join(get_wsrep_options()))

# Recommendations for InnoDB
def mysql_innodb()
    subheaderprint("InnoDB Metrics")
    
    # InnoDB
    if not ((myvar["have_innodb"]) and (myvar["have_innodb"] == "YES") and (enginestats["InnoDB"])):
        infoprint("InnoDB is disabled.")
        if mysql_version_ge(5, 5):
            badprint("InnoDB Storage engine is disabled. InnoDB is the default storage engine")
            return
    infoprint("InnoDB is enabled.")
    
    if opt[buffers] != 0:
        infoprint("InnoDB Buffers")
        if myvar["innodb_buffer_pool_size"]:
            info_msg = f" +-- InnoDB Buffer Pool: {hr_bytes(myvar['innodb_buffer_pool_size'])}"
            infoprint(info_msg)
        if myvar["innodb_buffer_pool_instances"]:
            info_msg = f" +-- InnoDB Buffer Pool Instances: {hr_bytes(myvar['innodb_buffer_pool_instances'])}"
            infoprint(info_msg)
        
        if myvar["innodb_buffer_pool_chunk_size"]:
            info_msg = f" +-- InnoDB Buffer Pool Chunk Size: {hr_bytes(myvar['innodb_buffer_pool_chunk_size'])}"
            infoprint(info_msg)
        if myvar["innodb_additional_mem_pool_size"]:
            info_msg = f" +-- InnoDB Additional Mem Pool: {hr_bytes(myvar['innodb_additional_mem_pool_size'])}"
            infoprint(info_msg)
        if myvar["innodb_log_file_size"]:
            info_msg = f" +-- InnoDB Log File Size: {hr_bytes(myvar['innodb_log_file_size'])}({mycalc['innodb_log_size_pct']} % of buffer pool)"
            infoprint(info_msg)
        if myvar["innodb_log_files_in_group"]:
            info_msg = f" +-- InnoDB Log File In Group: {hr_bytes(myvar['innodb_log_files_in_group'])}"
            infoprint(info_msg)
        if myvar["innodb_log_buffer_size"]:
            info_msg = f" +-- InnoDB Log Buffer: {hr_bytes(myvar['innodb_log_buffer_size'])}"
            infoprint(info_msg)
        if myvar["innodb_buffer_pool_pages_free"]:
            info_msg = f" +-- InnoDB Log Buffer Free: {hr_bytes(myvar['innodb_log_buffer_pool_pages_free'])}"
            infoprint(info_msg)
        if myvar["innodb_buffer_pool_pages_total"]:
            info_msg = f" +-- InnoDB Log Buffer Used: {hr_bytes(myvar['innodb_log_buffer_pool_pages_total'])}"
            infoprint(info_msg)
    if myvar["innodb_thread_concurrency"]:
        info_msg = f"InnoDB Thread Concurrency {myvar['innodb_thread_concurrency']}"
        infoprint(info_msg)
    
    # InnoDB Buffer Pull Size
    if myvar["innodb_file_per_Table"] == "ON":
        goodprint("InnoDB File per table is activated")
    else:
        badprint("InnoDB File per table is not activated")
        adjvars.append("innodb_file_per_table=ON")
    
    # InnoDB Buffer Pool Size
    if myvar["innodb_buffer_pool_size"] > enginestats["InnoDB"]:
        good_msg = f"InnoDB buffer pool / data size: {hr_bytes(myvar['innodb_buffer_pool_size'])}/{hr_bytes(enginestats['InnoDB'])}"
        goodprint(good_msg)
    else:
        bad_msg = f"InnoDB buffer pool / data size: {hr_bytes(myvar['innodb_buffer_pool_size'])}/{hr_bytes(enginestats['InnoDB'])}"
        badprint(bad_msg)
        adjvars.append(f"innodb_buffer_pool_size (>= {hr_bytes_rnd(enginestats['InnoDB'])}) if possible.")
    
    if (mycalc["innodb_log_size_pct"] < 20) or (mycalc["innodb_log_size_pct"] > 30):
        bad_msg = f"Ratio InnoDB log file size / InnoDB Buffer pool size ({mycalc['innodb_log_file_pct']} %): {hr_bytes(myvar['innodb_log_file_size'])} * {myvar['innodb_log_files_in_group']}/{hr_bytes(myvar['innodb_buffer_pool_size']} should be equal to 25%"
        badprint(bad_msg)
        adjvars.append(f"innodb_log_file_size * innodb_log_files_in_group should be equals to 1/4 of buffer pool size (={hr_bytes(myvar['innodb_buffer_pool_size'] * myvar['innodb_log_files_in_group'] / 4)}) if possible.")
    else:
        good_msg = f"Ratio InnoDB log file size / InnoDB Buffer pool size ({mycalc['innodb_log_file_pct']} %): {hr_bytes(myvar['innodb_log_file_size'])} * {myvar['innodb_log_files_in_group']}/{hr_bytes(myvar['innodb_buffer_pool_size']} should be equal to 25%"
        goodprint(good_msg)
    
    # InnoDB Buffer Pull Instances (MySQL 5.6.6+)
    if myvar["innodb_buffer_pool_instances"]:
        # Bad Value if > 64
        if myvar["innodb_buffer_pool_instances"] > 64:
            bad_msg = f"InnoDB buffer pool instances: {myvar['innodb_buffer_pool_instances']}"
            badprint(bad_msg)
            adjvars.append("innodb_buffer_pool_instances (<= 64)")
        
        # InnoDB Buffer Pool Size > 1GB
        if myvar["innodb_buffer_pool_size"] > 1 * 1024 **3:
            # InnoDB Buffer Pool Size / 1GB = InnoDB Buffer Pool Instances limited to 64 max.
            #  InnoDB Buffer Pool Size > 64GB
            max_innodb_buffer_pool_instances = int(myvar["innodb_buffer_pool_size"] / ( 1024 ** 3))
            if max_innodb_buffer_pool_instances > 64:
                max_innodb_buffer_pool_instances = 64
            
            if myvar["innodb_buffer_pool_instances"] != max_innodb_buffer_pool_instances:
                bad_msg = f"InnoDB buffer pool instances: {myvar['innodb_buffer_pool_instances']}"
                badprint(bad_msg)
                adjvars.append(f"innodb_buffer_pool_instances(={max_innodb_buffer_pool_instances})")
            else:
                good_msg = f"InnoDB buffer pool instances: {myvar['innodb_buffer_pool_instances']}"
                goodprint(good_msg)
        # InnoDB Buffer Pull Size < 1GB
        else:
            if myvar["innodb_buffer_pool_instances"] != 1:
                badprint("InnoDB buffer pool <= 1G and Innodb_buffer_pool_instances(!=1).")
                adjvars.append("innodb_buffer_pool_instances (=1)")
            else:
                good_msg = f"InnoDB buffer pool instances: {myvar['innodb_buffer_pool_instances']}"
                goodprint(good_msg)
    
    # InnoDB Used Buffer Pool Size vs CHUNK size
    if not myvar["innodb_buffer_pool_chunk_size"]:
        infoprint("InnoDB Buffer Pool Chunk Size not used or defined in your version")
    else:
        info_msg = f"Number of InnoDB Buffer Pool Chunk : {int(myvar['innodb_buffer_pool_size']) / int(myvar['innodb_buffer_pool_chunk_size'])} for {myvar['innodb_buffer_pool_instances']} Buffer Pool Instance(s)"
        infoprint(info_msg)
        
        if (int(myvar['innodb_buffer_pool_size']) % (int(myvar['innodb_buffer_pool_chunk_size']) * int(myvar['innodb_buffer_pool_instances']))) == 0:
            goodprint("Innodb_buffer_pool_size aligned with Innodb_buffer_pool_chunk_size & Innodb_buffer_pool_instances")
        else:
            badprint("Innodb_buffer_pool_size not aligned with Innodb_buffer_pool_chunk_size & Innodb_buffer_pool_instances")
            #adjvars.append("Adjust innodb_buffer_pool_instances, innodb_buffer_pool_chunk_size with innodb_buffer_pool_size")
            adjvars.append("innodb_buffer_pool_size must always be equal to or a multiple of innodb_buffer_pool_chunk_size * innodb_buffer_pool_instances")
    
    # InnoDB Read efficency
    if (mycalc["pct_read_efficiency"]) and (mycalc["pct_read_efficiency"] < 90):
        bad_msg = f"InnoDB Read buffer efficiency: {mycalc['pct_read_efficiency']}% ({mystat['Innodb_buffer_pool_read_requests'] - mystat['Innodb_buffer_pool_reads']} hits / {mystat['Innodb_buffer_pool_read_requests']} total"
        badprint(bad_msg)
    else:
        good_msg = f"InnoDB Read buffer efficiency: {mycalc['pct_read_efficiency']}% ({mystat['Innodb_buffer_pool_read_requests'] - mystat['Innodb_buffer_pool_reads']} hits / {mystat['Innodb_buffer_pool_read_requests']} total"
        goodprint(good_msg)
    
    # InnoDB Write efficency
    if (mycalc["pct_write_efficiency"]) and (mycalc["pct_write_efficiency"] < 90):
        bad_msg = f"InnoDB Write buffer efficiency: {mycalc['pct_write_efficiency']}% ({mystat['Innodb_buffer_pool_write_requests'] - mystat['Innodb_buffer_pool_writes']} hits / {mystat['Innodb_buffer_pool_write_requests']} total"
        badprint(bad_msg)
    else:
        good_msg = f"InnoDB Write buffer efficiency: {mycalc['pct_write_efficiency']}% ({mystat['Innodb_buffer_pool_write_requests'] - mystat['Innodb_buffer_pool_writes']} hits / {mystat['Innodb_buffer_pool_write_requests']} total"
        goodprint(good_msg)
    
    # InnoDB Log Waits
    if (mystat["Innodb_log_waits"]) and (mystat["Innodb_log_waits"] > 0):
        bad_msg = f"InnoDB log waits: {percentage(mystat['Innodb_log_waits'], mystat['Innodb_log_writes'])}% ({mystat['Innodb_log_waits']} waits / {mystat['Innodb_log_writes']} writes)"
        badprint(bad_msg)
        adjvars.append(f"innodb_log_buffer_size (>= {hr_bytes_rnd(myvar['innodb_log_buffer_size'])})")
    else:
        good_msg = f"InnoDB log waits: {percentage(mystat['Innodb_log_waits'], mystat['Innodb_log_writes'])}% ({mystat['Innodb_log_waits']} waits / {mystat['Innodb_log_writes']} writes)"
        goodprint(good_msg)
    
    result["Calculations"] = [mycalc]

# Recommendations for Database metrics
def mysql_databases():
    if opt[dbstat] == 0:
        return 0
    
    subheaderprint("Database Metrics")
    if not mysql_version_ge(5, 5):
        infoprint("Skip Database metrics from information schema missing in this version")
        return
    
    dblist = select_array("SHOW DATABASES;")
    info_msg = f"There is {len(dblist)} Database(s)"
    infoprint(info_msg)
    totaldbinfo = select_one("SELECT SUM(TABLE_ROWS), SUM(DATA_LENGTH), SUM(INDEX_LENGTH) , SUM(DATA_LENGTH+INDEX_LENGTH), COUNT(TABLE_NAME),COUNT(DISTINCT(TABLE_COLLATION)),COUNT(DISTINCT(ENGINE)) FROM information_schema.TABLES WHERE TABLE_SCHEMA NOT IN ( 'mysql' );").split("\s")

    infoprint("All Databases:")
    
    info_msg = f" +-- TABLE : {0 if totaldbinfo[4] == 'NULL' else totaldbinfo[4]}"
    infoprint(info_msg)
    info_msg = f" +-- ROWS  : {0 if totaldbinfo[0] == 'NULL' else totaldbinfo[0]}"
    infoprint(info_msg)
    info_msg = f" +-- DATA  : {hr_bytes(totaldbinfo[1]} ({percentage(totaldbinfo[1], totaldbinfo[3])}%)"
    infoprint(info_msg)
    info_msg = f" +-- INDEX : {hr_bytes(totaldbinfo[2]} ({percentage(totaldbinfo[2], totaldbinfo[3])}%)"
    infoprint(info_msg)
    info_msg = f" +-- SIZE  : {hr_bytes(totaldbinfo[3]}"
    infoprint(info_msg)
    
    info_msg = f" +-- COLLA : {0 if totaldbinfo[5] == 'NULL' else totaldbinfo[5]} ({', '.join(select_array('SELECT DISTINCT(TABLE_COLLATION) FROM information_schema.TABLES;'))})"
    infoprint(info_msg)
    info_msg = f" +-- ENGIN : {0 if totaldbinfo[6] == 'NULL' else totaldbinfo[6]} ({', '.join(select_array('SELECT DDISTINCT(ENGINE) FROM information_schema.TABLES;'))})"
    infoprint(info_msg)
    
    result["Databases"]["All databases"]["Rows"] = 0 if totaldbinfo[0] == 'NULL' else totaldbinfo[0]
    result["Databases"]["All databases"]["Data Size"] = totaldbinfo[1]
    result["Databases"]["All databases"]["Data Pct"] = f"{percentage(totaldbinfo[1], totaldbinfo[3])}%"
    result["Databases"]["All databases"]["Index Size"] = totaldbinfo[2]
    result["Databases"]["All databases"]["Data Pct"] = f"{percentage(totaldbinfo[2], totaldbinfo[3])}%"
    result["Databases"]["All databases"]["Total Size"] = totaldbinfo[3]
    
    if not (opt["silent"] or opt["json"]):
        print("\n")
    for db in dblist:
        db = db.rstrip()
        if db in (
            "information_schema",
            "performance_schema",
            "mysql",
            ""
        ):
            continue
        
        dbinfo = select_one(f"SELECT TABLE_SCHEMA, SUM(TABLE_ROWS), SUM(DATA_LENGTH), SUM(INDEX_LENGTH) , SUM(DATA_LENGTH+INDEX_LENGTH), COUNT(DISTINCT ENGINE),COUNT(TABLE_NAME),COUNT(DISTINCT(TABLE_COLLATION)),COUNT(DISTINCT(ENGINE)) FROM information_schema.TABLES WHERE TABLE_SCHEMA='{db}' GROUP BY TABLE_SCHEMA ORDER BY TABLE_SCHEMA").split("\s")
        if not dbinfo[0]:
            continue
        info_msg = f"Database: {dbinfo[0]}"
        infoprint(info_msg)
        
        info_msg = f" +-- TABLE: {0 if totaldbinfo[6] == 'NULL' else totaldbinfo[6]}"
        infoprint(info_msg)
        info_msg = f" +-- COLL : {0 if totaldbinfo[5] == 'NULL' else totaldbinfo[5]} ({', '.join(select_array('SELECT DISTINCT(TABLE_COLLATION) FROM information_schema.TABLES WHERE TABLE_SCHEMA='{db}';'))})"
        infoprint(info_msg)
        info_msg = f" +-- ROWS : {0 if totaldbinfo[1] == 'NULL' else totaldbinfo[1]}"
        infoprint(info_msg)
        info_msg = f" +-- DATA : {hr_bytes(totaldbinfo[2]} ({percentage(totaldbinfo[2], totaldbinfo[4])}%)"
        infoprint(info_msg)
        info_msg = f" +-- INDEX: {hr_bytes(totaldbinfo[3]} ({percentage(totaldbinfo[3], totaldbinfo[4])}%)"
        infoprint(info_msg)
        info_msg = f" +-- TOTAL: {hr_bytes(totaldbinfo[4]}"
        infoprint(info_msg)
        info_msg = f" +-- ENGIN: {0 if totaldbinfo[8] == 'NULL' else totaldbinfo[8]} ({', '.join(select_array('SELECT DDISTINCT(ENGINE) FROM information_schema.TABLES WHERE TABLE_SCHEMA='{db}';'))})"
        infoprint(info_msg)
        
        if (dbinfo[2] != 'NULL') and (dbinfo[3] != 'NULL') and (dbinfo[2] < dbinfo[3]):
            bad_msg = f"Index size is larger than data size for {dbinfo[0]} \n"
            badprint(bad_msg)
        if dbinfo[5] > 1:
            bad_msg = f"There are {dbinfo[5]} storage engines. Be careful. \n"
            badprint(bad_msg)
        
        result["Databases"][dbinfo[0]]["Rows"] = dbinfo[1]
        result["Databases"][dbinfo[0]]["Table"] = dbinfo[6]
        result["Databases"][dbinfo[0]]["Collations"] = dbinfo[7]
        result["Databases"][dbinfo[0]]]["Data Size"] = dbinfo[2]
        result["Databases"][dbinfo[0]]]["Data Pct"] = f"{percentage(dbinfo[2], dbinfo[4])}%"
        result["Databases"][dbinfo[0]]]["Index Size"] = dbinfo[3]
        result["Databases"][dbinfo[0]]]["Data Pct"] = f"{percentage(dbinfo[3], dbinfo[4])}%"
        result["Databases"][dbinfo[0]]]["Total Size"] = dbinfo[4]
        
        if dbinfo[7] > 1:
            bad_msg = f"{dbinfo[7]} different collations for database {dbinfo[0]}"
            badprint(bad_msg)
            generalrec.append(f"Check all table collations are identical for all tables in {dbinfo[0]} database.")
        else:
            good_msg = f"{dbinfo[7]} collation for {dbinfo[0]} database"
            goodprint(good_msg)
        
        if dbinfo[8] > 1:
            bad_msg = f"{dbinfo[8]} different engines for database {dbinfo[0]}"
            badprint(bad_msg)
            generalrec.append(f"Check all table engines are identical for all tables in {dbinfo[0]} database.")
        else:
            good_msg = f"{dbinfo[8]} engine for {dbinfo[0]} database"
            goodprint(good_msg)
        
        distinct_column_charset = select_array(f"select DISTINCT(CHARACTER_SET_NAME) from information_schema.COLUMNS where CHARACTER_SET_NAME IS NOT NULL AND TABLE_SCHEMA ='{db}'")
        info_msg = f"Charsets for {dbinfo[0]} database table column: {', '.join(distinct_column_charset)}"
        infoprint(info_msg)
        if len(distinct_column_charset) > 1:
            bad_msg = f"{dbinfo[0]} table column(s) has several charsets defined for all text like column(s)"
            badprint(bad_msg)
            generalrec.append(f"Limit charset for column to one charset if possible for {dbinfo[0]} database.")
        else:
            good_msg = f"{dbinfo[0]} table column(s) has same charset defined for all text like column(s)"
            goodprint(good_msg)
        
        distinct_column_collation = select_array(f"select DISTINCT(COLLATION_NAME) from information_schema.COLUMNS where COLLATION_NAME IS NOT NULL AND TABLE_SCHEMA ='{db}'")
        info_msg = f"Collations for {dbinfo[0]} database table column: {', '.join(distinct_column_collations)}"
        infoprint(info_msg)
        if len(distinct_column_collation) > 1:
            bad_msg = f"{dbinfo[0]} table column(s) has several collations defined for all text like column(s)"
            badprint(bad_msg)
            generalrec.append(f"Limit charset for column to one collation if possible for {dbinfo[0]} database.")
        else:
            good_msg = f"{dbinfo[0]} table column(s) has same charset defined for all text like column(s)"
            goodprint(good_msg)

# Recommendations for Indexes metrics
def mysql_indexes():
    if opt[idxstat] == 0:
        return
    subheaderprint("Indexes Metrics")
    if not mysql_version_ge(5, 5):
        infoprint("Skip Index metrics from information schema missing in this version")
        return
    #if not mysql_version_ge(5, 6):
    #    infoprint("Skip Index metrics from information schema due to erroneous information provided in this version")
    #    return
    selIdxREq = """
SELECT
  CONCAT(CONCAT(t.TABLE_SCHEMA, '.'),t.TABLE_NAME) AS 'table'
 , CONCAT(CONCAT(CONCAT(s.INDEX_NAME, '('),s.COLUMN_NAME), ')') AS 'index'
 , s.SEQ_IN_INDEX AS 'seq'
 , s2.max_columns AS 'maxcol'
 , s.CARDINALITY  AS 'card'
 , t.TABLE_ROWS   AS 'est_rows'
 , INDEX_TYPE as type
 , ROUND(((s.CARDINALITY / IFNULL(t.TABLE_ROWS, 0.01)) * 100), 2) AS 'sel'
FROM INFORMATION_SCHEMA.STATISTICS s
 INNER JOIN INFORMATION_SCHEMA.TABLES t
  ON s.TABLE_SCHEMA = t.TABLE_SCHEMA
  AND s.TABLE_NAME = t.TABLE_NAME
 INNER JOIN (
  SELECT
     TABLE_SCHEMA
   , TABLE_NAME
   , INDEX_NAME
   , MAX(SEQ_IN_INDEX) AS max_columns
  FROM INFORMATION_SCHEMA.STATISTICS
  WHERE TABLE_SCHEMA NOT IN ('mysql', 'information_schema', 'performance_schema')
  AND INDEX_TYPE <> 'FULLTEXT'
  GROUP BY TABLE_SCHEMA, TABLE_NAME, INDEX_NAME
 ) AS s2
 ON s.TABLE_SCHEMA = s2.TABLE_SCHEMA
 AND s.TABLE_NAME = s2.TABLE_NAME
 AND s.INDEX_NAME = s2.INDEX_NAME
WHERE t.TABLE_SCHEMA NOT IN ('mysql', 'information_schema', 'performance_schema')
AND t.TABLE_ROWS > 10
AND s.CARDINALITY IS NOT NULL
AND (s.CARDINALITY / IFNULL(t.TABLE_ROWS, 0.01)) < 8.00
ORDER BY sel
LIMIT 10;
"""
    idxinfo = select_array(selIdxReq)
    infoprint("Worst selectivity indexes:")
    for idx in idxinfo:
        debug_msg = f"{idx}"
        debugprint(debug_msg)
        info = idx.split("\s")
        info_msg = f"Index: {info[1]}"
        infoprint(info_msg)
        
        info_msg = f" +-- COLUMN      : {info[0]}"
        infoprint(info_msg)
        info_msg = f" +-- NB SEQS     : {info[2]} sequence(s)"
        infoprint(info_msg)
        info_msg = f" +-- NB COLS     : {info[3]} column(s)"
        infoprint(info_msg)
        info_msg = f" +-- CARDINALITY : {info[4]} distinct values"
        infoprint(info_msg)
        info_msg = f" +-- NB ROWS     : {info[5]} rows"
        infoprint(info_msg)
        info_msg = f" +-- TYPE        : {info[6]}"
        infoprint(info_msg)
        info_msg = f" +-- SELECTIVITY : {info[7]}%"
        infoprint(info_msg)
        
        result["Indexes"][info[1]["Column"] = info[0]
        result["Indexes"][info[1]["Sequence number"] = info[2]
        result["Indexes"][info[1]["Number of column"] = info[3]
        result["Indexes"][info[1]["Cardinality"] = info[4]
        result["Indexes"][info[1]["Row number"] = info[5]
        result["Indexes"][info[1]["Index Type"] = info[6]
        result["Indexes"][info[1]["Selectivity"] = info[7]
        
        if info[7] < 25:
            bad_msg = f"{info[1]} has a low selectivity"
            badprint(bad_msg)
    
    if not ((myvar["performance_schema"]) and (myvar["performance_schema"] == "ON"):
        return
    
    selIdxReq = """
SELECT CONCAT(CONCAT(object_schema,'.'),object_name) AS 'table', index_name
FROM performance_schema.table_io_waits_summary_by_index_usage
WHERE index_name IS NOT NULL
AND count_star =0
AND index_name <> 'PRIMARY'
AND object_schema != 'mysql'
ORDER BY count_star, object_schema, object_name;
"""
    idxinfo = select_array(selIdxReq)
    infoprint("Unused indexes:")
    if len(idxinfo) > 0:
        generalrec.append("Remove unused indexes.")
    for idx in idxinfo:
        info = idx.split("\s")
        bad_msg = f"Index {info[1]} on {info[0]} is not used"
        badprint(bad_msg)
        result["Indexes"]["Unused Indexes"].append(f"{info[0]}.{info[1]}")

# Take the two recommendation arrays and display them at the end of the output
def make_recommendations():
    result["Recommendations"] = generalrec
    result["Adjust variables"] = adjvars
    subheaderprint("Recommendations")
    if len(generalrec) > 0:
        prettyprint("General recommendations:")
        for rec in generalrec:
            prettyprint(f"    {rec}")
    if len(adjvars) > 0:
        prettyprint("Variables to adjust:")
        if mycalc["pct_max_physical_memory"] > 90:
            prettyprint("  *** MySQL's maximum memory usage is dangerously high ***\n"
            prettyprint("  *** Add RAM before increasing MySQL buffer variables ***")
    if (len(generalrec) == 0) and (len(adjvars) == 0):
        prettyprint("No additional performance recommendations are available.")

def close_outputfile(fh):
    if fh:
        fh.close()

def headerprint():
    pretty_msg = f" >>  MySQLTuner {tunerversion} - Immanuel Washington <immanuelqrw@gmail.com>\n >>  Bug reports, feature requests, and downloads at https://github.com/immanuelqrw/PySQLtuner\n >>  Run with '--help' for additional options and output filtering"
    prettyprint(pretty_msg)

def string2file(filename, content):
    try:
        with open(filename, mode="w", encoding="utf-8") as fh:
            fh.write(content)
    except:
        print(f"Unable to open {filename} in write mode. Please check permissions for this file or directory")
    if opt["debug"]:
        debug_msg = f"{content}"
        debugprint(debug_msg)

def file2array(filename):
    if opt["debug"]:
        debug_msg = f"* reading {filename}"
        debugprint(debug_msg)
    with open(filename, mode="r", encoding="utf-8") as fh:
        print(f"Couldn't open {filename} for reading: idk\n")
        lines = fh.readlines()
    return lines

def file2string(filename):
    return "".join(file2array(filename))

if opt["template"] != 0:
    templateModel = file2string(opt["template"])
else:
    # DEFAULT REPORT TEMPLATE
    templateModel = """
<!DOCTYPE html>
<html>
<head>
  <title>MySQLTuner Report</title>
  <meta charset="UTF-8">
</head>
<body>

<h1>Result output</h1>
<pre>
{$data}
</pre>

</body>
</html>
"""

def dump_result():
    if opt["debug"]:
        debugprint(", ".join(result))
        
    debug_msg = f"HTML REPORT: {opt['reportfile']}"
    debugprint(debug_msg)
    
    if opt["reportfile"] != 0:
        #idk what this is doing
        if idk:
            badprint("Text::Template Module is needed.")
        
        #idk this part

def is_exe(fpath):
    return os.path.isfile(fpath) and os.access(fpath, os.X_OK)

def which(prog_name, path_string):
    path_array = env["PATH"].split(":")

    for path in path_array:
        program = os.path.join(path, prog_name)
        fpath, fname = os.path.split(program)
        if fpath:
            if is_exe(program):
                return program
        else:
            for path in os.environ["PATH"].split(os.pathsep):
                path = path.strip('"')
                exe_file = os.path.join(path, program)
                if is_exe(exe_file):
                    return exe_file

    return None

"""
def which(program):
    import os
    def is_exe(fpath):
        return os.path.isfile(fpath) and os.access(fpath, os.X_OK)

    fpath, fname = os.path.split(program)
    if fpath:
        if is_exe(program):
            return program
    else:
        for path in os.environ["PATH"].split(os.pathsep):
            path = path.strip('"')
            exe_file = os.path.join(path, program)
            if is_exe(exe_file):
                return exe_file

    return None
"""
# ---------------------------------------------------------------------------
# BEGIN 'MAIN'
# ---------------------------------------------------------------------------
headerprint()               # Header Print
validate_tuner_version()    # Check last version
mysql_setup()               # Gotta login first
os_setup()                  # Set up some OS variables
get_all_vars()              # Toss variables/status into hashes
get_tuning_info()           # Get information about the tuning connexion
validate_mysql_version()    # Check current MySQL version

check_architecture()        # Suggest 64-bit upgrade
system_recommendations()    # avoid to many service on the same host
log_file_recommandations()  # check log file content
check_storage_engines()     # Show enabled storage engines
mysql_databases()           # Show informations about databases
mysql_indexes()             # Show informations about indexes
security_recommendations()  # Display some security recommendations
cve_recommendations()       # Display related CVE
calculations()              # Calculate everything we need
mysql_stats()               # Print the server stats
mysqsl_pfs()                # Print Performance schema info
mariadb_threadpool()        # Print MaraiDB ThreadPool stats
mysql_myisam()              # Print MyISAM stats
mysql_innodb()              # Print InnoDB stats
mariadb_ariadb()            # Print MaraiDB AriaDB stats
mariadb_tokudb()            # Print MariaDB Tokudb stats
mariadb_xtradb()            # Print MariaDB XtraDB stats
mariadb_rockdb()            # Print MariaDB RockDB stats
mariadb_spider()            # Print MariaDB Spider stats
mariadb_connect()           # Print MariaDB Connect stats
mariadb_galera()            # Print MariaDB Galera Cluster stats
get_replication_status()    # Print replication info
make_recommendations()      # Make recommendations based on stats
dump_result()               # Dump result if debug is on
close_outputfile()          # Close reportfile if needed

# ---------------------------------------------------------------------------
# END 'MAIN'
# ---------------------------------------------------------------------------

=encoding UTF-8

=head1 NAME

 MySQLTuner 1.7.0 - MySQL High Performance Tuning Script

=head1 IMPORTANT USAGE GUIDELINES

To run the script with the default options, run the script without arguments
Allow MySQL server to run for at least 24-48 hours before trusting suggestions
Some routines may require root level privileges (script will provide warnings)
You must provide the remote server's total memory when connecting to other servers

#=head1 CONNECTION AND AUTHENTIFICATION

# --host <hostname>    Connect to a remote host to perform tests (default: localhost)
# --socket <socket>    Use a different socket for a local connection
# --port <port>        Port to use for connection (default: 3306)
# --user <username>    Username to use for authentication
# --userenv <envvar>   Name of env variable which contains username to use for authentication
# --pass <password>    Password to use for authentication
# --passenv <envvar>   Name of env variable which contains password to use for authentication
# --mysqladmin <path>  Path to a custom mysqladmin executable
# --mysqlcmd <path>    Path to a custom mysql executable
# --defaults-file <path>  Path to a custom .my.cnf
#=head1 PERFORMANCE AND REPORTING OPTIONS

# --skipsize                  Don't enumerate tables and their types/sizes (default: on)
                             (Recommended for servers with many tables)
# --skippassword              Don't perform checks on user passwords(default: off)
# --checkversion              Check for updates to MySQLTuner (default: don't check)
# --updateversion             Check for updates to MySQLTuner and update when newer version is available (default: don't check)
# --forcemem <size>           Amount of RAM installed in megabytes
# --forceswap <size>          Amount of swap memory configured in megabytes
# --passwordfile <path>       Path to a password file list(one password by line)

#=head1 OUTPUT OPTIONS

# --silent                    Don't output anything on screen
# --nogood                    Remove OK responses
# --nobad                     Remove negative/suggestion responses
# --noinfo                    Remove informational responses
# --debug                     Print debug information
# --dbstat                    Print database information
# --idxstat                   Print index information
# --sysstat                   Print system information
# --pfstat                    Print Performance schema
# --bannedports               Ports banned separated by comma(,)
# --maxportallowed            Number of ports opened allowed on this hosts
# --cvefile                   CVE File for vulnerability checks
# --nocolor                   Don't print output in color
# --json                      Print result as JSON string
# --buffers                   Print global and per-thread buffer values
# --outputfile <path>         Path to a output txt file
# --reportfile <path>         Path to a report txt file
# --template   <path>         Path to a template file
# --verbose                   Prints out all options (default: no verbose)