"""
Port of MySQLtuner-perl in python
Copyright (C) 2017 Immanuel Washington - immanuelqrw@gmail.com

Git repository at https://github.com/immanuelqrw/PySQLtuner

Inspired by Major Hayden's MySQLtuner-perl project:
https://github.com/major/MySQLtuner-perl
"""

import collections as clct
import getpass
import os
import platform
import psutil as psu
import psycopg2 as psy
import pymysql as sql
import re
import requests as req
import shutil
import sqlalchemy as sqla
import sqlalchemy.orm as orm
import typing as typ
import pysqltuner.fancy_print as fp
import pysqltuner.util as util

__version__: str = u"0.0.1"
__email__: str = u"immanuelqrw@gmail.com"


class Option:
    def __init__(self) -> None:
        self.silent: bool = False
        self.no_color: bool = False
        self.no_good: bool = False
        self.no_info: bool = False
        self.no_bad: bool = False
        self.debug: bool = False
        self.force_mem: int = None
        self.force_swap: int = None
        self.host: str = None
        self.socket: int = None
        self.port: int = None
        self.user: str = None
        self.password: str = None
        self.skip_size: bool = False
        self.check_version: bool = False
        self.update_version: bool = False
        self.buffers: bool = False
        self.password_file: str = None
        self.banned_ports: typ.Sequence[int] = None
        self.max_port_allowed: int = 0
        self.output_file: str = None
        self.db_stat: bool = False
        self.idx_stat: bool = False
        self.sys_stat: bool = False
        self.pf_stat: bool = False
        self.skip_password: bool = False
        self.no_ask: bool = False
        self.template: str = None
        self.json: bool = False
        self.pretty_json: bool = False
        self.report_file: str = None
        self.verbose: bool = False
        self.defaults_file: str = None
        self.mysqladmin: str = None
        self.mysqlcmd: str = None
        self.do_remote: int = None
        self.remote_connect: str = None
        self.cve_file: str = None


def usage() -> None:
    """Prints information about PySQLtuner's script"""
    usage_msg: str = u"\n".join((
        f"   MySQLTuner {__version__} - MySQL High Performance Tuning Script",
        u"   Bug reports, feature requests, and downloads at https://github.com/immanuelqrw/PySQLtuner",
        f"   Maintained by Immanuel Washington ({__email__}) - Licensed under GPL",
        u"",
        u"   Important Usage Guidelines:",
        u"      To run the script with the default options, run the script without arguments",
        u"      Allow MySQL server to run for at least 24-48 hours before trusting suggestions",
        u"      Some routines may require root level privileges (script will provide warnings)",
        u"      You must provide the remote server's total memory when connecting to other servers",
        u"",
        u"   Connection and Authentication",
        u"      --host <hostname>    Connect to a remote host to perform tests (default: localhost)",
        u"      --socket <socket>    Use a different socket for a local connection",
        u"      --port <port>Port to use for connection (default: 3306)",
        u"      --user <username>    Username to use for authentication",
        u"      --user-env <envvar>   Name of env variable which contains username to use for authentication",
        u"      --pass <password>    Password to use for authentication",
        u"      --pass-env <envvar>   Name of env variable which contains password to use for authentication",
        u"      --defaults-file <path>  Path to a custom .my.cnf",
        u"      --mysqladmin <path>  Path to a custom mysqladmin executable",
        u"      --mysqlcmd <path>    Path to a custom mysql executable",
        u"",
        u"      --no-ask      Don't ask password if needed",
        u"",
        u"   Performance and Reporting Options",
        u"      --skip-size   Don't enumerate tables and their types/sizes (default: on)",
        u"   (Recommended for servers with many tables)",
        u"      --skip-password       Don't perform checks on user passwords(default: off)",
        u"      --check-version       Check for updates to MySQLTuner",
        u"      --update-version      Check for updates to MySQLTuner and update when newer version is available",
        u"      --force-mem <size>    Amount of RAM installed in megabytes",
        u"      --force-swap <size>   Amount of swap memory configured in megabytes",
        u"      --password-file <path>Path to a password file list(one password by line)",
        u"   Output Options:",
        u"      --silent       Don't output anything on screen",
        u"      --no-good      Remove OK responses",
        u"      --no-bad       Remove negative/suggestion responses",
        u"      --no-info      Remove informational responses",
        u"      --debug        Print debug information",
        u"      --db-stat      Print database information",
        u"      --idx-stat     Print index information",
        u"      --sys-stat     Print system information",
        u"      --pf-stat      Print Performance schema information",
        u"      --banned-ports Ports banned separated by comma(,)",
        u"      --max-port-allowed     Number of ports opened allowed on this hosts",
        u"      --cve-file    CVE File for vulnerability checks",
        u"      --nocolor    Don't print output in color",
        u"      --json       Print result as JSON string",
        u"      --pretty-json Print result as human readable JSON",
        u"      --buffers    Print global and per-thread buffer values",
        u"      --output-file <path>  Path to a output txt file",
        u"",
        u"      --report-file <path>  Path to a report txt file",
        u"",
        u"      --template   <path>  Path to a template file",
        u"",
        u"      --verbose    Prints out all options (default: no verbose) u"
    ))
    print(usage_msg)


def header_print(option: Option) -> None:
    """Prints header

    :param Option option: options object
    :return:
    """
    header_message: str = u"\n".join((
        f" >> PySQLTuner {__version__} - Immanuel Washington <{__email__}>",
        u" >> Bug reports, feature requests, and downloads at https://github.com/immanuelqrw/PySQLtuner",
        u" >> Run with '--help' for additional options and output filtering"
    ))
    fp.pretty_print(header_message, option)


def memory_error(option: Option) -> None:
    """Prints error message and exits

    :param Option option: options object
    :return:
    """
    memory_error_message: str = u"\n".join((
        u"Unable to determine total memory/swap",
        u"Use '--force-mem and '--force-swap'"
     ))
    fp.bad_print(memory_error_message, option)
    raise MemoryError


def get_process_memory(process: str) -> int:
    """Process to find memory of process

    :param str process: name of process
    :return int: memory in bytes
    """
    memory_command: typ.Sequence[str] = (
        u"ps",
        u"-p",
        f"{process}",
        u"-o",
        u"rss"
    )
    memory: typ.Sequence[str] = util.get(memory_command)

    if len(memory) != 2:
        return 0
    else:
        return int(memory[1]) * 1024


def other_process_memory() -> int:
    """Gathers other processes and returns total memory

    :return int: total memory of other processes
    """
    process_cmd: typ.Sequence[str] = (
        u"ps",
        u"eaxo",
        u"pid,command"
    )
    processes: typ.Sequence[str] = util.get(process_cmd)

    process_filters: typ.Sequence[typ.Tuple[str, str]] = (
        (r".*PID.*", u""),
        (r".*mysqld.*", u""),
        (r".*\[.*\].*", u""),
        (r"^\s+$", u""),
        (r".*PID.*CMD.*", u""),
        (r".*systemd.*", u""),
        (r"\s*?(\d+)\s*.*", r"\1")
    )

    filtered_processes: typ.List[str] = []
    for process in processes:
        for process_filter, process_replace in process_filters:
            process = re.sub(process_filter, process_replace, process)
        filtered_process: str = process.strip()
        if filtered_process:
            filtered_processes.append(filtered_process)

    total_other_memory = 0
    for filtered_process in filtered_processes:
        total_other_memory += get_process_memory(filtered_process)

    return total_other_memory


def os_setup(option: Option) -> typ.Tuple[str, int, str, int, str, int, str]:
    """Gets name and memory of OS

    :param Option option:
    :return typ.Tuple[str, int, str, int, str, int, str]:
    """
    current_os: str = util.get(r"uname").strip()
    # du_flags: str = u"-b" if re.match(r"Linux", current_os) else u""
    if option.force_mem is not None and option.force_mem > 0:
        physical_memory: int = option.force_mem * 1024 ** 2
        fp.info_print(f"Assuming {option.force_mem} MB of physical memory", option)

        if option.force_swap is not None and option.force_swap > 0:
            swap_memory: int = option.force_swap * 1024 ** 2
            fp.info_print(f"Assuming {option.force_swap} MB of swap space", option)
        else:
            swap_memory: int = 0
            fp.bad_print(u"Assuming 0 MB of swap space (Use --force-swap to specify, option", option)
    else:
        try:
            if re.match(r"Linux|CYGWIN", current_os):
                linux_mem_cmd: typ.Sequence[str] = (
                    u"grep",
                    u"-i",
                    u"memtotal:",
                    u"/proc/meminfo",
                    u"|",
                    u"awk",
                    u"'{print \$2}'"
                )

                physical_memory: int = int(util.get(linux_mem_cmd))
                physical_memory *= 1024

                linux_swap_cmd: typ.Sequence[str] = (
                    u"grep",
                    u"-i",
                    u"swaptotal:",
                    u"/proc/meminfo",
                    u"|",
                    u"awk",
                    u"'{print \$2}'"
                )

                swap_memory: int = int(util.get(linux_swap_cmd))
                swap_memory *= 1024

            elif re.match(r"Darwin", current_os):
                darwin_mem_cmd: typ.Sequence[str] = (
                    u"sysctl",
                    u"-n",
                    u"hw.memsize"
                )

                physical_memory: int = int(util.get(darwin_mem_cmd))

                darwin_swap_cmd: typ.Sequence[str] = (
                    u"sysctl"
                    u"-n",
                    u"vm.swapusage",
                    u"|",
                    u"awk",
                    u"'{print \$3}'",
                    u"|",
                    u"sed",
                    u"'s/\..*\$//'"
                )

                swap_memory: int = int(util.get(darwin_swap_cmd))

            elif re.match(r"NetBSD|OpenBSD|FreeBSD", current_os):
                xbsd_mem_cmd: typ.Sequence[str] = (
                    u"sysctl",
                    u"-n",
                    u"hw.physmem"
                )

                physical_memory: int = int(util.get(xbsd_mem_cmd))
                if physical_memory < 0:
                    xbsd_mem64_cmd: typ.Sequence[str] = (
                        u"sysctl",
                        u"-n",
                        u"hw.physmem64"
                    )

                    physical_memory: int = int(util.get(xbsd_mem64_cmd))

                xbsd_swap_cmd: typ.Sequence[str] = (
                    u"swapctl"
                    u"-l",
                    u"|",
                    u"grep",
                    u"'^/'",
                    u"|",
                    u"awk",
                    u"'{ s+= \$2 }",
                    u"END",
                    u"{ print s }"
                )

                swap_memory: int = int(util.get(xbsd_swap_cmd))

            elif re.match(r"BSD", current_os):
                bsd_mem_cmd: typ.Sequence[str] = (
                    u"sysctl",
                    u"-n",
                    u"hw.physmem"
                )

                physical_memory: int = int(util.get(bsd_mem_cmd))

                bsd_swap_cmd: typ.Sequence[str] = (
                    u"swapinfo"
                    u"|",
                    u"grep",
                    u"'^/'",
                    u"|",
                    u"awk",
                    u"'{ s+= \$2 }",
                    u"END",
                    u"{ print s }"
                )

                swap_memory: int = int(util.get(bsd_swap_cmd))

            elif re.match(r"SunOS", current_os):
                sun_mem_cmd: typ.Sequence[str] = (
                    u"/usr/sbin/prtconf",
                    u"|",
                    u"grep",
                    u"Memory",
                    u"|",
                    u"cut",
                    u"-f",
                    u"3",
                    u"-d"
                    u"' u"
                )

                physical_memory: int = int(util.get(sun_mem_cmd))
                physical_memory *= 1024 ** 2

                swap_memory: int = 0

            elif re.match(r"AIX", current_os):
                aix_mem_cmd: typ.Sequence[str] = (
                    u"lsattr",
                    u"-El",
                    u"sys0",
                    u"|",
                    u"grep",
                    u"realmem",
                    u"awk",
                    u"'{print \$2}'"
                )

                physical_memory: int = int(util.get(aix_mem_cmd))
                physical_memory *= 1024

                aix_swap_cmd: typ.Sequence[str] = (
                    u"lsps"
                    u"-as",
                    u"|",
                    u"awk",
                    u"-F\"(MB| +)\"",
                    u"'/MB",
                    u"{print \$2}'"
                )

                swap_memory: int = int(util.get(aix_swap_cmd))
                swap_memory *= 1024 ** 2

            elif re.match(r"windows", current_os, re.IGNORECASE):
                win_mem_cmd: typ.Sequence[str] = (
                    u"wmic",
                    u"ComputerSystem",
                    u"get",
                    u"TotalPhysicalMemory"
                )

                physical_memory: int = int(util.get(win_mem_cmd))

                win_swap_cmd: typ.Sequence[str] = (
                    u"wmic",
                    u"OS",
                    u"get",
                    u"FreeVirtualMemory"
                )

                swap_memory: int = int(util.get(win_swap_cmd))

        except MemoryError:
            memory_error(option)

    fp.debug_print(f"Physical Memory: {physical_memory}", option)
    fp.debug_print(f"Swap Memory: {swap_memory}", option)

    process_memory: int = other_process_memory()

    return (
        current_os,
        physical_memory,
        util.bytes_to_string(physical_memory),
        swap_memory,
        util.bytes_to_string(swap_memory),
        process_memory,
        util.bytes_to_string(process_memory)

    )


def is_readable(read_path: str) -> bool:
    """Checks if file is readable

    :param str read_path: readable file path
    :return bool:
    """
    return os.path.isfile(read_path) and os.access(read_path, os.R_OK)


def mysql_setup(option: Option) -> bool:
    """Sets up options for mysql

    :param Option option: options object
    :return bool: whether setup was successful
    """
    if option.mysqladmin:
        mysqladmin_command: str = option.mysqladmin.strip()
    else:
        mysqladmin_command: str = shutil.which(u"mysqladmin").strip()

    if not os.path.exists(mysqladmin_command) and option.mysqladmin:
        fp.bad_print(f"Unable to find the mysqladmin command you specified {mysqladmin_command}", option)
        raise FileNotFoundError
    elif not os.path.exists(mysqladmin_command):
        fp.bad_print(u"Couldn't find mysqladmin in your $PATH. Is MySQL installed?", option)
        raise FileNotFoundError

    if option.mysqlcmd:
        mysql_command: str = option.mysqlcmd.strip()
    else:
        mysql_command: str = shutil.which(u"mysql").strip()

    if not os.path.exists(mysql_command) and option.mysqlcmd:
        fp.bad_print(f"Unable to find the mysql command you specified {mysql_command}", option)
        raise FileNotFoundError
    elif not os.path.exists(mysql_command):
        fp.bad_print(u"Couldn't find mysql in your $PATH. Is MySQL installed?", option)
        raise FileNotFoundError

    mysql_defaults_command: typ.Sequence[str] = (
        mysql_command,
        u"--print-defaults"
    )
    mysql_cli_defaults: str = util.get(mysql_defaults_command)
    fp.debug_print(f"MySQL Client: {mysql_cli_defaults}", option)

    if re.match(r"auto-vertical-output", mysql_cli_defaults):
        fp.bad_print(u"Avoid auto-vertical-output in configuration file(s) for MySQL like", option)
        raise Exception

    fp.debug_print(f"MySQL Client {mysql_command}", option)

    option.port = 3306 if not option.port else option.port

    if option.socket:
        option.remote_connect: str = f"-S {option.socket} -P {option.port}"

    if option.host:
        option.host = option.host.strip()

        if not option.force_mem and option.host not in (u"127.0.0.1", u"localhost"):
            fp.bad_print(u"The --force-mem option is required for remote connections", option)
            raise ConnectionRefusedError

        fp.info_print(f"Performing tests on {option.host}:{option.port}", option)
        option.remote_connect: str = f"-h {option.host} -P {option.port}"

        if option.host not in (u"127.0.0.1", u"localhost"):
            option.do_remote: int = 1

    if option.user and option.password:
        mysql_login: str = f"-u {option.user} {option.remote_connect}"
        login_command: typ.Sequence[str] = (
            mysqladmin_command,
            u"ping",
            mysql_login,
            u"2>&1"
        )
        login_status: str = util.get(login_command)
        if re.match(r"mysqld is alive", login_status):
            fp.good_print(u"Logged in using credentials passed on the command line", option)
            return True
        else:
            fp.bad_print(u"Attempted to use login credentials, but they were invalid", option)
            raise ConnectionRefusedError

    svcprop_exe: str = shutil.which(u"svcprop")
    if svcprop_exe.startswith(u"/"):
        # We are on Solaris
        svc_user_command: typ.Sequence[str] = (
            u"svcprop",
            u"-p",
            u"quickbackup/username",
            u"svc:/network/mysql-quickbackup:default"
        )
        mysql_login: str = util.get(svc_user_command)
        mysql_login = re.sub(r"\s+$", u"", mysql_login)

        svc_pass_command: typ.Sequence[str] = (
            u"svcprop",
            u"-p",
            u"quickbackup/password",
            u"svc:/network/mysql-quickbackup:default"
        )
        mysql_pass: str = util.get(svc_pass_command)
        mysql_pass = re.sub(r"\s+$", u"", mysql_pass)

        if not mysql_login.startswith(u"svcprop"):
            # mysql-quickbackup is installed
            mysql_login_connect: str = f"-u {mysql_login} -p{mysql_pass}"
            login_command: typ.Sequence[str] = (
                mysqladmin_command,
                mysql_login_connect,
                u"ping",
                u"2>&1"
            )
            login_status: str = util.get(login_command)
            if re.match(r"mysqld is alive", login_status):
                fp.good_print(u"Logged in using credentials passed from mysql-quickbackup", option)
                return True
            else:
                fp.bad_print(u"Attempted to use login credentials from mysql-quickbackup, but they were invalid", option)
                raise ConnectionRefusedError

    elif is_readable(u"/etc/psa/.psa.shadow") and not option.do_remote:
        # It's a Plesk box, use the available credentials
        plesk_command: typ.Sequence[str] = (
            u"cat",
            u"/etc/psa/.psa.shadow"
        )
        plesk_pass: str = util.get(plesk_command)

        mysql_login: str = f"-u admin -p{plesk_pass}"
        login_command: typ.Sequence[str] = (
            mysqladmin_command,
            u"ping",
            mysql_login,
            u"2>&1"
        )
        login_status: str = util.get(login_command)

        if not re.match(r"mysqld is alive", login_status):
            # Plesk 10+
            plesk_command: typ.Sequence[str] = (
                u"/usr/local/psa/bin/admin",
                u"--show-password"
            )
            plesk_pass: str = util.get(plesk_command)

            mysql_login: str = f"-u admin -p{plesk_pass}"
            login_command: typ.Sequence[str] = (
                mysqladmin_command,
                u"ping",
                mysql_login,
                u"2>&1"
            )
            login_status: str = util.get(login_command)

            if not re.match(r"mysqld is alive", login_status):
                fp.bad_print(u"Attempted to use login credentials from Plesk and Plesk 10+, but they failed", option)
                raise ConnectionRefusedError

    elif is_readable(u"/usr/local/directadmin/conf/mysql.conf") and not option.do_remote:
        # It's a DirectAdmin box, use the available credentials
        mysql_user_command: typ.Sequence[str] = (
            u"cat",
            u"/usr/local/directadmin/conf/mysql.conf",
            u"|",
            u"egrep",
            u"'^user=.*'"
        )
        mysql_user: str = util.get(mysql_user_command)

        mysql_pass_command: typ.Sequence[str] = (
            u"cat",
            u"/usr/local/directadmin/conf/mysql.conf",
            u"|",
            u"egrep",
            u"'^passwd=.*'"
        )
        mysql_pass: str = util.get(mysql_pass_command)

        user_filters: typ.Sequence[typ.Tuple[str, str]] = (
            (u"user=u", u""),
            (u"[\r\n]", u"")
        )
        for user_filter, user_replace in user_filters:
            mysql_user: str = re.sub(user_filter, user_replace, mysql_user)

        pass_filters: typ.Sequence[typ.Tuple[str, str]] = (
            (u"passwd=u", u""),
            (u"[\r\n]", u"")
        )
        for pass_filter, pass_replace in pass_filters:
            mysql_pass: str = re.sub(pass_filter, pass_replace, mysql_pass)

        mysql_login: str = f"-u {mysql_user} -p{mysql_pass}"
        login_command: typ.Sequence[str] = (
            mysqladmin_command,
            u"ping",
            mysql_login,
            u"2>&1"
        )
        login_status: str = util.get(login_command)

        if not re.match(r"mysqld is alive", login_status):
            fp.bad_print(u"Attempted to use login credentials from DirectAdmin, but they failed", option)
            raise ConnectionRefusedError

    elif is_readable(u"/etc/mysql/debian.cnf") and not option.do_remote:
        # We have a debian maintenance account, use the available credentials
        mysql_login: str = u"--defaults-file=/etc/mysql/debian.cnf"
        login_command: typ.Sequence[str] = (
            mysqladmin_command,
            mysql_login,
            u"ping",
            u"2>&1"
        )
        login_status: str = util.get(login_command)

        if re.match(r"mysqld is alive", login_status):
            fp.good_print(u"Logged in using credentials from debian maintenance account.", option)
            return True
        else:
            fp.bad_print(u"Attempted to use login credentials from DirectAdmin, but they failed", option)
            raise ConnectionRefusedError

    elif option.defaults_file and is_readable(option.defaults_file):
        # Defaults File
        fp.debug_print(f"defaults file detected: {option.defaults_file}", option)

        mysql_defaults_command: typ.Sequence[str] = (
            mysql_command,
            u"--print-defaults"
        )
        util.run(mysql_defaults_command)

        mysql_login: str = f"--defaults-file={option.defaults_file}"
        login_command: typ.Sequence[str] = (
            mysqladmin_command,
            mysql_login,
            u"ping",
            u"2>&1"
        )
        login_status: str = util.get(login_command)

        if re.match(r"mysqld is alive", login_status):
            fp.good_print(u"Logged in using credentials from defaults file account.", option)
            return True
    else:
        # It's not Plesk or debian, we should try a login
        login_command: typ.Sequence[str] = (
            mysqladmin_command,
            option.remote_connect,
            u"ping",
            u"2>&1"
        )
        fp.debug_print(u" ".join(login_command), option)

        login_status: str = util.get(login_command)

        if re.match(r"mysqld is alive", login_status):
            # Login went just fine
            # mysql_login: str = f" {option.remote_connect} u"

            # Did this go well because of a .my.cnf file or is there no password set?
            user_path: str = os.environ["HOME"].strip()
            if not os.path.exists(f"{user_path}/.my.cnf") and not os.path.exists(f"{user_path}/.mylogin.cnf"):
                fp.bad_print(u"Successfully authenticated with no password - SECURITY RISK!", option)

            return True

        else:
            if option.no_ask:
                fp.bad_print(u"Attempted to use login credentials, but they were invalid", option)
                raise ConnectionRefusedError

            # If --user is defined no need to ask for username
            if option.user:
                name: str = option.user.strip()
            else:
                name: str = input(u"Please enter your MySQL administrative login: u").strip()

            # If --pass is defined no need to ask for password
            if option.password:
                password: str = option.password.strip()
            else:
                password: str = getpass.getpass(u"Please enter your MySQL administrative password: u").strip()

            mysql_login: str = f"-u {name}"
            if password:
                mysql_login = u" ".join((mysql_login, f"-p'{password}'"))

            mysql_login: str = u" ".join((mysql_login, option.remote_connect))

            login_command: typ.Sequence[str] = (
                mysqladmin_command,
                u"ping",
                mysql_login,
                u"2>&1"
            )

            login_status: str = util.get(login_command)

            if re.match(r"mysqld is alive", login_status):
                if not password:
                    # Did this go well because of a .my.cnf file or is there no password set?
                    user_path: str = os.environ["HOME"].strip()
                    if not os.path.exists(f"{user_path}/.my.cnf"):
                        fp.bad_print(u"Successfully authenticated with no password - SECURITY RISK!", option)

                return True
            else:
                fp.bad_print(u"Attempted to use login credentials but they were invalid", option)
                raise ConnectionRefusedError


# TODO finish all functions below this comment
def tuning_info():
    pass


def mysql_status_vars():
    pass


def opened_ports() -> typ.Sequence[str]:
    """Finds all opened ports

    :return typ.Sequence[str]: array of all opened ports
    """
    opened_ports_command: typ.Sequence[str] = (
        u"netstat",
        u"-ltn"
    )
    all_opened_ports: str = util.get(opened_ports_command)

    port_filters: typ.Sequence[typ.Tuple[str, str]] = (
        (r".*:(\d+)\s.*$", r"\1"),
        (r"\D", u"")
    )

    filtered_ports: typ.Sequence[str] = sorted(
        re.sub(port_filter, port_replace, open_port)
        for open_port in all_opened_ports
        for port_filter, port_replace in port_filters
    )

    filtered_ports = [
        filtered_port
        for filtered_port in filtered_ports
        if not re.match(r"^$", filtered_port)
    ]

    # TODO include opened ports in results object

    return filtered_ports


def is_open_port(port: str) -> bool:
    """Finds if port is open

    :param str port: port name
    :return bool: whether the port specified is open
    """
    port_pattern: str = f"^{port}$"
    return any(re.search(port_pattern, open_port) for open_port in opened_ports())


def os_release() -> str:
    """Finds OS release

    :return str: returns OS release
    """
    release_filters: typ.Sequence[typ.Tuple[str, str]] = (
        (u".*=\"", u""),
        (u"\"$", u"")
    )

    lsb_release_file: str = u"/etc/lsb-release"
    if os.path.isfile(lsb_release_file):
        with open(lsb_release_file, mode=u"r", encoding=u"utf-8") as lrf:
            info_release: str = lrf.read()
        os_release_: str = info_release[3]

        for release_filter, release_replace in release_filters:
            os_release_: str = re.sub(release_filter, release_replace, os_release_)

        return os_release_

    sys_release_file: str = u"/etc.system-release"
    if os.path.isfile(sys_release_file):
        with open(sys_release_file, mode=u"r", encoding=u"utf-8") as srf:
            info_release: str = srf.read()
        os_release_: str = info_release[0]

        return os_release_

    os_release_file: str = u"/etc/os-release"
    if os.path.isfile(os_release_file):
        with open(os_release_file, mode=u"r", encoding=u"utf-8") as orf:
            info_release: str = orf.read()
        os_release_: str = info_release[0]

        for release_filter, release_replace in release_filters:
            os_release_: str = re.sub(release_filter, release_replace, os_release_)

        return os_release_

    issue_file: str = u"/etc/issue"
    if os.path.isfile(issue_file):
        with open(issue_file, mode=u"r", encoding=u"utf-8") as isf:
            info_release: str = isf.read()
        os_release_: str = info_release[0]

        os_release_: str = re.sub(r"\s+\\n.*", u"", os_release_)

        return os_release_

    return u"Unknown OS release"


def fs_info(option: Option) -> None:
    """Appends filesystem information to recommendations

    :param Option option: options object
    :return:
    """
    s_info: typ.Sequence[str] = util.get((
        u"df",
        u"-P",
        u"|",
        u"grep",
        u"'%'"
    )).split(u"\n")

    i_info: typ.Sequence[str] = util.get((
        u"df",
        u"-Pi",
        u"|",
        u"grep",
        u"'%'"
    )).split(u"\n")[1:]

    info_filters: typ.Sequence[typ.Tuple[str, str]] = (
        (r".*\s(\d+)%\s+(.*)", u"\1\t\2")
    )
    for info_filter, info_replace in info_filters:
        s_info: typ.Sequence[str] = tuple(
            re.sub(info_filter, info_replace, info)
            for info in s_info
        )

    for info in s_info:
        if re.match(r"(\d+)\t", info) and re.match(r"(run|dev|sys|proc)($|/)", info):
            continue
        matched = re.match(r"(\d+)\t(.*)", info)
        if matched:
            space_perc: str = matched.group(1)
            mount_point: str = matched.group(2)
            if int(matched.group(1)) > 85:
                fp.bad_print(f"Mount point {mount_point} is using {space_perc} % total space", option)
                # TODO append to recommendations
            else:
                fp.info_print(f"Mount point {mount_point} is using {space_perc} % total space", option)

            # TODO result object assigning

    for info in i_info:
        if re.match(r"(\d+)\t", info) and re.match(r"(run|dev|sys|proc)($|/)"):
            continue
        matched = re.match(r"(\d+)\t(.*)", info)
        if matched:
            space_perc: str = matched.group(1)
            mount_point: str = matched.group(2)
            if int(matched.group(1)) > 85:
                fp.bad_print(f"Mount point {mount_point} is using {space_perc} % of max allowed inodes", option)
                # TODO append to recommendations
            else:
                fp.info_print(f"Mount point {mount_point} is using {space_perc} % of max allowed inodes", option)

            # TODO result object assigning


def is_virtual_machine() -> bool:
    """Checks if virtual machine

    :return bool: whether it is a virtual machine
    """
    is_vm: int = int(util.get((
        u"grep",
        u"-Ec",
        u"'^flags.*\ hypervisor\ '",
        u"/proc/cpuinfo"
    )))
    return bool(is_vm)


def info_cmd(command: typ.Sequence[str], option: Option, delimiter: str = u"") -> None:
    """Runs commands and prints information

    :param typ.Sequence[str] command: sequence of strings which constitute command
    :param Option option: options object
    :param str delimiter: delimiter
    :return:
    """
    cmd: str = f"{command}"
    fp.debug_print(f"CMD: {cmd}", option)

    result: str = tuple(
            info.strip()
            for info in util.get(command)
    )
    for info in result:
        fp.info_print(f"{delimiter}{info}", option)


def kernel_info(option: Option) -> None:
    params: typ.Sequence[str] = (
        u"fs.aio-max-nr",
        u"fs.aio-nr",
        u"fs.file-max",
        u"sunrpc.tcp_fin_timeout",
        u"sunrpc.tcp_max_slot_table_entries",
        u"sunrpc.tcp_slot_table_entries",
        u"vm.swappiness"
    )

    fp.info_print(u"Information about kernel tuning:", option)

    for param in params:
        sysctl_devnull_command: typ.Sequence[str] = (
            u"sysctl",
            param,
            u"2>/dev/null"
        )
        fp.info_cmd(sysctl_devnull_command, option, delimiter=u"\t")
        # TODO result setting

    sysctl_swap_command: typ.Sequence[str] = (
        u"sysctl",
        u"-n",
        u"vm.swappiness"
    )
    if int(util.get(sysctl_swap_command)) > 10:
        fp.bad_print(u"Swappiness is > 10, please consider having a value lower than 10", option)
        # TODO recommendation appending and adjusted variables
    else:
        fp.info_print(u"Swappiness is < 10.", option)

    # only if /proc/sys/sunrpc exists
    slot_table_command: typ.Sequence[str] = (
        u"sysctl",
        u"-n",
        u"sunrpc.tcp_slot_table_entries",
        u"2>/dev/null"
    )
    tcp_slot_entries: str = util.get(slot_table_command)

    if os.path.isfile(u"/proc/sys/sunrpc") and (not tcp_slot_entries or int(tcp_slot_entries) < 100):
        fp.bad_print("Initial TCP slot entries is < 1M, please consider having a value greater than 100", option)
        # TODO recommendation appending and adjusting variables
    else:
        fp.info_print(u"TCP slot entries is > 100.", option)

    aio_max_command: typ.Sequence[str] = (
        u"sysctl",
        u"-n",
        u"fs.aio-max-nr"
    )
    aio_max: str = util.get(aio_max_command)

    if aio_max < 1e6:
        fp.bad_print(u"Max running total of the number of events is < 1M, please consider having a value greater than 1M", option)
        # TODO recommendation appending and adjusting variables
    else:
        fp.info_print(u"Max Number of AIO events is > 1M.", option)


def system_info(option: Option) -> None:
    # TODO set results object
    fp.info_print(os_release(), option)
    if is_virtual_machine():
        fp.info_print(u"Machine Type:\t\t\t\t\t: Virtual Machine", option)
        # TODO set results object
    else:
        fp.info_print(u"Machine Type:\t\t\t\t\t: Physical Machine", option)
        # TODO set results object

    # TODO set results object

    connect_command: typ.Sequence[str] = (
        u"ping",
        u"-c",
        u"ipecho.net",
        u"&>/dev/null"
    )

    is_connected: bool = True if int(util.get(connect_command)) == 0 else False
    if is_connected:
        fp.info_print(u"Internet\t\t\t\t\t: Connected", option)
        # TODO set results object
    else:

        fp.bad_print(u"Internet\t\t\t\t\t: Disconnected", option)

    # TODO set several variables in results object

    core_command: typ.Sequence[str] = (
        u"nproc"
    )
    process_amount: int = int(util.get(core_command))
    fp.info_print(f"Number of Core CPU : {process_amount}", option)

    os_type_command: typ.Sequence[str] = (
        u"uname",
        u"-o"
    )
    os_type: str = util.get(os_type_command)
    fp.info_print(f"Operating System Type : {os_type}", option)

    kernel_release_command: typ.Sequence[str] = (
        u"uname",
        u"-r"
    )
    kernel_release: str = util.get(kernel_release_command)
    fp.info_print(f"Kernel Release : {os_type}", option)

    hostname_command: typ.Sequence[str] = (
        u"hostname"
    )
    hostname: str = util.get(hostname_command)
    fp.info_print(f"Hostname\t\t\t\t: {hostname}", option)

    ip_command: typ.Sequence[str] = (
        u"hostname",
        u"-I"
    )
    ip: str = util.get(ip_command)
    fp.info_print(f"Internal IP\t\t\t\t: {ip}", option)

    network_card_command: typ.Sequence[str] = (
        u"ifconfig",
        u"|",
        u"grep",
        u"-A1",
        u"mtu"
    )
    fp.info_print(u"Network Cards\t\t\t: ", option)
    info_cmd(network_card_command, option, delimiter=u"\t")

    try:
        external_ip: str = req.get(u"ipecho.net/plain")
        fp.info_print(f"External IP\t\t\t\t: {external_ip}", option)
    except req.exceptions.MissingSchema as err:
        fp.bad_print(f"External IP\t\t\t\t: Can't check because of Internet connectivity", option)

    name_server_command: typ.Sequence[str] = (
        u"grep",
        u"'nameserver'",
        u"/etc/resolv.conf",
        u"\|",
        u"awk",
        u"'{print \$2}'"
    )
    name_servers: str = util.get(name_server_command)
    fp.info_print(f"Name Servers\t\t\t\t: {name_servers}", option)

    fp.info_print(u"Logged in Users\t\t\t\t:", option)
    logged_user_command: typ.Sequence[str] = (
        "who"
    )
    info_cmd(logged_user_command, option, delimiter=u"\t")
    logged_users = util.get(logged_user_command)

    ram_command: typ.Sequence[str] = (
        u"free",
        u"-m",
        u"|",
        u"grep",
        u"-v",
        u"+"
    )
    ram: str = util.get(ram_command)
    fp.info_print(f"Ram Usages in Mb\t\t: {ram}", option)

    load_command: typ.Sequence[str] = (
        u"top",
        u"-n",
        u"1",
        u"-b"
        u"|",
        u"grep",
        u"'load average:'"
    )
    load_average: str = util.get(load_command)


def system_recommendations(physical_memory: int, banned_ports: typ.Sequence[str], option: Option) -> None:
    """Generates system level recommendations

    :param int physical_memory: amount of physical memory in bytes
    :param typ.Sequence[str] banned_ports: sequence of banned ports
    :param Option option: options object
    :return:
    """
    if not option.sys_stat:
        return None

    os_name: str = platform.system()
    if not re.match(r"Linux", os_name, re.IGNORECASE):
        fp.info_print(u"Skipped due to non Linux Server", option)
        return None

    fp.pretty_print(u"Look for related Linux system recommendations", option)

    system_info(option)
    other_proc_mem: int = other_process_memory()

    fp.info_print(f"User process except mysqld used {util.bytes_to_string(other_proc_mem)} RAM", option)

    if 0.15 * physical_memory < other_proc_mem:
        fp.bad_print((
            u"Other user process except mysqld used more than 15% of total physical memory "
            f"{util.percentage(other_proc_mem, physical_memory)}% "
            f"({util.bytes_to_string(other_proc_mem)} / {util.bytes_to_string(physical_memory)})"
        ), option)
        # TODO recommendations and adjusted variables
    else:
        fp.info_print((
            u"Other user process except mysqld used more than 15% of total physical memory "
            f"{util.percentage(other_proc_mem, physical_memory)}% "
            f"({util.bytes_to_string(other_proc_mem)} / {util.bytes_to_string(physical_memory)})"
        ), option)

    if option.max_port_allowed > 0:
        open_ports: typ.Sequence[str] = opened_ports()
        fp.info_print(f"There are {len(open_ports)} listening port(s) on this server", option)

        if len(open_ports) > option.max_port_allowed:
            fp.bad_print((
                f"There are too many listening ports: "
                f"{len(open_ports)} opened > {option.max_port_allowed} allowed"
            ), option)
            # TODO recommendations
        else:
            fp.info_print(f"There are less than {option.max_port_allowed} opened ports on this server", option)

    for banned_port in banned_ports:
        if is_open_port(banned_port):
            fp.bad_print(f"Banned port: {banned_port} is opened.", option)
            # TODO recommendations
        else:
            fp.good_print(f"{banned_port} is not opened.", option)

    fs_info(option)
    kernel_info(option)


def security_recommendations(option: Option) -> None:
    fp.subheader_print(u"Security Recommendations", option)
    if option.skip_password:
        fp.info_print(u"Skipped due to --skip-password option", option)
        return None

    pass_column: str = u"password"
    # TODO need mysql version

    # Looking for Anonymous users
    mysql_stat_query: str = "\n".join((
        u"SELECT",
        u"CONCAT(`usr`.`USER`, '@', `usr`.`HOST`) AS `GRANTEE`",
        u"FROM",
        u"`mysql`.`user` AS `usr`",
        u"WHERE",
        u"TRIM(`usr`.`USER`) = ''",
        u"OR",
        u"`usr`.`USER` IS NULL;"
    ))
    connect_params: typ.Dict[str, str] = util.connection_params()
    engine = sqla.create_engine(sqla.engine.url.URL(**connect_params))
    with util.session_scope(engine) as sess:
        result = sess.execute(mysql_stat_query)
        Stat = clct.namedtuple(u"Stat", result.keys())
        stats: typ.Sequence[Stat] = [Stat(*stat).GRANTEE for stat in result.fetchall()]

    fp.debug_print(f"{stats}", option)

