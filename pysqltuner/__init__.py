"""
Port of MySQLtuner-perl in python
Copyright (C) 2017 Immanuel Washington - immanuelqrw@gmail.com

Git repository at https://github.com/immanuelqrw/PySQLtuner

Inspired by Major Hayden's MySQLtuner-perl project:
https://github.com/major/MySQLtuner-perl
"""

import collections as clct
import getpass
import json
import os
import os.path as osp
import platform
import psutil as psu
import re
import requests as req
import shutil
import sqlalchemy as sqla
import sqlalchemy.orm as orm
import pysqltuner.tuner as tuner
import typing as typ
import pysqltuner.fancy_print as fp
import pysqltuner.util as util

__version__: str = u"0.0.1"
__email__: str = u"immanuelqrw@gmail.com"


def usage() -> None:
    """Prints information about PySQLtuner's script"""
    usage_file: str = osp.join(osp.dirname(__file__), u"..")
    with open(usage_file, mode=u"r", encoding="utf-8") as uf:
        usage_msg: str = uf.read().replace(
            u":version",
            __version__
        ).replace(
            u":email",
            __email__
        )

    print(usage_msg)


def header_print(option: tuner.Option) -> None:
    """Prints header

    :param tuner.Option option: options object
    :return:
    """
    header_message: str = u"\n".join((
        f" >> PySQLTuner {__version__} - Immanuel Washington <{__email__}>",
        u" >> Bug reports, feature requests, and downloads at https://github.com/immanuelqrw/PySQLtuner",
        u" >> Run with '--help' for additional options and output filtering"
    ))
    option.pretty_print(header_message)


def memory_error(option: tuner.Option) -> None:
    """Prints error message and exits

    :param tuner.Option option: options object
    :return:
    """
    memory_error_message: str = u"\n".join((
        u"Unable to determine total memory/swap",
        u"Use '--force-mem and '--force-swap'"
     ))
    option.bad_print(memory_error_message)
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


def os_setup(option: tuner.Option) -> typ.Tuple[str, int, str, int, str, int, str]:
    """Gets name and memory of OS

    :param tuner.Option option:
    :return typ.Tuple[str, int, str, int, str, int, str]:
    """
    current_os: str = util.get(r"uname").strip()
    # du_flags: str = u"-b" if re.match(r"Linux", current_os) else u""
    if option.force_mem is not None and option.force_mem > 0:
        physical_memory: int = option.force_mem * 1024 ** 2
        option.info_print(f"Assuming {option.force_mem} MB of physical memory")

        if option.force_swap is not None and option.force_swap > 0:
            swap_memory: int = option.force_swap * 1024 ** 2
            option.info_print(f"Assuming {option.force_swap} MB of swap space")
        else:
            swap_memory: int = 0
            option.bad_print(u"Assuming 0 MB of swap space (Use --force-swap to specify)")
    else:
        physical_memory: int = 0
        swap_memory: int = 0
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

    option.debug_print(f"Physical Memory: {physical_memory}")
    option.debug_print(f"Swap Memory: {swap_memory}")

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


def mysql_setup(option: tuner.Option) -> bool:
    """Sets up options for mysql

    :param tuner.Option option: options object
    :return bool: whether setup was successful
    """
    if option.mysqladmin:
        mysqladmin_command: str = option.mysqladmin.strip()
    else:
        mysqladmin_command: str = shutil.which(u"mysqladmin").strip()

    if not os.path.exists(mysqladmin_command) and option.mysqladmin:
        option.bad_print(f"Unable to find the mysqladmin command you specified {mysqladmin_command}")
        raise FileNotFoundError
    elif not os.path.exists(mysqladmin_command):
        option.bad_print(u"Couldn't find mysqladmin in your $PATH. Is MySQL installed?")
        raise FileNotFoundError

    if option.mysqlcmd:
        mysql_command: str = option.mysqlcmd.strip()
    else:
        mysql_command: str = shutil.which(u"mysql").strip()

    if not os.path.exists(mysql_command) and option.mysqlcmd:
        option.bad_print(f"Unable to find the mysql command you specified {mysql_command}")
        raise FileNotFoundError
    elif not os.path.exists(mysql_command):
        option.bad_print(u"Couldn't find mysql in your $PATH. Is MySQL installed?")
        raise FileNotFoundError

    mysql_defaults_command: typ.Sequence[str] = (
        mysql_command,
        u"--print-defaults"
    )
    mysql_cli_defaults: str = util.get(mysql_defaults_command)
    option.debug_print(f"MySQL Client: {mysql_cli_defaults}")

    if re.match(r"auto-vertical-output", mysql_cli_defaults):
        option.bad_print(u"Avoid auto-vertical-output in configuration file(s) for MySQL like")
        raise Exception

    option.debug_print(f"MySQL Client {mysql_command}")

    option.port = 3306 if not option.port else option.port

    if option.socket:
        option.remote_connect: str = f"-S {option.socket} -P {option.port}"

    if option.host:
        option.host = option.host.strip()

        if not option.force_mem and option.host not in (u"127.0.0.1", u"localhost"):
            option.bad_print(u"The --force-mem option is required for remote connections")
            raise ConnectionRefusedError

        option.info_print(f"Performing tests on {option.host}:{option.port}")
        option.remote_connect: str = f"-h {option.host} -P {option.port}"

        if option.host not in (u"127.0.0.1", u"localhost"):
            option.do_remote: bool = True

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
            option.good_print(u"Logged in using credentials passed on the command line")
            return True
        else:
            option.bad_print(u"Attempted to use login credentials, but they were invalid")
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
                option.good_print(u"Logged in using credentials passed from mysql-quickbackup")
                return True
            else:
                option.bad_print(u"Attempted to use login credentials from mysql-quickbackup, they were invalid")
                raise ConnectionRefusedError

    elif util.is_readable(u"/etc/psa/.psa.shadow") and not option.do_remote:
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
                option.bad_print(u"Attempted to use login credentials from Plesk and Plesk 10+, but they failed")
                raise ConnectionRefusedError

    elif util.is_readable(u"/usr/local/directadmin/conf/mysql.conf") and not option.do_remote:
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
            option.bad_print(u"Attempted to use login credentials from DirectAdmin, but they failed")
            raise ConnectionRefusedError

    elif util.is_readable(u"/etc/mysql/debian.cnf") and not option.do_remote:
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
            option.good_print(u"Logged in using credentials from debian maintenance account.")
            return True
        else:
            option.bad_print(u"Attempted to use login credentials from DirectAdmin, but they failed")
            raise ConnectionRefusedError

    elif option.defaults_file and util.is_readable(option.defaults_file):
        # Defaults File
        option.debug_print(f"defaults file detected: {option.defaults_file}")

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
            option.good_print(u"Logged in using credentials from defaults file account.")
            return True
    else:
        # It's not Plesk or debian, we should try a login
        login_command: typ.Sequence[str] = (
            mysqladmin_command,
            option.remote_connect,
            u"ping",
            u"2>&1"
        )
        option.debug_print(u" ".join(login_command))

        login_status: str = util.get(login_command)

        if re.match(r"mysqld is alive", login_status):
            # Login went just fine
            # mysql_login: str = f" {option.remote_connect} u"

            # Did this go well because of a .my.cnf file or is there no password set?
            user_path: str = os.environ["HOME"].strip()
            if not os.path.exists(f"{user_path}/.my.cnf") and not os.path.exists(f"{user_path}/.mylogin.cnf"):
                option.bad_print(u"Successfully authenticated with no password - SECURITY RISK!")

            return True

        else:
            if option.no_ask:
                option.bad_print(u"Attempted to use login credentials, but they were invalid")
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
                        option.bad_print(u"Successfully authenticated with no password - SECURITY RISK!")

                return True
            else:
                option.bad_print(u"Attempted to use login credentials but they were invalid")
                raise ConnectionRefusedError


def tuning_info(sess: orm.session.Session) -> None:
    """Gathers tuning information

    :param orm.session.Session sess:
    :return:
    """
    result = sess.execute(r"\w\s")
    # TODO set result values
    for line in result.fetchall():
        pass


def mysql_status_vars(option: tuner.Option, info: tuner.Info, sess: orm.session.Session) -> None:
    """Gathers all status variables

    :param tuner.Option option: options object
    :param tuner.Info info: info object
    :param orm.session.Session sess: session
    :return:
    """
    # We need to initiate at least one query so that our data is usable
    try:
        result = sess.execute(u"SELECT VERSION() AS `VERSION`;")
    except Exception:
        option.bad_print(u"Not enough privileges for running PySQLTuner")
        raise

    # TODO set variables
    Version = clct.namedtuple(u"Version", result.keys())
    version: str = [
        Version(*version).VERSION.split("-")[0]
        for version in result.fetchall()
    ][0]

    option.debug_print(f"VERSION: {version}")
    # TODO set results value
    # TODO assign values to new lists

    if info.wsrep_provider_options:
        info.have_galera = True
        option.debug_print(f"Galera options: {info.wsrep_provider_options}")

    # Workaround for MySQL bug #59393 wrt. ignore-builtin-innodb
    if info.ignore_builtin_innodb:
        info.have_innodb = False

    # Support GTID MODE FOR MariaDB
    # Issue MariaDB GTID mode #272
    if info.gtid_strict_mode:
        info.gtid_mode = info.gtid_strict_mode

    if info.thread_pool_size > 0:
        info.have_threadpool = True

    # have_* for engines is deprecated and will be removed in MySQL 5.6;
    # check SHOW ENGINES and set corresponding old style variables.
    # Also works around MySQL bug #59393 wrt. skip-innodb
    # TODO engine stuff


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
    return any(
        re.search(port_pattern, open_port)
        for open_port in opened_ports()
    )


def fs_info(option: tuner.Option) -> typ.Sequence[typ.List[str], typ.List[str]]:
    """Recommendations for filesystem

    :param tuner.Option option:
    :return typ.Sequence[typ.List[str], typ.List[str]]: list of recommendations and list of adjusted variables
    """
    recommendations: typ.List[str] = []
    adjusted_vars: typ.List[str] = []

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
    s_info: typ.Sequence[str] = tuple(
        re.sub(info_filter, info_replace, info)
        for info in s_info
        for info_filter, info_replace in info_filters
    )

    for info in s_info:
        if re.match(r"(\d+)\t", info) and re.match(r"(run|dev|sys|proc)($|/)", info):
            continue
        matched = re.match(r"(\d+)\t(.*)", info)
        if matched:
            space_perc: str = matched.group(1)
            mount_point: str = matched.group(2)
            if int(matched.group(1)) > 85:
                option.bad_print(f"Mount point {mount_point} is using {space_perc} % total space")
                recommendations.append(
                    f"Add some space to {mount_point} mount point."
                )
            else:
                option.info_print(f"Mount point {mount_point} is using {space_perc} % total space")

            # TODO result object assigning

    for info in i_info:
        if re.match(r"(\d+)\t", info) and re.match(r"(run|dev|sys|proc)($|/)", info):
            continue
        matched = re.match(r"(\d+)\t(.*)", info)
        if matched:
            space_perc: str = matched.group(1)
            mount_point: str = matched.group(2)
            if int(matched.group(1)) > 85:
                option.bad_print(f"Mount point {mount_point} is using {space_perc} % of max allowed inodes")
                recommendations.append(
                    f"Add some space to {mount_point} mount point."
                )
            else:
                option.info_print(f"Mount point {mount_point} is using {space_perc} % of max allowed inodes")

            # TODO result object assigning

    return recommendations, adjusted_vars


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


def info_cmd(command: typ.Sequence[str], option: tuner.Option, delimiter: str = u"") -> None:
    """Runs commands and prints information

    :param typ.Sequence[str] command: sequence of strings which constitute command
    :param tuner.Option option: options object
    :param str delimiter: delimiter
    :return:
    """
    cmd: str = f"{command}"
    option.debug_print(f"CMD: {cmd}")

    result: str = tuple(
            info.strip()
            for info in util.get(command)
    )
    for info in result:
        option.info_print(f"{delimiter}{info}")


def kernel_info(option: tuner.Option) -> typ.Sequence[typ.List[str], typ.List[str]]:
    """Recommendations for kernel

    :param tuner.Option option:
    :return typ.Sequence[typ.List[str], typ.List[str]]: list of recommendations and list of adjusted variables
    """
    recommendations: typ.List[str] = []
    adjusted_vars: typ.List[str] = []

    params: typ.Sequence[str] = (
        u"fs.aio-max-nr",
        u"fs.aio-nr",
        u"fs.file-max",
        u"sunrpc.tcp_fin_timeout",
        u"sunrpc.tcp_max_slot_table_entries",
        u"sunrpc.tcp_slot_table_entries",
        u"vm.swappiness"
    )

    option.info_print(u"Information about kernel tuning:")

    for param in params:
        sysctl_devnull_command: typ.Sequence[str] = (
            u"sysctl",
            param,
            u"2>/dev/null"
        )
        info_cmd(sysctl_devnull_command, option, delimiter=u"\t")
        # TODO result setting

    sysctl_swap_command: typ.Sequence[str] = (
        u"sysctl",
        u"-n",
        u"vm.swappiness"
    )
    if int(util.get(sysctl_swap_command)) > 10:
        option.bad_print(u"Swappiness is > 10, please consider having a value lower than 10")
        recommendations.append(u"Setup swappiness  to be <= 10")
        adjusted_vars.append(u"vm.swappiness <= 10 (echo 0 > /proc/sys/vm/swappiness)")
    else:
        option.info_print(u"Swappiness is < 10.")

    # only if /proc/sys/sunrpc exists
    slot_table_command: typ.Sequence[str] = (
        u"sysctl",
        u"-n",
        u"sunrpc.tcp_slot_table_entries",
        u"2>/dev/null"
    )
    tcp_slot_entries: str = util.get(slot_table_command)

    if os.path.isfile(u"/proc/sys/sunrpc") and (not tcp_slot_entries or int(tcp_slot_entries) < 100):
        option.bad_print("Initial TCP slot entries is < 1M, please consider having a value greater than 100")
        recommendations.append(u"Setup Initial TCP slot entries > 100")
        adjusted_vars.append(
            u"sunrpc.tcp_slot_table_entries > 100 (echo 128 > /proc/sys/sunrpc/tcp_slot_table_entries)"
        )
    else:
        option.info_print(u"TCP slot entries is > 100.")

    aio_max_command: typ.Sequence[str] = (
        u"sysctl",
        u"-n",
        u"fs.aio-max-nr"
    )
    aio_max: str = util.get(aio_max_command)

    if aio_max < 1e6:
        option.bad_print((
                u"Max running total of the number of events is < 1M,"
                u"please consider having a value greater than 1M"
        ))
        recommendations.append(u"Setup max running number events greater than 1M")
        adjusted_vars.append(u"fs.aio-max-nr > 1M (echo 1048576 > /proc/sys/fs/aio-max-nr)")
    else:
        option.info_print(u"Max Number of AIO events is > 1M.")

    return recommendations, adjusted_vars


def system_info(option: tuner.Option) -> None:
    # TODO set results object
    os_release: str = platform.release()
    option.info_print(os_release)
    if is_virtual_machine():
        option.info_print(u"Machine Type:\t\t\t\t\t: Virtual Machine")
        # TODO set results object
    else:
        option.info_print(u"Machine Type:\t\t\t\t\t: Physical Machine")
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
        option.info_print(u"Internet\t\t\t\t\t: Connected")
        # TODO set results object
    else:

        option.bad_print(u"Internet\t\t\t\t\t: Disconnected")

    # TODO set several variables in results object

    core_command: typ.Sequence[str] = (
        u"nproc"
    )
    process_amount: int = int(util.get(core_command))
    option.info_print(f"Number of Core CPU : {process_amount}")

    os_type_command: typ.Sequence[str] = (
        u"uname",
        u"-o"
    )
    os_type: str = util.get(os_type_command)
    option.info_print(f"Operating System Type : {os_type}")

    kernel_release_command: typ.Sequence[str] = (
        u"uname",
        u"-r"
    )
    kernel_release: str = util.get(kernel_release_command)
    option.info_print(f"Kernel Release : {os_type}")

    hostname_command: typ.Sequence[str] = (
        u"hostname"
    )
    hostname: str = util.get(hostname_command)
    option.info_print(f"Hostname\t\t\t\t: {hostname}")

    ip_command: typ.Sequence[str] = (
        u"hostname",
        u"-I"
    )
    ip: str = util.get(ip_command)
    option.info_print(f"Internal IP\t\t\t\t: {ip}")

    network_card_command: typ.Sequence[str] = (
        u"ifconfig",
        u"|",
        u"grep",
        u"-A1",
        u"mtu"
    )
    option.info_print(u"Network Cards\t\t\t: ")
    info_cmd(network_card_command, option, delimiter=u"\t")

    try:
        external_ip: str = req.get(u"ipecho.net/plain")
        option.info_print(f"External IP\t\t\t\t: {external_ip}")
    except req.exceptions.MissingSchema as err:
        option.bad_print(f"External IP\t\t\t\t: Can't check because of Internet connectivity")
        raise err

    name_server_command: typ.Sequence[str] = (
        u"grep",
        u"'nameserver'",
        u"/etc/resolv.conf",
        u"\|",
        u"awk",
        u"'{print \$2}'"
    )
    name_servers: str = util.get(name_server_command)
    option.info_print(f"Name Servers\t\t\t\t: {name_servers}")

    option.info_print(u"Logged in Users\t\t\t\t:")
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
    option.info_print(f"Ram Usages in Mb\t\t: {ram}")

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


def system_recommendations(
    physical_memory: int,
    banned_ports: typ.Sequence[str],
    option: tuner.Option
) -> typ.Sequence[typ.List[str], typ.List[str]]:
    """Generates system level recommendations

    :param int physical_memory: amount of physical memory in bytes
    :param typ.Sequence[str] banned_ports: sequence of banned ports
    :param tuner.Option option: options object

    :return typ.Sequence[typ.List[str], typ.List[str]]: list of recommendations and list of adjusted variables
    """
    recommendations: typ.List[str] = []
    adjusted_vars: typ.List[str] = []

    if not option.sys_stat:
        return recommendations, adjusted_vars

    os_name: str = platform.system()
    if not re.match(r"Linux", os_name, re.IGNORECASE):
        option.info_print(u"Skipped due to non Linux Server")
        return recommendations, adjusted_vars

    option.pretty_print(u"Look for related Linux system recommendations")

    system_info(option)
    other_proc_mem: int = other_process_memory()

    option.info_print(f"User process except mysqld used {util.bytes_to_string(other_proc_mem)} RAM")

    if 0.15 * physical_memory < other_proc_mem:
        option.bad_print((
            u"Other user process except mysqld used more than 15% of total physical memory "
            f"{util.percentage(other_proc_mem, physical_memory)}% "
            f"({util.bytes_to_string(other_proc_mem)} / {util.bytes_to_string(physical_memory)})"
        ))
        recommendations.append(u"Consider stopping or dedicate server for additional process other than mysqld")
        adjusted_vars.append(
            u"DON'T APPLY SETTINGS BECAUSE THERE ARE TOO MANY PROCESSES RUNNING ON THIS SERVER. OOM KILL CAN OCCUR!"
        )
    else:
        option.info_print((
            u"Other user process except mysqld used more than 15% of total physical memory "
            f"{util.percentage(other_proc_mem, physical_memory)}% "
            f"({util.bytes_to_string(other_proc_mem)} / {util.bytes_to_string(physical_memory)})"
        ))

    if option.max_port_allowed > 0:
        open_ports: typ.Sequence[str] = opened_ports()
        option.info_print(f"There are {len(open_ports)} listening port(s) on this server")

        if len(open_ports) > option.max_port_allowed:
            option.bad_print((
                f"There are too many listening ports: "
                f"{len(open_ports)} opened > {option.max_port_allowed} allowed"
            ))
            recommendations.append(
                u"Consider dedicating a server for your database installation with less services running on!"
            )
        else:
            option.info_print(f"There are less than {option.max_port_allowed} opened ports on this server")

    for banned_port in banned_ports:
        if is_open_port(banned_port):
            option.bad_print(f"Banned port: {banned_port} is opened.")
            recommendations.append(f"Port {banned_port} is opened. Consider stopping program handling this port.")
        else:
            option.good_print(f"{banned_port} is not opened.")

    fs_recs, fs_vars = fs_info(option)
    kern_recs, kern_vars = kernel_info(option)

    recommendations.extend(fs_recs)
    recommendations.extend(kern_recs)

    adjusted_vars.extend(fs_vars)
    adjusted_vars.extend(kern_vars)

    return recommendations, adjusted_vars


def security_recommendations(
    option: tuner.Option,
    info: tuner.Info,
    sess: orm.session.Session
) -> typ.Sequence[typ.List[str], typ.List[str]]:
    """Security Recommendations

    :param tuner.Option option:
    :param tuner.Info info:
    :param orm.session.Session sess:

    :return typ.Sequence[typ.List[str], typ.List[str]]: list of recommendations and list of adjusted variables
    """
    recommendations: typ.List[str] = []
    adjusted_vars: typ.List[str] = []

    option.subheader_print(u"Security Recommendations")
    if option.skip_password:
        option.info_print(u"Skipped due to --skip-password option")
        return recommendations, adjusted_vars

    password_column: str = u"PASSWORD"
    if (info.ver_major, info.ver_minor) >= (5, 7):
        password_column = u"AUTHENTICATION_STRING"

    # Looking for Anonymous users
    mysql_user_query_file: str = osp.join(info.query_dir, u"user-query.sql")
    with open(mysql_user_query_file, mode=u"r", encoding=u"utf-8") as muqf:
        mysql_user_query: sqla.Text = sqla.text(muqf.read())
    result = sess.execute(mysql_user_query)
    User = clct.namedtuple(u"User", result.keys())
    users: typ.Sequence[str] = [
        User(*user).GRANTEE
        for user in result.fetchall()
    ]

    option.debug_print(f"{users}")

    if users:
        for user in sorted(users):
            option.bad_print(f"User '{user}' is an anonymous account.")
        recommendations.append(
            f"Remove Anonymous User accounts - there are {len(users)} anonymous accounts."
        )
    else:
        option.good_print(u"There are no anonymous accounts for any database users")

    if (info.ver_major, info.ver_minor, info.ver_micro) <= (5, 1):
        option.bad_print(u"No more password checks for MySQL <= 5.1")
        option.bad_print(u"MySQL version <= 5.1 are deprecated and are at end of support")
        return recommendations, adjusted_vars

    # Looking for Empty Password
    if (info.ver_major, info.ver_minor, info.ver_micro) >= (5, 5):
        mysql_password_query_file: str = osp.join(info.query_dir, f"password-query-5_5.sql")
    else:
        mysql_password_query_file: str = osp.join(info.query_dir, u"password-query-5_4.sql")

    with open(mysql_password_query_file, mode=u"r", encoding=u"utf-8") as mpqf:
        mysql_password_query: sqla.Text = sqla.text(mpqf.read())

    result = sess.execute(mysql_password_query, password_column=password_column)
    Password = clct.namedtuple(u"Password", result.keys())
    password_users: typ.Sequence[str] = [
        Password(*password).GRANTEE
        for password in result.fetchall()
    ]

    if password_users:
        for user in password_users:
            option.bad_print(f"User '{user}' has no password set.")
        recommendations.append((
            u"Set up a Password for user with the following SQL statement: "
            u"( SET PASSWORD FOR 'user'@'SpecificDNSorIp' = PASSWORD('secure_password'); )"
        ))
    else:
        option.good_print(u"All database users have passwords assigned")

    if (info.ver_major, info.ver_minor, info.ver_micro) >= (5, 7):
        mysql_plugin_query_file: str = osp.join(info.query_dir, u"plugin-query.sql")
        with open(mysql_plugin_query_file, mode=u"r", encoding=u"utf-8") as mpqf:
            mysql_plugin_query: sqla.Text = sqla.text(mpqf.read())

        result = sess.execute(mysql_plugin_query)
        Plugin = clct.namedtuple(u"Plugin", result.keys())
        plugin_amount: typ.Sequence[int] = int(*[
            Plugin(*plugin).COUNT
            for plugin in result.fetchall()
        ])

        if plugin_amount >= 1:
            option.info_print(u"Bug #80860 MySQL 5.7: Avoid testing password when validate_password is activated")
            return recommendations, adjusted_vars

    # Looking for User with user/ uppercase /capitalise user as password
    mysql_capitalize_query_file: str = osp.join(info.query_dir, f"capitalize-query.sql")
    with open(mysql_capitalize_query_file, mode=u"r", encoding=u"utf-8") as mcqf:
        mysql_capitalize_query: sqla.Text = sqla.text(mcqf.read())
    result = sess.execute(mysql_capitalize_query, password_column=password_column)
    Capitalize = clct.namedtuple(u"Capitalize", result.keys())
    capitalize_users: typ.Sequence[Capitalize] = [
        Capitalize(*user).GRANTEE
        for user in result.fetchall()
    ]

    if capitalize_users:
        for user in capitalize_users:
            option.bad_print(f"User '{user}' has user name as password")
        recommendations.append((
            u"Set up a Password for user with the following SQL statement: "
            u"( SET PASSWORD FOR 'user'@'SpecificDNSorIP' = PASSWORD('secure_password'); )"
        ))
    mysql_host_query_file: str = osp.join(info.query_dir, u"host-query.sql")
    with open(mysql_host_query_file, mode=u"r", encoding=u"utf-8") as mhqf:
        mysql_host_query: sqla.Text = sqla.text(mhqf.read())
    result = sess.execute(mysql_host_query)
    Host = clct.namedtuple(u"Host", result.keys())
    host_users: typ.Sequence[str] = [
        Host(*user).GRANTEE
        for user in result.fetchall()
    ]

    if host_users:
        for user in host_users:
            option.bad_print(f"User '{user}' does not have specific host restrictions.")
        recommendations.append(u"Restrict Host for 'user'@'%' to 'user'@SpecificDNSorIP'")

    if os.path.isfile(option.basic_passwords_file):
        option.bad_print(u"There is no basic password file list!")
        return recommendations, adjusted_vars

    with open(option.basic_passwords_file, mode=u"r", encoding=u"utf-8") as bpf:
        passwords: typ.Sequence[str] = bpf.readlines()

    option.info_print(f"There are {len(passwords)} basic passwords in the list")
    bad_amount: int = 0

    if passwords:
        interpass_amount = 0
        for password in passwords:
            interpass_amount += 1

            # Looking for User with user/ uppercase /capitalise user as password
            mysql_capital_password_query_file: str = osp.join(info.query_dir, u"capital-password-query.sql")
            with open(mysql_capital_password_query_file, mode=u"r", encoding=u"utf-8") as mcpqf:
                mysql_capital_password_query: sqla.Text = sqla.text(mcpqf.read())
            result = sess.execute(mysql_capital_password_query, password=password, password_column=password_column)
            CapitalPassword = clct.namedtuple(u"CapitalPassword", result.keys())
            capital_password_users: typ.Sequence[str] = [
                CapitalPassword(*user).GRANTEE
                for user in result.fetchall()
            ]

            option.debug_print(f"There are {len(capital_password_users)} items.")
            if capital_password_users:
                for user in capital_password_users:
                    option.bad_print((
                        f"User '{user}' is using weak password: "
                        f"{password} in a lower, upper, or capitalized derivative version."
                    ))
                    bad_amount += 1
            if interpass_amount % 1000 == 0:
                option.debug_print(f"{interpass_amount} / {len(passwords)}")
    if bad_amount > 0:
        recommendations.append(
            f"{bad_amount} user(s) used a basic or weak password."
        )

    return recommendations, adjusted_vars


def replication_status(option: tuner.Option) -> None:
    option.subheader_print(u"Replication Metrics")
    # TODO get info from variable gathering function
    # option.info_print(f"Galera Synchronous replication {option.}")


def validate_mysql_version(option: tuner.Option, info: tuner.Info) -> None:
    """Check MySQL Version

    :param tuner.Option option: option object
    :param tuner.Info info: info object

    :return:
    """
    full_version: str = f"{info.ver_major}.{info.ver_minor}.{info.ver_micro}"

    if (info.ver_major, info.ver_major, info.ver_micro) < (5, 1):
        option.bad_print(f"Your MySQL version {full_version} is EOL software! Upgrade soon!")
    elif (6 <= info.ver_major <= 9) or info.ver_major >= 12:
        option.bad_print(f"Currently running unsupported MySQL version {full_version}")
    else:
        option.good_print(f"Currently running supported MySQL version {full_version}")


def check_architecture(option: tuner.Option, physical_memory: int) -> None:
    """Checks architecture of system

    :param tuner.Option option: options object
    :param int physical_memory: Physical memory in bytes
    :return:
    """
    # Checks for 32-bit boxes with more than 2GB of RAM
    if option.do_remote:
        return
    arch_bit: str = platform.architecture()[0]
    if "64" in arch_bit:
        option.good_print("Operating on 64-bit architecture")
    else:
        if physical_memory > 2 ** 31:
            option.bad_print(u"Switch to 64-bit OS - MySQL cannot currently use all of your RAM")
        else:
            option.good_print(u"Operating on a 32-bit architecture with less than 2GB RAM")

        # TODO set architecture to result object


def check_storage_engines(
    option: tuner.Option,
    info: tuner.Info,
    sess: orm.session.Session
) -> typ.Sequence[typ.List[str], typ.List[str]]:
    """Storage Engine information

    :param tuner.Option option:
    :param tuner.Info info:
    :param orm.session.Session sess:

    :return typ.Sequence[typ.List[str], typ.List[str]]: list of recommendations and list of adjusted variables
    """
    recommendations: typ.List[str] = []
    adjusted_vars: typ.List[str] = []

    option.subheader_print(u"Storage Engine Statistics")
    if option.skip_size:
        option.info_print(u"Skipped due to --skip-size option")
        return recommendations, adjusted_vars

    engines: str = ""
    if (info.ver_major, info.ver_minor, info.ver_micro) >= (5, 1, 5):
        engine_version: str = u"5_1"
        if (info.ver_major, info.ver_minor) == (5, 5):
            engine_version = u"5_5"

        engine_support_query_file: str = osp.join(info.query_dir, f"engine-support-query={engine_version}.sql")

        with open(engine_support_query_file, mode=u"r", encoding=u"utf-8") as esqf:
            engine_support_query: str = esqf.read()
        result = sess.execute(engine_support_query)
        EngineSupport = clct.namedtuple(u"EngineSupport", result.keys())
        engine_supports: typ.Sequence[str, str] = [
            (engine_support.ENGINE, engine_support.SUPPORT)
            for engine_support in [
                EngineSupport(*engine_support)
                for engine_support in result.fetchall()
            ]
        ]
        for engine, support in engine_supports:
            if engine.strip() and support.strip():
                # TODO set result variable
                if support in (u"YES", u"ENABLES"):
                    engine_part: str = option.green_wrap(f"+{engine} ")
                else:
                    engine_part: str = option.red_wrap(f"+{engine} ")
                engines += engine_part
    else:
        # TODO need variable object to pick which parts to print
        engines += option.green_wrap(u"+Archive") if info.have_archive else option.red_wrap(u"-Archive")
        engines += option.green_wrap(u"+BDB") if info.have_bdb else option.red_wrap(u"-BDB")
        engines += (
            option.green_wrap(u"+Federated")
            if info.have_federated_engine
            else option.red_wrap(u"-Federated")
        )
        engines += option.green_wrap(u"+InnoDB") if info.have_innodb else option.red_wrap(u"-InnoDB")
        engines += option.green_wrap(u"+MyISAM") if info.have_myisam else option.red_wrap(u"-MyISAM")
        engines += (
            option.green_wrap(u"+NDBCluster")
            if info.have_ndb_cluster
            else option.red_wrap(u"-NDBCLuster")
        )

    database_query: str = u"SHOW DATABASES;"
    result = sess.execute(database_query)
    Database = clct.namedtuple(u"Database", result.keys())
    databases: typ.Sequence[str] = [
        Database(*database).Database
        for database in result.fetchall()
    ]
    # TODO set result variable

    option.info_print(f"Status {engines}")

    if (info.ver_major, info.ver_minor, info.ver_micro) >= (5, 1, 5):
        # MySQL 5 servers can have table sizes calculated quickly from information schema
        engine_query_file: str = osp.join(info.query_dir, u"engine-query.sql")
        with open(engine_query_file, mode=u"r", encoding=u"utf-8") as eqf:
            engine_query: str = eqf.read()
        result = sess.execute(engine_query)
        Engine = clct.namedtuple(u"Engine", result.keys())
        engine_sizes: typ.Sequence[str, int, int, int, int] = [
            (engine.ENGINE, engine.SIZE, engine.COUNT, engine.DATA_SIZE, engine.INDEX_SIZE)
            for engine in [
                Engine(*engine)
                for engine in result.fetchall()
            ]
        ]

        for engine, size, count, data_size, index_size in engine_sizes:
            option.debug_print(f"Engine Found: {engine}")
            if not engine:
                continue
            # TODO set stats and count and results variables
    else:
        tables: typ.Sequence[str] = []
        # MySQL < 5 servers take a lot of work to get table sizes
        # Now we build a database list, and loop through it to get storage engine stats for tables
        for database in databases:
            if database.strip() in (
                u"information_schema",
                u"mysql",
                u"performance_schema",
                u"lost+found"
            ):
                continue

            indexes: typ.Tuple[int, int, int] = (1, 6, 9)

            if __name__ == '__main__':
                if (info.ver_major, info.ver_minor, info.ver_micro) < (4, 1):
                    # MySQL 3.23/4.0 keeps Data_Length in the 5th (0-based) column
                    indexes = (1, 5, 8)

                # TODO append to tables list based on query
            # Parse through the table list to generate storage engine counts/statistics
            # TODO parse through tables to gather sizes

        # TODO set variables and add recommendations
        # TODO defragment tables
        # TODO etc

    return recommendations, adjusted_vars


def calculations(
    sess: orm.session.Session,
    option: tuner.Option,
    info: tuner.Info,
    stat: tuner.Stat,
    calc: tuner.Calc
) -> None:
    if stat.questions < 1:
        option.bad_print(u"Your server has not answered any queries - cannot continue...")
        raise NotImplementedError

    # Per-thread Memory
    if (info.ver_major, info.ver_minor, info.ver_micro) >= (4,):
        calc.per_thread_buffers = (
            info.read_buffer_size +
            info.read_rnd_buffer_size +
            info.sort_buffer_size +
            info.thread_stack +
            info.join_buffer_size
        )
    else:
        calc.per_thread_buffers = (
            info.record_buffer +
            info.record_rnd_buffer +
            info.sort_buffer_size +
            info.thread_stack +
            info.join_buffer_size
        )

    calc.total_per_thread_buffers = calc.per_thread_buffers * info.max_connections
    calc.max_total_per_thread_buffers = calc.per_thread_buffers * stat.max_used_connections

    # Server-wide Memory
    calc.max_temp_table_size = max(info.temp_table_size, info.max_heap_table_size)
    calc.server_buffers = (
        info.key_buffer_size +
        calc.max_temp_table_size +
        info.innodb_buffer_pool_size +
        info.innodb_additional_mem_pool_size +
        info.innodb_log_buffer_size +
        info.query_cache_size +
        info.ariadb_pagecache_buffer_size
    )

    # Global Memory
    # Max used memory is memory used by MySQL based on Max_used_connections
    # This is the max memory used theoretically calculated with the max concurrent connection number reached by mysql
    calc.max_peak_memory = (
        calc.server_buffers +
        calc.max_total_per_thread_buffers +
        performance_memory(info, sess) +
        gcache_memory(option, info)
    )
    calc.pct_max_physical_memory = util.percentage(calc.max_peak_memory, stat.physical_memory)

    option.debug_print(f"Max Used Memory: {util.bytes_to_string(calc.max_used_memory)}")
    option.debug_print(f"Max Used Percentage RAM: {util.bytes_to_string(calc.pct_max_used_memory)}%")
    option.debug_print(f"Max Peak Memory: {util.bytes_to_string(calc.max_peak_memory)}")
    option.debug_print(f"Max Peak Percentage RAM: {util.bytes_to_string(calc.pct_max_physical_memory)}%")

    # Slow Queries
    calc.pct_slow_queries = int(stat.slow_queries / stat.questions * 100)

    # Connections
    calc.pct_connections_used = int(stat.max_used_connections / info.max_connections)
    calc.pct_connections_used = min(calc.pct_connections_used, 100)

    # Aborted Connections
    calc.pct_connections_aborted = util.percentage(stat.aborted_connections, stat.connections)
    option.debug_print(f"Aborted Connections: {stat.aborted_connections}")
    option.debug_print(f"Connections: {stat.connections}")
    option.debug_print(f"Percent of Connections Aborted {calc.pct_connections_aborted}")

    # Key Buffers
    if (info.ver_major, info.ver_minor, info.ver_micro) >= (4, 1) and info.key_buffer_size > 0:
        calc.pct_key_buffer_used = round(100 * (
            1 - (
                stat.key_blocks_unused *
                info.key_cache_block_size /
                info.key_buffer_size
            )
        ), 1)

    if stat.key_read_requests > 0:
        calc.pct_keys_from_memory = round(100 * (
            1 - (
                stat.key_reads /
                stat.key_read_requests
            )
        ), 1)

    if stat.ariadb_pagecache_read_requests > 0:
        calc.pct_ariadb_keys_from_memory = round(100 * (
            1 - (
                stat.ariadb_pagecache_reads /
                stat.ariadb_pagecache_read_requests
            )
        ), 1)

    if stat.key_write_requests > 0:
        calc.pct_write_keys_from_memory = round(100 * (
            1 - (
                stat.key_writes /
                stat.key_write_requests
            )
        ), 1)

    if option.do_remote and info.ver_major < 5:
        size: int = 0
        index_size_command: typ.Sequence[str] = u" ".join((
            u"find",
            f"{info.data_dir}",
            u"-name",
            u"'*MYI'",
            u"2>&1",
            u"|",
            u"xargs du -L"
            f"{stat.du_flags}",
            u"2>&1"
        ))
        index_size: int = int(util.get(index_size_command).split()[0])
        size += index_size

        calc.total_myisam_indexes = size
        calc.total_ariadb_indexes = 0
    elif info.ver_major >= 5:
        myisam_index_query_file: str = osp.join(info.query_dir, u"myisam-index-query.sql")
        with open(myisam_index_query_file, mode=u"r", encoding=u"utf-8") as miqf:
            myisam_query: sqla.Text = sqla.text(miqf.read())
            result = sess.execute(myisam_query)
            Index = clct.namedtuple(u"Index", result.keys())
            index_sizes: typ.Sequence[int] = [
                index.INDEX_LENGTH
                for index in [
                    Index(*index)
                    for index in result.fetchall()
                ]
            ]

            for index_size in index_sizes:
                calc.total_myisam_indexes += index_size

        ariadb_index_query_file: str = osp.join(info.query_dir, u"aria-index-query.sql")
        with open(ariadb_index_query_file, mode=u"r", encoding=u"utf-8") as aqf:
            ariadb_query: sqla.Text = sqla.text(aqf.read())
            result = sess.execute(ariadb_query)
            Index = clct.namedtuple(u"Index", result.keys())
            index_sizes: typ.Sequence[int] = [
                index.INDEX_LENGTH
                for index in [
                    Index(*index)
                    for index in result.fetchall()
                ]
            ]

            for index_size in index_sizes:
                calc.total_ariadb_indexes += index_size

    if not calc.total_myisam_indexes:
        calc.total_myisam_indexes = 0

    if not calc.total_ariadb_indexes:
        calc.total_ariadb_indexes = 1

    # Query Cache
    if info.ver_major >= 4:
        calc.query_cache_efficiency = (round(100 * (
            stat.query_cache_hits / (stat.com_select + stat.query_cache_hits)
        ), ndigits=1))

        if info.query_cache_size:
            calc.pct_query_cache_used = (round(100 - (
                (stat.query_cache_free_memory / info.query_cache_size * 100)
            ), ndigits=1))

        if stat.query_cache_low_memory_prunes != 0:
            calc.query_cache_prunes_per_day = int(
                stat.query_cache_low_memory_prunes / stat.uptime
            )

    # Sorting
    calc.total_sorts = stat.sort_scan + stat.sort_range
    if calc.total_sorts > 0:
        calc.pct_temp_sort_table = int(
            stat.sort_merge_passes / calc.total_sorts * 100
        )

    # Joins
    calc.joins_without_indexes = stat.select_range_check + stat.select_full_join
    calc.joins_without_indexes_per_day = int(
        calc.joins_without_indexes / stat.uptime / 86400
    )

    # Temporary tables
    if stat.created_temp_tables > 0:
        if stat.created_temp_disk_tables > 0:
            calc.pct_temp_disk = int(
                stat.created_temp_disk_tables / stat.created_temp_tables * 100
            )

    # Table cache
    if stat.opened_tables > 0:
        calc.table_cache_hit_rate = int(
            stat.open_tables / stat.opened_tables * 100
        )
    else:
        calc.table_cache_hit_rate = 100

    # Open files
    if info.open_files_limit > 0:
        calc.pct_files_open = int(
            stat.open_files / info.open_files_limit * 100
        )

    # Table locks
    if stat.immediate_table_locks > 0:
        if stat.waited_table_locks == 0:
            calc.pct_immediate_table_locks = 100
        else:
            calc.pct_immediate_table_locks = int(
                stat.immediate_table_locks / (stat.waited_table_locks + stat.immediate_table_locks) * 100
            )

    # Thread cache
    calc.thread_cache_hit_rate = int(100 - (
        stat.created_threads / stat.connections * 100
    ))

    # Other
    if stat.connections > 0:
        calc.pct_connections_aborted = int(
            stat.aborted_connections / stat.connections * 100
        )

    if stat.questions > 0:
        calc.total_reads = stat.com_select
        calc.total_writes = (
            stat.com_delete +
            stat.com_insert +
            stat.com_update +
            stat.com_replace
        )

        if calc.total_reads == 0:
            calc.pct_reads = 0
        else:
            calc.pct_reads = int(
                calc.total_reads / (calc.total_reads + calc.total_writes) * 100
            )

    # InnoDB
    if info.have_innodb:
        calc.innodb_log_size_pct = int(
            info.innodb_log_file_size * info.innodb_log_files_in_group / info.innodb_buffer_pool_size * 100
        )

    # InnoDB Buffer pool read cache efficiency
    calc.pct_read_efficiency = util.percentage(
        stat.innodb_buffer_pool_read_requests - stat.innodb_buffer_pool_reads
    )
    option.debug_print(f"pct_read_efficiency: {calc.pct_read_efficiency}")
    option.debug_print(f"innodb_buffer_pool_reads: {stat.innodb_buffer_pool_reads}")
    option.debug_print(f"innodb_buffer_pool_read_requests: {stat.innodb_buffer_pool_read_requests}")

    # InnoDB log write cache efficiency
    calc.pct_write_efficiency = util.percentage(
        stat.innodb_log_write_requests - stat.innodb_log_writes
    )
    option.debug_print(f"pct_write_efficiency: {calc.pct_write_efficiency}")
    option.debug_print(f"innodb_log_writes: {stat.innodb_log_writes}")
    option.debug_print(f"innodb_log_write_requests: {stat.innodb_log_write_requests}")

    if stat.innodb_buffer_pool_pages_total > 0:
        calc.pct_innodb_buffer_used = util.percentage(
            stat.innodb_buffer_pool_pages_total - stat.innodb_buffer_pool_pages_free
        )

    # Binlog Cache
    if info.log_bin:
        calc.pct_binlog_cache = util.percentage(
            stat.binlog_cache_use - stat.binlog_cache_disk_use,
            stat.binlog_cache_use
        )


# TODO finish mysql stats function
def mysql_stats(
    option: tuner.Option,
    info: tuner.Info,
    stat: tuner.Stat,
    calc: tuner.Calc
 ) -> typ.Sequence[typ.List[str], typ.List[str]]:
    """MySQL stats

    :param tuner.Option option:
    :param tuner.Info info:
    :param tuner.Stat stat:
    :param tuenr.Calc calc:

    :return typ.Sequence[typ.List[str], typ.List[str]]: list of recommendations and list of adjusted variables
    """
    recommendations: typ.List[str] = []
    adjusted_vars: typ.List[str] = []

    option.subheader_print(u"Performance Metrics")
    # Show uptime, queries per second, connections, traffic stats
    if stat.uptime > 0:
        qps: str = f"{round(stat.questions / stat.uptime, 3)}"

    if stat.uptime < 86400:
        recommendations.append(u"MySQL started within last 24 hours - recommendations may be inaccurate")

    option.info_print(u" ".join((
        f"Up for: {util.pretty_uptime(stat.uptime)}",
        f"({stat.questions} q [{qps} qps], {stat.connections} conn",
        f"TX: {util.bytes_to_string(stat.bytes_sent)}, RX: {util.bytes_to_string(stat.bytes_received)})"
    )))

    option.info_print(f"Reads / Writes {calc.pct_reads}% / {calc.pct_writes}%")

    # Binlog Cache
    if not info.log_bin:
        option.info_print(u"Binary logging is not enabled")
    else:
        option.info_print(f"Binary logging is enabled (GTID MODE: {info.gtid_mode}")

    # Memory Usage
    option.info_print(f"Physical Memory       : {util.bytes_to_string(stat.physical_memory)}")
    option.info_print(f"Max MySQL Memory      : {util.bytes_to_string(calc.max_peak_memory)}")
    option.info_print(f"Other Process Memory  : {util.bytes_to_string(other_process_memory())}")

    return recommendations, adjusted_vars


def mysql_myisam(
    option: tuner.Option,
    info: tuner.Info,
    stat: tuner.Stat,
    calc: tuner.Calc
 ) -> typ.Sequence[typ.List[str], typ.List[str]]:
    """Recommendations for MyISAM

    :param tuner.Option option:
    :param tuner.Info info:
    :param tuner.Stat stat:
    :param tuenr.Calc calc:

    :return typ.Sequence[typ.List[str], typ.List[str]]: list of recommendations and list of adjusted variables
    """
    recommendations: typ.List[str] = []
    adjusted_vars: typ.List[str] = []

    option.subheader_print(u"MyISAM Metrics")

    # Key Buffer usage
    key_buffer_used_msg: str = (
        f"Key Buffer used: {calc.pct_key_buffer_used}% "
        f"({util.bytes_to_string(info.key_buffer_size * calc.pct_key_buffer_used / 100)} "
        f"used / {util.bytes_to_string(info.key_buffer_size)} cache)"
    )

    if calc.pct_key_buffer_used == 90:
        option.debug_print(key_buffer_used_msg)
    elif calc.pct_key_buffer_used < 90:
        option.bad_print(key_buffer_used_msg)
    else:
        option.good_print(key_buffer_used_msg)

    # Key Buffer
    if calc.total_myisam_indexes == 0 and option.do_remote:
        recommendations.append(u"Unable to calculate MyISAM indexes on remote MySQL server < 5.0.0")
    elif calc.total_myisam_indexes == 0:
        option.bad_print(u"None of your MyISAM tables are indexed - add indexes immediately")
    else:
        key_buffer_size_msg: str = (
            f"Key Buffer Size / Total MyISAM indexes: "
            f"{util.bytes_to_string(info.key_buffer_size)} / "
            f"{util.bytes_to_string(calc.total_myisam_indexes)}"
        )
        if info.key_buffer_size < calc.total_myisam_indexes and calc.pct_keys_from_memory < 95:
            option.bad_print(key_buffer_size_msg)
            adjusted_vars.append(f"key_buffer_size (> {util.bytes_to_string(calc.total_myisam_indexes)})")
        else:
            option.good_print(key_buffer_size_msg)

        read_key_buffer_msg: str = (
            f"Read Key Buffer Hit Rate: {calc.pct_keys_from_memory}% "
            f"({util.bytes_to_string(stat.key_read_requests)} cached / "
            f"{util.bytes_to_string(stat.key_reads)} reads)"
        )
        if stat.key_read_requests > 0:
            if calc.pct_keys_from_memory < 95:
                option.bad_print(read_key_buffer_msg)
            else:
                option.good_print(read_key_buffer_msg)
        else:
            # No Queries have run that would use keys
            option.debug_print(read_key_buffer_msg)

        write_key_buffer_msg: str = (
            f"Write Key Buffer Hit Rate: {calc.pct_write_keys_from_memory}% "
            f"({util.bytes_to_string(stat.key_write_requests)} cached / "
            f"{util.bytes_to_string(stat.key_writes)} writes)"
        )
        if stat.key_write_requests > 0:
            if calc.pct_write_keys_from_memory < 95:
                option.bad_print(write_key_buffer_msg)
            else:
                option.good_print(write_key_buffer_msg)
        else:
            # No Queries have run that would use keys
            option.debug_print(write_key_buffer_msg)

    return recommendations, adjusted_vars


def mariadb_threadpool(option: tuner.Option, info: tuner.Info) -> typ.Sequence[typ.List[str], typ.List[str]]:
    """Recommendations for ThreadPool

    :param tuner.Option option:
    :param tuner.Info info:
    :return typ.Sequence[typ.List[str], typ.List[str]]: list of recommendations and list of adjusted variables
    """
    recommendations: typ.List[str] = []
    adjusted_vars: typ.List[str] = []

    option.subheader_print(u"ThreadPool Metrics")

    # AriaDB
    if not info.have_threadpool:
        option.info_print(u"ThreadPool stat is disabled.")
        return recommendations, adjusted_vars

    option.info_print(u"ThreadPool stat is enabled.")
    option.info_print(f"Thread Pool size: {info.thread_pool_size} thread(s)")

    versions: typ.Sequence[str] = (
        u"mariadb",
        u"percona"
    )
    if any(version in info.version.lower() for version in versions):
        option.info_print(f"Using default value is good enough for your version ({info.version})")
        return recommendations, adjusted_vars

    if info.have_innodb:
        if info.thread_pool_size < 16 or info.thread_pool_size > 36:
            option.bad_print(u"thread_pool_size between 16 and 36 when using InnoDB storage engine.")
            recommendations.append(
                f"Thread Pool size for InnoDB usage ({info.thread_pool_size})"
            )
            adjusted_vars.append(
                u"thread_pool_size between 16 and 36 for InnoDB usage"
            )
        else:
            option.good_print(u"thread_pool_size between 16 and 36 when using InnoDB storage engine")

    if info.have_myisam:
        if info.thread_pool_size < 4 or info.thread_pool_size > 8:
            option.bad_print(u"thread_pool_size between 4 and 8 when using MyISAM storage engine.")
            recommendations.append(
                f"Thread Pool size for MyISAM usage ({info.thread_pool_size})"
            )
            adjusted_vars.append(
                u"thread_pool_size between 4 and 8 for MyISAM usage"
            )
        else:
            option.good_print(u"thread_pool_size between 4 and 8 when using MyISAM storage engine")

    return recommendations, adjusted_vars


def performance_memory(info: tuner.Info, sess: orm.session.Session) -> int:
    """Gets Performance schema memory taken

    :param tuner.Info info:
    :param orm.session.Session sess:
    :return int:
    """
    # Performance Schema
    if not info.performance_schema:
        return 0

    pf_memory_query_file: str = osp.join(info.query_dir, u"performance_schema-memory-query.sql")
    with open(pf_memory_query_file, mode=u"r", encoding=u"utf-8") as pfmqf:
        pf_memory_query: sqla.Text = sqla.text(pfmqf.read())
        result = sess.execute(pf_memory_query)
        Memory = clct.namedtuple(u"Memory", result.keys())
        memory_sizes: typ.Sequence[int] = [
            memory.DATA_LENGTH
            for memory in [
                Memory(*memory)
                for memory in result.fetchall()
            ]
        ]
    return sum(memory_sizes)


# TODO 1500 line function
def mysql_pfs(
    sess: orm.session.Session,
    option: tuner.Option,
    info: tuner.Info,
    stat: tuner.Stat,
    calc: tuner.Calc
) -> typ.Sequence[typ.List[str], typ.List[str]]:
    """

    :param orm.session.Session sess:
    :param tuner.Option option:
    :param tuner.Info info:
    :param tuner.Stat stat:
    :param tuenr.Calc calc:

    :return typ.Sequence[typ.List[str], typ.List[str]]: list of recommendations and list of adjusted variables
    """
    recommendations: typ.List[str] = []
    adjusted_vars: typ.List[str] = []

    return recommendations, adjusted_vars


def mariadb_ariadb(
    option: tuner.Option,
    info: tuner.Info,
    calc: tuner.Calc,
    stat: tuner.Stat
) -> typ.Sequence[typ.List[str], typ.List[str]]:
    """Recommendations for AriaDB

    :param tuner.Option option:
    :param tuner.Info info:
    :param tuner.Calc calc:
    :param tuner.Stat stat:

    :return typ.Sequence[typ.List[str], typ.List[str]]: list of recommendations and list of adjusted variables
    """
    recommendations: typ.List[str] = []
    adjusted_vars: typ.List[str] = []

    # AriaDB
    if not info.have_ariadb:
        option.info_print(u"AriaDB is disabled.")
        return recommendations, adjusted_vars

    option.info_print(u"AriaDB is enabled.")

    # Aria pagecache
    if calc.total_ariadb_indexes == 0 and option.do_remote:
        recommendations.append(
            u"Unable to calculate AriaDB indexes on remote MySQL server < 5.0.0"
        )
    elif calc.total_ariadb_indexes == 0:
        option.bad_print(u"None of your AriaDB tables are indexed - add indexes immediately")
    else:
        ariadb_pagecache_size_message: str = (
            u"AriaDB pagecache size / total AriaDB indexes: "
            f"{util.bytes_to_string(info.ariadb_pagecache_buffer_size)}/"
            f"{util.bytes_to_string(calc.total_ariadb_indexes)}"
        )
        if info.ariadb_pagecache_buffer_size < calc.total_ariadb_indexes and calc.pct_ariadb_keys_from_memory < 95:
            option.bad_print(ariadb_pagecache_size_message)
            adjusted_vars.append(
                f"ariadb_pagecache_buffer_size (> {util.bytes_to_string(calc.total_ariadb_indexes)})"
            )
        else:
            option.good_print(ariadb_pagecache_size_message)

        if stat.ariadb_pagecache_read_requests > 0:
            ariadb_pagecache_read_message: str = (
                f"AriaDB pagecache hit rate: {calc.pct_ariadb_keys_from_memory}% ("
                f"{util.bytes_to_string(stat.ariadb_pagecache_read_requests)} cached /"
                f"{util.bytes_to_string(stat.ariadb_pagecache_read_requests)} reads)"
            )
            if calc.pct_ariadb_keys_from_memory < 95:
                option.bad_print(ariadb_pagecache_read_message)
            else:
                option.good_print(ariadb_pagecache_read_message)

    return recommendations, adjusted_vars


def mariadb_tokudb(option: tuner.Option, info: tuner.Info) -> None:
    """Recommendations for TokuDB

    :param tuner.Option option:
    :param tuner.Info info:
    :return:
    """
    option.subheader_print(u"TokuDB Metrics")

    # Toku DB
    if not info.have_tokudb:
        option.info_print(u"TokuDB is disabled.")
        return

    option.info_print(u"TokuDB is enabled.")


def mariadb_xtradb(option: tuner.Option, info: tuner.Info) -> None:
    """Recommendations for XtraDB

    :param tuner.Option option:
    :param tuner.Info info:
    :return:
    """
    option.subheader_print(u"XtraDB Metrics")

    # Xtra DB
    if not info.have_xtradb:
        option.info_print(u"XtraDB is disabled.")
        return

    option.info_print(u"XtraDB is enabled.")


def mariadb_rocksdb(option: tuner.Option, info: tuner.Info) -> None:
    """Recommendations for RocksDB

    :param tuner.Option option:
    :param tuner.Info info:
    :return:
    """
    option.subheader_print(u"RocksDB Metrics")

    # Rocks DB
    if not info.have_rocksdb:
        option.info_print(u"RocksDB is disabled.")
        return

    option.info_print(u"RocksDB is enabled.")


def mariadb_spider(option: tuner.Option, info: tuner.Info) -> None:
    """Recommendations for Spider

    :param tuner.Option option:
    :param tuner.Info info:
    :return:
    """
    option.subheader_print(u"Spider Metrics")

    # Toku DB
    if not info.have_spider:
        option.info_print(u"Spider is disabled.")
        return

    option.info_print(u"Spider is enabled.")


def mariadb_connect(option: tuner.Option, info: tuner.Info) -> None:
    """Recommendations for Connect

    :param tuner.Option option:
    :param tuner.Info info:
    :return:
    """
    option.subheader_print(u"Connect Metrics")

    # Toku DB
    if not info.have_connect:
        option.info_print(u"Connect is disabled.")
        return

    option.info_print(u"Connect is enabled.")


def wsrep_options(option: tuner.Option, info: tuner.Info) -> typ.Sequence[str]:
    """

    :param tuner.Option option:
    :param tuner.Info info:
    :return:
    """
    if not info.wsrep_provider_options:
        return []

    galera_options: typ.Sequence[str] = [
        wsrep.strip()
        for wsrep in info.wsrep_provider_options.split(u";")
        if wsrep.strip()
    ]

    option.debug_print(f"{galera_options}")

    return galera_options


def wsrep_option(option: tuner.Option, info: tuner.Info, key: str) -> int:
    """

    :param tuner.Option option:
    :param tuner.Info info:
    :param str key:
    :return str:
    """
    if not info.wsrep_provider_options:
        return 0

    galera_options: typ.Sequence[str] = wsrep_options(option, info)
    if not galera_options:
        return 0

    galera_match: str = f"\s*{key} ="
    memory_values: typ.Sequence[str] = [
        galera_option for galera_option in galera_options
        if re.match(galera_match, galera_option)
    ]

    return util.string_to_bytes(memory_values[0])


def gcache_memory(option: tuner.Option, info: tuner.Info) -> int:
    """

    :param tuner.Option option:
    :param tuner.Info info:
    :return int:
    """
    return wsrep_option(option, info, u"gcache.size")


def mariadb_galera(
    sess: orm.session.Session,
    option: tuner.Option,
    info: tuner.Info,
    stat: tuner.Stat
) -> typ.Sequence[typ.List[str], typ.List[str]]:
    """Recommendations for Galera

    :param orm.session.Session sess:
    :param tuner.Option option:
    :param tuner.Info info:
    :param tuner.Stat stat:
    :return typ.Sequence[typ.List[str], typ.List[str]]: list of recommendations and list of adjusted variables
    """
    recommendations: typ.List[str] = []
    adjusted_vars: typ.List[str] = []

    # TODO fill galera mariadb in -- needs result
    option.subheader_print(u"Galera Metrics")

    # Galera Cluster
    if not info.have_galera:
        option.info_print(u"Galera is disabled.")

    option.info_print(u"Galera is enabled.")
    # option.debug_print(u"Galera variables:")
    # TODO set result object

    option.debug_print(u"Galera wsrep provider options:")
    galera_options: typ.Sequence[str] = wsrep_options(option, info)
    # TODO set result object
    for galera_option in galera_options:
        option.debug_print(f"\t{galera_option.strip()}")

    # option.debug_print(u"Galera status:")
    # TODO set result object

    option.info_print(f"GCache is using {util.bytes_to_string(wsrep_option(option, info, key=u'gcache.mem_size'))}")

    wsrep_slave_threads: int = wsrep_option(option, info, key=u"wsrep_slave_threads")
    cpu_count: int = psu.cpu_count()
    if wsrep_slave_threads < 3 * cpu_count or wsrep_slave_threads > 4 * cpu_count:
        option.bad_print(u"wsrep_slave_threads is not between 3 to 4 times the number of CPU(s)")
        adjusted_vars.append(u"wsrep_slave_threads = 4 * # of Core CPU")
    else:
        option.good_print(u"wsrep_slave_threads is between 3 to 4 times the number of CPU(s)")

    gcs_limit: int = wsrep_option(option, info, key=u"gcs.limit")
    if gcs_limit != 5 * wsrep_slave_threads:
        option.bad_print(u"gcs.limit should be equal to 5 * wsrep_slave_threads")
        adjusted_vars.append(u"wsrep_slave_threads = 5 * # wsrep_slave_threads")
    else:
        option.good_print(u"gcs.limit is equal to 5 * wsrep_slave_threads")

    wsrep_flow_control_paused: int = wsrep_option(option, info, key=u"wsrep_flow_control_paused")
    if wsrep_flow_control_paused > 0.02:
        option.bad_print(u"Flow control fraction > 0.02")
    else:
        option.good_print(u"Flow control fraction seems to be OK")

    non_primary_key_table_query_file: str = osp.join(info.query_dir, u"non_primary-key-table-query.sql")
    with open(non_primary_key_table_query_file, mode=u"r", encoding=u"utf-8") as npktqf:
        non_primary_key_table_query: sqla.Text = sqla.text(npktqf.read())

    result = sess.execute(non_primary_key_table_query)
    NonPrimaryKeyTable = clct.namedtuple(u"NonPrimaryKeyTable", result.keys())
    non_primary_key_tables: typ.Sequence[str] = [
        NonPrimaryKeyTable(*non_primary_key_table).TABLE
        for non_primary_key_table in result.fetchall()
    ]

    if len(non_primary_key_tables) > 0:
        option.bad_print(u"Following table(s) don't have primary keys:")
        for non_primary_key_table in non_primary_key_tables:
            option.bad_print(f"\t{non_primary_key_table}")
            # TODO assign to result object
    else:
        option.good_print(u"All tables have a primary key")

    non_innodb_table_query_file: str = osp.join(info.query_dir, u"non_innodb-table-query.sql")
    with open(non_innodb_table_query_file, mode=u"r", encoding=u"utf-8") as nitqf:
        non_innodb_table_query: sqla.Text = sqla.text(nitqf.read())

    result = sess.execute(non_innodb_table_query)
    NonInnoDBTable = clct.namedtuple(u"NonInnoDBTable", result.keys())
    non_innodb_tables: typ.Sequence[str] = [
        NonInnoDBTable(*non_innodb_table).TABLE
        for non_innodb_table in result.fetchall()
        ]

    if len(non_innodb_tables) > 0:
        option.bad_print(u"Following table(s) are not InnoDB table(s):")
        for non_innodb_table in non_innodb_tables:
            option.bad_print(f"\t{non_innodb_table}")
            recommendations.append(u"Ensure that all tables are InnoDB tables for Galera replciation")
            # TODO assign to result object
    else:
        option.good_print(u"All tables are InnoDB tables")

    if info.binlog_format != u"ROW":
        option.bad_print(u"Binlog format should be in ROW mode.")
        adjusted_vars.append(u"binlog_format = ROW")
    else:
        option.bad_print(u"Binlog format is in ROW mode.")

    if info.innodb_flush_log_at_trx_commit:
        option.bad_print(u"InnoDB flush log at each commit should be disabled.")
        adjusted_vars.append(u"innodb_flush_log_at_trx_commit = False")
    else:
        option.good_print(u"InnoDB flush log at each commit is disabled")

    option.info_print(f"Read consistency mode: {info.wsrep_causal_reads}")
    if info.wsrep_cluster_name and info.wsrep_on:
        option.good_print(u"Galera WsREP is enabled.")
        if info.wsrep_cluster_address.strip():
            option.good_print(f"Galera Cluster address is defined: {info.wsrep_cluster_address}")

            nodes: typ.Sequence[str] = info.wsrep_cluster_address.split(u",")
            option.info_print(f"There are {len(nodes)} nodes in wsrep_cluster_size")

            node_amount: int = stat.wsrep_cluster_size
            if node_amount in (3, 5):
                option.good_print(f"There are {node_amount} nodes in wsrep_cluster_size")
            else:
                option.bad_print((
                    f"There are {node_amount} nodes in wsrep_cluster_size. "
                    u"Prefer 3 or 5 node architecture"
                ))
                recommendations.append(u"Prefer 3 or 5 node architecture")

            # wsrep_cluster_address doesn't include garbd nodes
            if len(nodes) > node_amount:
                option.bad_print((
                    u"All cluster nodes are not detected. "
                    u"wsrep_cluster_size less then node count in wsrep_cluster_address"
                ))
            else:
                option.good_print(u"All cluster nodes detected.")
        else:
            option.bad_print(u"Galera Cluster address is undefined")
            adjusted_vars.append(u"Set up wsrep_cluster_name variable for Galera replication")

        if info.wsrep_node_name.strip():
            option.good_print(f"Galera node name is defined: {info.wsrep_node_name}")
        else:
            option.bad_print(u"Galera node name is not defined")
            adjusted_vars.append(u"Set up wsrep_node_name variable for Galera replication")

        if info.wsrep_notify_cmd.strip():
            option.good_print(f"Galera notify command is defined: {info.wsrep_notify_cmd}")
        else:
            option.bad_print(u"Galera notify command is not defined")
            adjusted_vars.append(u"Set up wsrep_notify_cmd variable for Galera replication")

        if "xtrabackup" in info.wsrep_sst_method.strip():
            option.good_print(f"Galera SST method is based on xtrabackup")
        else:
            option.bad_print(u"Galera node name is not xtrabackup based")
            adjusted_vars.append(u"Set up parameter wsrep_sst_method variable to xtrabackup based parameter")

        if info.wsrep_osu_method == "TOI":
            option.good_print(u"TOI is the default mode for upgrade.")
        else:
            option.bad_print(u"Schema upgrades are not replicated automatically.")
            adjusted_vars.append(u"Set wsrep_osu_method = 'TOI'")

        option.info_print(f"Max WsREP message: {util.bytes_to_string(info.wsrep_max_ws_size)}")
    else:
        option.bad_print(u"Galera WsREP is disabled.")

    if stat.wsrep_connected:
        option.good_print(u"Node is connected")
    else:
        option.bad_print(u"Node is not connected")

    if stat.wsrep_ready:
        option.good_print(u"Node is ready")
    else:
        option.bad_print(u"Node is not ready")

    option.info_print(f"Cluster status: {stat.wsrep_cluster_status}")
    if stat.wsrep_cluster_status.title() == u"Primary":
        option.good_print(u"Galera cluster is consistent and ready for operations")
    else:
        option.bad_print(u"Galera cluster is not consistent and ready")

    if stat.wsrep_local_state_uuid == stat.wsrep_cluster_state_uuid:
        option.good_print((
            f"Node and whole cluster at the same level: {stat.wsrep_cluster_state_uuid}"
        ))
    else:
        option.bad_print(u"None and whole cluster not at same level")
        option.info_print(f"Node    state uuid: {stat.wsrep_local_state_uuid}")
        option.info_print(f"Cluster state uuid: {stat.wsrep_cluster_state_uuid}")

    if stat.wsrep_local_state_comment.title() == u"Synced":
        option.good_print(u"Node is synced with whole cluster")
    else:
        option.bad_print(u"Node is not synced")
        option.info_print(f"Node state: {stat.wsrep_local_state_comment}")

    if stat.wsrep_local_cert_failures == 0:
        option.good_print(u"There are no certification failures detected")
    else:
        option.bad_print(f"There are {stat.wsrep_local_cert_failures} certification failure(s) detected")

    # TODO weird debug print

    option.debug_print(",".join(wsrep_options(option, info)))

    return recommendations, adjusted_vars


def mysql_innodb(
    option: tuner.Option,
    info: tuner.Info,
    stat: tuner.Stat,
    calc: tuner.Calc
) -> typ.Sequence[typ.List[str], typ.List[str]]:
    """Recommendations for InnoDB

    :param tuner.Option option:
    :param tuner.Info info:
    :param tuner.Stat stat:
    :param tuenr.Calc calc:

    :return typ.Sequence[typ.List[str], typ.List[str]]: list of recommendations and list of adjusted variables
    """
    recommendations: typ.List[str] = []
    adjusted_vars: typ.List[str] = []

    option.subheader_print(u"InnoDB Metrics")

    # InnoDB
    if not info.have_innodb:
        option.info_print(u"InnoDB is disabled.")
        if (info.ver_major, info.ver_minor) >= (5, 5):
            option.bad_print(u"InnoDB Storage Engine is disabled. InnoDB is the default storage engine")

        return recommendations, adjusted_vars

    option.info_print(u"InnoDB is enabled.")

    if option.buffers:
        option.info_print(u"InnoDB Buffers")

        option.info_print(f" +-- InnoDB Buffer Pool: {util.bytes_to_string(info.innodb_buffer_pool_size)}")

        option.info_print((
            u" +-- InnoDB Buffer Pool Instances:"
            f" {util.bytes_to_string(info.innodb_buffer_pool_instances)}"
        ))

        option.info_print((
            u" +-- InnoDB Buffer Pool Chunk Size:"
            f" {util.bytes_to_string(info.innodb_buffer_pool_chunk_size)}"
        ))

        option.info_print((
            u" +-- InnoDB Additional Mem Pool:"
            f" {util.bytes_to_string(info.innodb_additional_mem_pool_size)}"
        ))

        option.info_print((
            u" +-- InnoDB Log File Size:"
            f" {util.bytes_to_string(info.innodb_log_file_size)}"
            f"({calc.innodb_log_size_pct}% of buffer pool)"
        ))

        option.info_print((
            u" +-- InnoDB Log Files In Group:"
            f" {util.bytes_to_string(info.innodb_log_files_in_group)}"
        ))

        option.info_print((
            u" +-- InnoDB Total Log File Size:"
            f" {util.bytes_to_string(info.innodb_log_files_in_group * info.innodb_log_file_size)}"
        ))

        option.info_print((
            u" +-- InnoDB Log Buffer:"
            f" {util.bytes_to_string(info.innodb_log_buffer_size)}"
        ))

        option.info_print((
            u" +-- InnoDB Log Buffer Free:"
            f" {util.bytes_to_string(stat.innodb_buffer_pool_pages_free)}"
        ))

        option.info_print((
            u" +-- InnoDB Log Buffer Used:"
            f" {util.bytes_to_string(stat.innodb_buffer_pool_pages_total)}"
        ))

    option.info_print((
        u" +-- InnoDB Thread Concurrency:"
        f" {util.bytes_to_string(info.innodb_thread_concurrency)}"
    ))

    if info.innodb_file_per_table:
        option.good_print(u"InnoDB file per table is activated")
    else:
        option.bad_print(u"InnoDB file per table is not activated")
        adjusted_vars.append(u"innodb_file_per_table=ON")

    # TODO figure out engine_stat
    # InnoDB Buffer Pool Size
    if info.innodb_buffer_pool_size > engine_stat.innodb:
        option.good_print((
            u"InnoDB Buffer Pool / Data size: "
            f"{util.bytes_to_string(info.innodb_buffer_pool_size)}/"
            f"{util.bytes_to_string(engine_stat.innodb)}"
        ))
    else:
        option.bad_print((
            u"InnoDB Buffer Pool / Data size: "
            f"{util.bytes_to_string(info.innodb_buffer_pool_size)}/"
            f"{util.bytes_to_string(engine_stat.innodb)}"
        ))
        adjusted_vars.append(
            f"innodb_buffer_pool_size (>= {util.bytes_to_string(engine_stat.innodb)}) if possible."
        )

    if 20 <= calc.innodb_log_size_pct <= 30:
        option.good_print((
            u"InnoDB Log file size / InnoDB Buffer pool size "
            f"({calc.innodb_log_size_pct}%): "
            f"{util.bytes_to_string(info.innodb_log_file_size)} * "
            f"{info.innodb_log_files_in_group} / "
            f"{util.bytes_to_string(info.innodb_buffer_pool_size)} "
            u"should be equal 25%"
        ))
    else:
        option.bad_print((
            u"InnoDB Log file size / InnoDB Buffer pool size "
            f"({calc.innodb_log_size_pct}%): "
            f"{util.bytes_to_string(info.innodb_log_file_size)} * "
            f"{info.innodb_log_files_in_group} / "
            f"{util.bytes_to_string(info.innodb_buffer_pool_size)} "
            u"should be equal 25%"
        ))
        adjusted_vars.append((
            u"innodb_log_file_size * innodb_log_files_in_group should be equal to 25% of buffer pool size "
            f"(={util.bytes_to_string(info.innodb_buffer_pool_size * info.innodb_log_files_in_group / 4)}) "
            u"if possible"
        ))

    # InnoDB Buffer Pool Instances (MySQL 5.6.6+)
    # Bad Value if > 64
    if info.innodb_buffer_pool_instances > 64:
        option.bad_print(f"InnoDB Buffer pool instances: {info.innodb_buffer_pool_instances}")
        adjusted_vars.append(u"innodb_buffer_pool_instances (<= 64)")

    # InnoDB Buffer Pool Size > 1 GB
    if info.innodb_buffer_pool_size > 1 * 1024 ** 3:
        # InnoDB Buffer Pool Size / 1 GB = InnoDB Buffer Pool Instances limited to 64 max.
        # InnoDB Buffer Pool Size > 64 GB
        max_innodb_buffer_pool_instances: int = min(int(info.innodb_buffer_pool_size / (1024 ** 3)), 64)

        if info.innodb_buffer_pool_instances == max_innodb_buffer_pool_instances:
            option.good_print(f"InnoDB Buffer pool instances: {info.innodb_buffer_pool_instances}")
        else:
            option.bad_print(f"InnoDB Buffer pool instances: {info.innodb_buffer_pool_instances}")
            adjusted_vars.append(f"innodb_buffer_pool_instances (= {max_innodb_buffer_pool_instances})")
    else:
        if info.innodb_buffer_pool_instances == 1:
            option.good_print(f"InnoDB Buffer pool instances {info.innodb_buffer_pool_instances}")
        else:
            option.bad_print(u"InnoDB Buffer pool <= 1 GB and innodb_buffer_pool_instances != 1")
            adjusted_vars.append(u"innodb_buffer_pool_instances (== 1)")

    # InnoDB Used Buffer Pool Size vs CHUNK size
    if info.innodb_buffer_pool_chunk_size:
        option.info_print(u"InnoDB Buffer Pool Chunk Size not used or defined in your version")
    else:
        option.info_print((
            u"Number of InnoDB Buffer Pool Chunks: "
            f"{info.innodb_buffer_pool_size} / {info.innodb_buffer_pool_chunk_size} for "
            f"{info.innodb_buffer_pool_instances} Buffer Pool Instance(s)"
        ))

        if info.innodb_buffer_pool_size % (info.innodb_buffer_pool_chunk_size * info.innodb_buffer_pool_instances) == 0:
            option.good_print((
                u"innodb_buffer_pool_size aligned with innodb_buffer_pool_chunk_size & innodb_buffer_pool_instances"
            ))
        else:
            option.bad_print((
                u"innodb_buffer_pool_size not aligned with innodb_buffer_pool_chunk_size & innodb_buffer_pool_instances"
            ))
            adjusted_vars.append((
                u"innodb_buffer_pool_size must always be equal to "
                u"or a multiple of innodb_buffer_pool_chunk_size * innodb_buffer_pool_instances"
            ))

    # InnoDB Read Efficiency
    if calc.pct_read_efficiency > 90:
        option.good_print((
            f"{calc.pct_read_efficiency}% "
            f"({stat.innodb_buffer_pool_read_requests - stat.innodb_buffer_pool_reads} hits / "
            f"{stat.innodb_buffer_pool_read_requests} total)"
        ))
    else:
        option.bad_print((
            f"{calc.pct_read_efficiency}% "
            f"({stat.innodb_buffer_pool_read_requests - stat.innodb_buffer_pool_reads} hits / "
            f"{stat.innodb_buffer_pool_read_requests} total)"
        ))

    # InnoDB Write Efficiency
    if calc.pct_write_efficiency > 90:
        option.good_print((
            f"{calc.pct_read_efficiency}% "
            f"({stat.innodb_log_write_requests - stat.innodb_log_writes} hits / "
            f"{stat.innodb_log_write_requests} total)"
        ))
    else:
        option.bad_print((
            f"{calc.pct_read_efficiency}% "
            f"({stat.innodb_log_write_requests - stat.innodb_log_writes} hits / "
            f"{stat.innodb_log_write_requests} total)"
        ))

    # InnoDB Log Waits
    if calc.pct_read_efficiency > 90:
        option.good_print((
            u"InnoDB Log Waits:"
            f"{util.percentage(stat.innodb_log_waits, stat.innodb_log_writes)}% "
            f"({stat.innodb_log_waits} waits / "
            f"{stat.innodb_log_writes} writes)"
        ))
    else:
        option.bad_print((
            u"InnoDB Log Waits:"
            f"{util.percentage(stat.innodb_log_waits, stat.innodb_log_writes)}% "
            f"({stat.innodb_log_waits} waits / "
            f"{stat.innodb_log_writes} writes)"
        ))
        adjusted_vars.append(
            f"innodb_log_buffer_size (>= {util.bytes_to_string(info.innodb_log_buffer_size)})"
        )

    # TODO set result object

    return recommendations, adjusted_vars


def mysql_databases(
    sess: orm.session.Session,
    option: tuner.Option,
    info: tuner.Info
) -> typ.Sequence[typ.List[str], typ.List[str]]:
    """Recommendations for database metrics

    :param orm.session.Session sess:
    :param tuner.Option option:
    :param tuner.Info info:
    :return typ.Sequence[typ.List[str], typ.List[str]]: list of recommendations and list of adjusted variables
    """
    recommendations: typ.List[str] = []
    adjusted_vars: typ.List[str] = []

    if not option.db_stat:
        return recommendations, adjusted_vars

    option.subheader_print(u"Database Metrics")
    if (info.ver_major, info.ver_minor) >= (5, 5):
        option.info_print(u"Skip Database metrics from information schema missing in this version")
        return recommendations, adjusted_vars

    database_query: str = u"SHOW DATABASES;"
    result = sess.execute(database_query)
    Database = clct.namedtuple(u"Database", result.keys())
    databases: typ.Sequence[str] = [
        Database(*database).Database
        for database in result.fetchall()
    ]

    option.info_print(f"There are {len(databases)} Databases")

    databases_info_query_file: str = osp.join(info.query_dir, u"databases-info-query.sql")
    with open(databases_info_query_file, mode=u"r", encoding=u"utf-8") as diqf:
        databases_info_query: sqla.Text = sqla.text(diqf.read())
    result = sess.execute(databases_info_query)
    DatabasesInfo = clct.namedtuple(u"DatabasesInfo", result.keys())
    databases_info: DatabasesInfo = [
        DatabasesInfo(*databases_info)
        for databases_info in result.fetchall()
    ][0]
    option.info_print(u"All Databases:")
    option.info_print(f" +-- TABLE      : {databases_info.TABLE_COUNT}")
    option.info_print(f" +-- ROWS       : {databases_info.ROW_AMOUNT}")
    option.info_print((
        f" +-- DATA       : {util.bytes_to_string(databases_info.DATA_SIZE)} "
        f"({util.percentage(databases_info.DATA_SIZE, databases_info.TOTAL_SIZE)}%)"
    ))
    option.info_print((
        f" +-- INDEX      : {util.bytes_to_string(databases_info.INDEX_SIZE)} "
        f"({util.percentage(databases_info.INDEX_SIZE, databases_info.TOTAL_SIZE)}%)"
    ))

    table_collation_query_file: str = osp.join(info.query_dir, u"all-table-collations-query.sql")
    with open(table_collation_query_file, mode=u"r", encoding=u"utf-8") as atcqf:
        table_collation_query: sqla.Text = sqla.text(atcqf.read())
    result = sess.execute(table_collation_query)
    TableCollation = clct.namedtuple(u"TableCollation", result.keys())
    table_collations: TableCollation = [
        TableCollation(*table_collation)
        for table_collation in result.fetchall()
    ]
    all_table_collations: str = ", ".join(
        table_collation.TABLE_COLLATION
        for table_collation in table_collations
    )
    option.info_print((
        f" +-- COLLATION  : {databases_info.COLLATION_COUNT} "
        f"({all_table_collations})"
    ))

    table_engine_query_file: str = osp.join(info.query_dir, u"all-table-engines-query.sql")
    with open(table_engine_query_file, mode=u"r", encoding=u"utf-8") as ateqf:
        table_engine_query: sqla.Text = sqla.text(ateqf.read())
    result = sess.execute(table_engine_query)
    TableEngine = clct.namedtuple(u"TableEngine", result.keys())
    table_engines: TableEngine = [
        TableEngine(*table_engine)
        for table_engine in result.fetchall()
    ]
    all_table_engines: str = ", ".join(
        table_engine.TABLE_COLLATION
        for table_engine in table_engines
    )
    option.info_print((
        f" +-- ENGINE     : {databases_info.ENGINE_COUNT} "
        f"({all_table_engines})"

    ))

    # TODO set result object

    if not (option.silent and option.json):
        print(u"\n")

    database_info_query_file: str = osp.join(info.query_dir, u"database-info-query.sql")
    with open(database_info_query_file, mode=u"r", encoding=u"utf-8") as diqf:
        database_info_query: sqla.Text = sqla.text(diqf.read())
    for database in databases:
        result = sess.execute(database_info_query, TABLE_SCHEMA=database)
        DatabaseInfo = clct.namedtuple(u"DatabaseInfo", result.keys())
        database_info: DatabaseInfo = [
            DatabaseInfo(*database_info)
            for database_info in result.fetchall()
        ][0]
        option.info_print(f"Database: {database}")
        option.info_print(f" +-- TABLE      : {database_info.TABLE_COUNT}")
        option.info_print(f" +-- ROWS       : {database_info.ROW_AMOUNT}")
        option.info_print((
            f" +-- DATA       : {util.bytes_to_string(database_info.DATA_SIZE)} "
            f"({util.percentage(database_info.DATA_SIZE, database_info.TOTAL_SIZE)}%)"
        ))
        option.info_print((
            f" +-- INDEX      : {util.bytes_to_string(database_info.INDEX_SIZE)} "
            f"({util.percentage(database_info.INDEX_SIZE, database_info.TOTAL_SIZE)}%)"
        ))

        table_collation_query_file: str = osp.join(info.query_dir, u"table-collations-query.sql")
        with open(table_collation_query_file, mode=u"r", encoding=u"utf-8") as tcqf:
            table_collation_query: sqla.Text = sqla.text(tcqf.read())
        result = sess.execute(table_collation_query, TABLE_SCHEMA=database)
        TableCollation = clct.namedtuple(u"TableCollation", result.keys())
        table_collations: TableCollation = [
            TableCollation(*table_collation)
            for table_collation in result.fetchall()
        ]
        all_table_collations: str = ", ".join(
            table_collation.TABLE_COLLATION
            for table_collation in table_collations
        )
        option.info_print((
            f" +-- COLLATION  : {database_info.COLLATION_COUNT} "
            f"({all_table_collations})"
        ))

        table_engine_query_file: str = osp.join(info.query_dir, u"table-engines-query.sql")
        with open(table_engine_query_file, mode=u"r", encoding=u"utf-8") as teqf:
            table_engine_query: sqla.Text = sqla.text(teqf.read())
        result = sess.execute(table_engine_query, TABLE_SCHEMA=database)
        TableEngine = clct.namedtuple(u"TableEngine", result.keys())
        table_engines: typ.Sequence[TableEngine] = [
            TableEngine(*table_engine)
            for table_engine in result.fetchall()
        ]
        all_table_engines: str = ", ".join(
            table_engine.TABLE_COLLATION
            for table_engine in table_engines
        )
        option.info_print((
            f" +-- ENGINE     : {database_info.ENGINE_COUNT} "
            f"({all_table_engines})"

        ))

        if database_info.DATA_LENGTH < database_info.INDEX_LENGTH:
            option.bad_print(f"Index size is larger than data size for {database}")
        if database_info.ENGINE_COUNT > 1:
            option.bad_print(f"There are {database_info.ENGINE_COUNT} storage engines. Be careful.")

        # TODO set result object

        if database_info.COLLATION_COUNT > 1:
            option.bad_print(f"{database_info.COLLATION_COUNT} different collations for database {database}")
            recommendations.append(
                f"Check all table collations are identical for all tables in {database} database"
            )
        else:
            option.good_print(f"{database_info.COLLATION_COUNT} collation for database {database}")

        if database_info.ENGINE_COUNT > 1:
            option.bad_print(f"{database_info.ENGINE_COUNT} different engines for database {database}")
            recommendations.append(
                f"Check all table engines are identical for all tables in {database} database"
            )
        else:
            option.good_print(f"{database_info.ENGINE_COUNT} engine for database {database}")

        character_set_query_file: str = osp.join(info.query_dir, u"character-set-query.sql")
        with open(character_set_query_file, mode=u"r", encoding=u"utf-8") as csqf:
            character_set_query: sqla.Text = sqla.text(csqf.read())
        result = sess.execute(character_set_query, TABLE_SCHEMA=database)
        CharacterSet = clct.namedtuple(u"CharacterSet", result.keys())
        character_sets: typ.Sequence[CharacterSet] = [
            CharacterSet(*character_set)
            for character_set in result.fetchall()
        ]
        all_character_sets: str = ", ".join(
            character_set.CHARACTER_SET_NAME
            for character_set in character_sets
        )

        option.info_print(f"Character sets for {database} database table column: {all_character_sets}")

        character_set_count: int = len(all_character_sets)
        if character_set_count > 1:
            option.bad_print(
                f"{character_set_count} table columns have several character sets defined for all text like columns",
                option
            )
            recommendations.append(
                f"Limit character sets for column to one character set if possible for {database} database"
            )
        else:
            option.good_print(
                f"{character_set_count} table columns have several character sets defined for all text like columns",
                option
            )

        collation_query_file: str = osp.join(info.query_dir, u"collation-query.sql")
        with open(collation_query_file, mode=u"r", encoding=u"utf-8") as cqf:
            collation_query: sqla.Text = sqla.text(cqf.read())
        result = sess.execute(collation_query, TABLE_SCHEMA=database)
        Collation = clct.namedtuple(u"Collation", result.keys())
        collations: typ.Sequence[Collation] = [
            Collation(*collation)
            for collation in result.fetchall()
            ]
        all_collations: str = ", ".join(
            collation.COLLATION_NAME
            for collation in collations
        )

        option.info_print(f"Collations for {database} database table column: {all_collations}")

        collation_count: int = len(all_collations)
        if collation_count > 1:
            option.bad_print(
                f"{collation_count} table columns have several collations defined for all text like columns",
                option
            )
            recommendations.append(
                f"Limit collations for column to one collation if possible for {database} database"
            )
        else:
            option.good_print(
                f"{collation_count} table columns have several collations defined for all text like columns",
                option
            )

    return recommendations, adjusted_vars


def mysql_indexes(
    sess: orm.session.Session,
    option: tuner.Option,
    info: tuner.Info,
) -> typ.Sequence[typ.List[str], typ.List[str]]:
    """

    :param orm.session.Session sess:
    :param tuner.Option option:
    :param tuner.Info info:

    :return typ.Sequence[typ.List[str], typ.List[str]]: list of recommendations and list of adjusted variables
    """
    recommendations: typ.List[str] = []
    adjusted_vars: typ.List[str] = []

    if not option.idx_stat:
        return recommendations, adjusted_vars

    option.subheader_print(u"Indexes Metrics")
    if (info.ver_major, info.ver_minor) < (5, 5):
        option.info_print(u"Skip Index metrics from information schema missing in this version")
        return recommendations, adjusted_vars

    worst_indexes_query_file: str = osp.join(info.query_dir, u"worst-indexes-query.sql")
    with open(worst_indexes_query_file, mode=u"r", encoding=u"utf-8") as wiqf:
        worst_indexes_query: sqla.Text = sqla.text(wiqf.read())
    result = sess.execute(worst_indexes_query)
    WorstIndex = clct.namedtuple(u"WorstIndex", result.keys())
    worst_indexes: typ.Sequence[WorstIndex] = [
        WorstIndex(*worst_index)
        for worst_index in result.fetchall()
    ]
    option.info_print(u"Worst Selectivity Indexes")
    for worst_index in worst_indexes:
        option.debug_print(f"{worst_index}")
        option.info_print(f"Index: {worst_index.INDEX}")

        option.info_print(f" +-- COLUMN      : {worst_index.SCHEMA_TABLE}")
        option.info_print(f" +-- SEQ_NUM     : {worst_index.SEQ_IN_INDEX} sequence(s)")
        option.info_print(f" +-- MAX_COLS    : {worst_index.MAX_COLUMNS} column(s)")
        option.info_print(f" +-- CARDINALITY : {worst_index.CARDINALITY} distinct values")
        option.info_print(f" +-- ROW_AMOUNT  : {worst_index.ROW_AMOUNT} rows")
        option.info_print(f" +-- INDEX_TYPE  : {worst_index.INDEX_TYPE}")
        option.info_print(f" +-- SELECTIVITY : {worst_index.SELECTIVITY}%")

        # TODO fill result object

        if worst_index.SELECTIVITY < 25:
            option.bad_print(f"{worst_index.INDEX} has a low selectivity")

    if not info.performance_schema:
        return recommendations, adjusted_vars

    unused_indexes_query_file: str = osp.join(info.query_dir, u"unused-indexes-query.sql")
    with open(unused_indexes_query_file, mode=u"r", encoding=u"utf-8") as uiqf:
        unused_indexes_query: sqla.Text = sqla.text(uiqf.read())
    result = sess.execute(unused_indexes_query)
    UnusedIndex = clct.namedtuple(u"UnusedIndex", result.keys())
    unused_indexes: typ.Sequence[UnusedIndex] = [
        UnusedIndex(*unused_index)
        for unused_index in result.fetchall()
    ]
    option.info_print(u"Unused Indexes")
    if len(unused_indexes) > 0:
        recommendations.append(u"Remove unused indexes.")
    for unused_index in unused_indexes:
        option.debug_print(f"{unused_index}")
        option.bad_print(f"Index: {unused_index.INDEX} on {unused_index.SCHEMA_TABLE} is not used")
        # TODO add to result object

    return recommendations, adjusted_vars


def make_recommendations(
    recommendations: typ.Sequence[str],
    adjusted_vars: typ.Sequence[str],
    option: tuner.Option,
    calc: tuner.Calc
) -> None:
    """Displays all recommendations

    :param typ.Sequence[str] recommendations:
    :param typ.Sequence[str] adjusted_vars:
    :param tuner.Option option:
    :param tuner.Calc calc:
    :return:
    """
    option.subheader_print(u"Recommendations")

    if recommendations:
        option.pretty_print(u"General Recommendations:")
        for recommendation in recommendations:
            option.pretty_print(f"\t{recommendation}")

    if adjusted_vars:
        option.pretty_print(u"Variables to Adjust:")
        if calc.pct_max_physical_memory > 90:
            option.pretty_print(u"  *** MySQL's maximum memory usage is dangerously high ***")
            option.pretty_print(u"  *** Add RAM before increasing MySQL buffer variables ***")
        for adjusted_var in adjusted_vars:
            option.pretty_print(f"\t{adjusted_var}")

    if not recommendations and not adjusted_vars:
        option.pretty_print(u"No additional performance recommendations are available.")


def template_model(option: tuner.Option, info: tuner.Info) -> str:
    """Generates template model

    :param tuner.Option option:
    :param tuner.Info info:
    :return str:
    """
    if option.template:
        template_file: str = option.template
    else:
        template_file: str = osp.join(info.script_dir, u"../template/template-model.htm")

    with open(template_file, mode=u"r", encoding=u"utf-8") as tf:
        _template_model: str = tf.read()

    return _template_model


def dump_result(result: typ.Any, option: tuner.Option, info: tuner.Info) -> None:
    if option.debug:
        option.debug_print(f"{result}")

    option.debug_print(f"HTML REPORT: {option.report_file}")

    if option.report_file:
        _template_model: str = template_model(option, info)
        with open(option.report_file, mode=u"w", encoding="utf-8") as rf:
            rf.write(_template_model.replace(u":data", json.dumps(result, sort_keys=True, indent=4)))

    if option.json:
        if option.pretty_json:
            print(json.dumps(result, sort_keys=True, indent=4))
        else:
            print(json.dumps(result))
