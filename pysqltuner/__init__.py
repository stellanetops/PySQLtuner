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
import socket
import sqlalchemy as sqla
import sqlalchemy.exc as sqle
import sqlalchemy.orm as orm
import pysqltuner.tuner as tuner
import typing as typ
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
    option.format_print(header_message, style=u"pretty")


def other_process_memory() -> int:
    """Gathers other processes and returns total memory

    :return int: total memory of other processes
    """
    process_filters: typ.Sequence[typ.Tuple[str, str]] = (
        (r".*PID.*", u""),
        (r".*mysqld.*", u""),
        (r".*\[.*\].*", u""),
        (r"^\s+$", u""),
        (r".*PID.*CMD.*", u""),
        (r".*systemd.*", u""),
        (r"\s*?(\d+)\s*.*", r"\1")
    )

    total_other_memory: int = 0
    for process in psu.process_iter():
        for process_filter, process_replace in process_filters:
            process = re.sub(process_filter, process_replace, process.name())
        filtered_process: str = process.strip()
        if filtered_process:
            total_other_memory += process.memory_info().rss

    return total_other_memory


def os_setup(option: tuner.Option) -> typ.Dict:
    """Gets name and memory of OS

    :param tuner.Option option:
    :return typ.Tuple[str, int, str, int, str, int, str]:
    """
    # du_flags: str = u"-b" if re.match(r"Linux", current_os) else u""
    if option.force_mem is not None and option.force_mem > 0:
        physical_memory: int = option.force_mem * 1024 ** 2
        option.format_print(f"Assuming {option.force_mem} MB of physical memory", style=u"info")

        if option.force_swap is not None and option.force_swap > 0:
            swap_memory: int = option.force_swap * 1024 ** 2
            option.format_print(f"Assuming {option.force_swap} MB of swap space", style=u"info")
        else:
            swap_memory: int = 0
            option.format_print(u"Assuming 0 MB of swap space (Use --force-swap to specify)", style=u"bad")
    else:
        physical_memory: int = psu.virtual_memory().available
        swap_memory: int = psu.swap_memory().total

    option.format_print(f"Physical Memory: {physical_memory}", style=u"debug")
    option.format_print(f"Swap Memory: {swap_memory}", style=u"debug")

    process_memory: int = other_process_memory()

    return {
        u"OS": {
            u"Physical Memory": {
                u"bytes": physical_memory,
                u"pretty": util.bytes_to_string(physical_memory)
            },
            u"Swap Memory": {
                u"bytes": swap_memory,
                u"pretty": util.bytes_to_string(swap_memory),
            },
            u"Other Processes": {
                u"bytes": process_memory,
                u"pretty": util.bytes_to_string(process_memory)
            }
        }
    }


def mysql_setup(sess: orm.session.Session, option: tuner.Option) -> bool:
    """Sets up options for mysql

    :param orm.session.Session sess: session
    :param tuner.Option option: options object
    :return bool: whether setup was successful
    """
    if option.mysqladmin:
        mysqladmin_command: str = option.mysqladmin.strip()
    else:
        mysqladmin_command: str = shutil.which(u"mysqladmin").strip()

    if not os.path.exists(mysqladmin_command) and option.mysqladmin:
        option.format_print(f"Unable to find the mysqladmin command you specified {mysqladmin_command}", style=u"bad")
        raise FileNotFoundError
    elif not os.path.exists(mysqladmin_command):
        option.format_print(u"Couldn't find mysqladmin in your $PATH. Is MySQL installed?", style=u"bad")
        raise FileNotFoundError

    if option.mysqlcmd:
        mysql_command: str = option.mysqlcmd.strip()
    else:
        mysql_command: str = shutil.which(u"mysql").strip()

    if not os.path.exists(mysql_command) and option.mysqlcmd:
        option.format_print(f"Unable to find the mysql command you specified {mysql_command}", style=u"bad")
        raise FileNotFoundError
    elif not os.path.exists(mysql_command):
        option.format_print(u"Couldn't find mysql in your $PATH. Is MySQL installed?", style=u"bad")
        raise FileNotFoundError

    mysql_defaults_command: typ.Sequence[str] = (
        mysql_command,
        u"--print-defaults"
    )
    mysql_cli_defaults: str = util.get(mysql_defaults_command)
    option.format_print(f"MySQL Client: {mysql_cli_defaults}", style=u"debug")

    if re.match(r"auto-vertical-output", mysql_cli_defaults):
        option.format_print(u"Avoid auto-vertical-output in configuration file(s) for MySQL like", style=u"bad")
        raise Exception

    option.format_print(f"MySQL Client {mysql_command}", style=u"debug")

    option.port = 3306 if not option.port else option.port

    if option.socket:
        option.remote_connect: str = f"-S {option.socket} -P {option.port}"

    if option.host:
        option.host = option.host.strip()

        if not option.force_mem and option.host not in (u"127.0.0.1", u"localhost"):
            option.format_print(u"The --force-mem option is required for remote connections", style=u"bad")
            raise ConnectionRefusedError

        option.format_print(f"Performing tests on {option.host}:{option.port}", style=u"info")
        option.remote_connect: str = f"-h {option.host} -P {option.port}"

        if option.host not in (u"127.0.0.1", u"localhost"):
            option.do_remote: bool = True

    if option.user and option.password:
        try:
            sess.execute("SELECT 1;")
            option.format_print(u"Logged in using credentials passed on the command line", style=u"good")
            return True
        except sqla.exc.SQLAlchemyError:
            option.format_print(u"Attempted to use login credentials, but they were invalid", style=u"bad")
            raise ConnectionRefusedError

    svcprop_exe: str = shutil.which(u"svcprop")
    if svcprop_exe.startswith(u"/"):
        try:
            sess.execute("SELECT 1;")
            option.format_print(u"Logged in using credentials passed from mysql-quickbackup", style=u"good")
            return True
        except sqla.exc.SQLAlchemyError:
            option.format_print(
                u"Attempted to use login credentials from mysql-quickbackup, they were invalid",
                style=u"bad"
            )
            raise ConnectionRefusedError

    elif util.is_readable(u"/etc/psa/.psa.shadow") and not option.do_remote:
        # It's a Plesk box, use the available credentials
        try:
            sess.execute("SELECT 1;")
            return True
        except sqla.exc.SQLAlchemyError:
            option.format_print(
                u"Attempted to use login credentials from Plesk and Plesk 10+, but they failed",
                style=u"bad"
            )
            raise ConnectionRefusedError

    elif util.is_readable(u"/usr/local/directadmin/conf/mysql.conf") and not option.do_remote:
        # It's a DirectAdmin box, use the available credentials
        try:
            sess.execute("SELECT 1;")
            return True
        except sqla.exc.SQLAlchemyError:
            option.format_print(u"Attempted to use login credentials from DirectAdmin, but they failed", style=u"bad")
            raise ConnectionRefusedError

    elif util.is_readable(u"/etc/mysql/debian.cnf") and not option.do_remote:
        # We have a debian maintenance account, use the available credentials
        try:
            sess.execute("SELECT 1;")
            return True
        except sqla.exc.SQLAlchemyError:
            option.format_print(u"Logged in using credentials from debian maintenance account.", style=u"good")
            raise ConnectionRefusedError

    elif option.defaults_file and util.is_readable(option.defaults_file):
        # Defaults File
        option.format_print(f"defaults file detected: {option.defaults_file}", style=u"debug")
        try:
            sess.execute("SELECT 1;")
            option.format_print(u"Logged in using credentials from defaults file account.", style=u"good")
            return True
        except Exception:
            raise ConnectionRefusedError
    else:
        # It's not Plesk or debian, we should try a login

        try:
            sess.execute("SELECT 1;")
            # Login went just fine
            # mysql_login: str = f" {option.remote_connect} u"

            # Did this go well because of a .my.cnf file or is there no password set?
            user_path: str = os.environ["HOME"].strip()
            if not os.path.exists(f"{user_path}/.my.cnf") and not os.path.exists(f"{user_path}/.mylogin.cnf"):
                option.format_print(u"Successfully authenticated with no password - SECURITY RISK!", style=u"bad")

            return True

        except sqla.exc.SQLAlchemyError:
            if option.no_ask:
                option.format_print(u"Attempted to use login credentials, but they were invalid", style=u"bad")
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

            try:
                sess.execute("SELECT 1;")
                if not password:
                    # Did this go well because of a .my.cnf file or is there no password set?
                    user_path: str = os.environ["HOME"].strip()
                    if not os.path.exists(f"{user_path}/.my.cnf"):
                        option.format_print(
                            u"Successfully authenticated with no password - SECURITY RISK!",
                            style=u"bad"
                        )

                return True
            except sqla.exc.SQLAlchemyError:
                option.format_print(u"Attempted to use login credentials but they were invalid", style=u"bad")
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


def mysql_status_vars(option: tuner.Option, info: tuner.Info, sess: orm.session.Session) -> typ.Dict:
    """Gathers all status variables

    :param tuner.Option option: options object
    :param tuner.Info info: info object
    :param orm.session.Session sess: session
    :return:
    """
    # We need to initiate at least one query so that our data is usable
    version_query: sqla.Text = info.query_from_file(u"version_query.sql")
    try:
        result = sess.execute(version_query)
    except Exception:
        option.format_print(u"Not enough privileges for running PySQLTuner", style=u"bad")
        raise

    Version = clct.namedtuple(u"Version", result.keys())
    version: str = [
        Version(*version).VERSION.split("-")[0]
        for version in result.fetchall()
    ][0]

    option.format_print(f"VERSION: {version}", style=u"debug")

    variables_query: sqla.Text = info.query_from_file(u"variables-query.sql")
    result = sess.execute(variables_query)
    Variable = clct.namedtuple(u"Variable", result.keys())
    variables: typ.Sequence[typ.Tuple[str, str]] = [
        (var.NAME, var.VALUE)
        for var in [
            Variable(*variable)
            for variable in result.fetchall()
        ]
    ]

    statuses_query: sqla.Text = info.query_from_file(u"statuses-query.sql")
    result = sess.execute(statuses_query)
    Status = clct.namedtuple(u"Status", result.keys())
    statuses: typ.Sequence[typ.Tuple[str, str]] = [
        (stat.NAME, stat.VALUE)
        for stat in [
            Status(*status)
            for status in result.fetchall()
        ]
    ]

    if info.wsrep_provider_options:
        info.have_galera = True
        option.format_print(f"Galera options: {info.wsrep_provider_options}", style=u"debug")

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
    engine_support_query = info.query_from_file(u"engine_support-query-5_5.sql")
    result = sess.execute(engine_support_query)
    EngineSupport = clct.namedtuple(u"EngineSupport", result.keys())
    engine_supports: typ.Sequence[typ.Dict[str, str]] = [
        {engs.ENGINE: engs.SUPPORT}
        for engs in [
            EngineSupport(*engine_support)
            for engine_support in result.fetchall()
        ]
    ]

    # TODO replication information

    return {
        u"MySQL Client": {
            u"Version": version
        },
        u"Variables": variables,
        u"Statuses": statuses,
        u"Storage Engines": engine_supports,
        u"Replication": {
            u"Status": None,
            u"Slaves": None
        }
    }


def opened_ports() -> typ.Sequence[typ.Sequence[str], typ.Dict]:
    """Finds all opened ports

    :return typ.Sequence[typ.Sequence[str], typ.Dict]: array of all opened ports, and results
    """
    all_opened_ports: typ.Sequence[typ.Any] = psu.net_connections()

    open_ports: typ.Sequence[str] = sorted(
        port.laddr[1]
        for port in all_opened_ports
    )

    return (
        open_ports,
        {
            u"Network": {
                u"TCP Opened": open_ports
            }
        }
    )


def is_open_port(port: str) -> bool:
    """Finds if port is open

    :param str port: port name
    :return bool: whether the port specified is open
    """
    port_pattern: str = f"^{port}$"
    return any(
        re.search(port_pattern, open_port)
        for open_port in opened_ports()[0]
    )


def fs_info(option: tuner.Option) -> typ.Sequence[typ.List[str], typ.List[str]]:
    """Recommendations for filesystem

    :param tuner.Option option:
    :return typ.Sequence[typ.List[str], typ.List[str], typ.Dict]:
        list of recommendations and list of adjusted variables and results
    """
    recommendations: typ.List[str] = []
    adjusted_vars: typ.List[str] = []

    mount_space: typ.List[typ.Dict[str, float]] = []
    for disk in psu.disk_partitions():
        if disk.opts == u"rw,fixed":
            mount_point: str = disk.mountpoint
            space_perc: float = psu.disk_usage(disk.mountpoint).percent

            if space_perc > 85:
                option.format_print(f"Mount point {mount_point} is using {space_perc} % total space", style=u"bad")
                recommendations.append(
                    f"Add some space to {mount_point} mount point."
                )
            else:
                option.format_print(f"Mount point {mount_point} is using {space_perc} % total space", style=u"info")

            mount_space.append({mount_point: space_perc})

    mount_inode: typ.List[typ.Dict[str, float]] = []
    for disk in psu.disk_partitions():
        if disk.opts == u"rw,fixed":
            mount_point: str = disk.mountpoint
            free_space: int = os.statvfs(mount_point).f_bfree
            total_space: int = os.statvfs(mount_point).f_blocks
            inode_perc: float = round(free_space / total_space, 1)

            if inode_perc > 85:
                option.format_print(
                    f"Mount point {mount_point} is using {inode_perc} % of max allowed inodes",
                    style=u"bad"
                )
                recommendations.append(
                    f"Add some space to {mount_point} mount point."
                )
            else:
                option.format_print(
                    f"Mount point {mount_point} is using {inode_perc} % of max allowed inodes",
                    style=u"info"
                )

            mount_inode.append({mount_point: inode_perc})

    return (
        recommendations,
        adjusted_vars,
        {
            u"Filesystem": {
                u"Space Percent": mount_space,
                u"Inode Percent": mount_inode
            }
        }
    )


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
    option.format_print(f"CMD: {cmd}", style=u"debug")

    result: str = tuple(
        info.strip()
        for info in util.get(command)
    )
    for info in result:
        option.format_print(f"{delimiter}{info}", style=u"info")


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

    option.format_print(u"Information about kernel tuning:", style=u"info")

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
        option.format_print(u"Swappiness is > 10, please consider having a value lower than 10", style=u"bad")
        recommendations.append(u"Setup swappiness  to be <= 10")
        adjusted_vars.append(u"vm.swappiness <= 10 (echo 0 > /proc/sys/vm/swappiness)")
    else:
        option.format_print(u"Swappiness is < 10.", style=u"info")

    # only if /proc/sys/sunrpc exists
    slot_table_command: typ.Sequence[str] = (
        u"sysctl",
        u"-n",
        u"sunrpc.tcp_slot_table_entries",
        u"2>/dev/null"
    )
    tcp_slot_entries: str = util.get(slot_table_command)

    if os.path.isfile(u"/proc/sys/sunrpc") and (not tcp_slot_entries or int(tcp_slot_entries) < 100):
        option.format_print(
            u"Initial TCP slot entries is < 1M, please consider having a value greater than 100",
            style=u"bad"
        )
        recommendations.append(u"Setup Initial TCP slot entries > 100")
        adjusted_vars.append(
            u"sunrpc.tcp_slot_table_entries > 100 (echo 128 > /proc/sys/sunrpc/tcp_slot_table_entries)"
        )
    else:
        option.format_print(u"TCP slot entries is > 100.", style=u"info")

    aio_max_command: typ.Sequence[str] = (
        u"sysctl",
        u"-n",
        u"fs.aio-max-nr"
    )
    aio_max: int = int(util.get(aio_max_command))

    if aio_max < 1000000:
        option.format_print((
                u"Max running total of the number of events is < 1M,"
                u"please consider having a value greater than 1M"
        ), style=u"bad")
        recommendations.append(u"Setup max running number events greater than 1M")
        adjusted_vars.append(u"fs.aio-max-nr > 1M (echo 1048576 > /proc/sys/fs/aio-max-nr)")
    else:
        option.format_print(u"Max Number of AIO events is > 1M.", style=u"info")

    return recommendations, adjusted_vars


def system_info(option: tuner.Option) -> typ.Dict:
    """Grabs system information
    
    :param tuner.Option option: 
    :return: 
    """
    os_release: str = platform.release()
    option.format_print(os_release, style=u"info")

    virtual_machine: bool = is_virtual_machine()
    if virtual_machine:
        option.format_print(u"Machine Type\t\t\t\t\t: Virtual Machine", style=u"info")
    else:
        option.format_print(u"Machine Type\t\t\t\t\t: Physical Machine", style=u"info")

    is_connected: bool = req.get(u"http://ipecho.net/plain").status_code == 200
    if is_connected:
        option.format_print(u"Internet\t\t\t\t\t: Connected", style=u"info")
    else:
        option.format_print(u"Internet\t\t\t\t\t: Disconnected", style=u"bad")

    cpu_count: int = psu.cpu_count()
    option.format_print(f"Number of Core CPU : {cpu_count}", style=u"info")

    os_type: str = platform.system()
    option.format_print(f"Operating System Type : {os_type}", style=u"info")

    kernel_release: str = platform.release()
    option.format_print(f"Kernel Release : {kernel_release}", style=u"info")

    hostname: str = socket.gethostname()
    option.format_print(f"Hostname\t\t\t\t: {hostname}", style=u"info")

    internal_ip: str = socket.gethostbyname(hostname)
    option.format_print(f"Internal IP\t\t\t\t: {internal_ip}", style=u"info")

    option.format_print(u"Network Cards\t\t\t: ", style=u"info")
    for network_card in psu.net_if_stats().keys():
        option.format_print(network_card)

    try:
        external_ip: str = req.get(u"http://ipecho.net/plain").text
        option.format_print(f"External IP\t\t\t\t: {external_ip}", style=u"info")
    except req.exceptions.MissingSchema as err:
        option.format_print(f"External IP\t\t\t\t: Can't check because of Internet connectivity", style=u"bad")
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
    option.format_print(f"Name Servers\t\t\t\t: {name_servers}", style=u"info")

    option.format_print(u"Logged in Users\t\t\t\t:", style=u"info")
    logged_users: typ.Sequence[str] = [
        user.name
        for user in psu.users()
    ]
    for logged_user in logged_users:
        option.format_print(logged_user, style=u"info")

    ram: str = util.bytes_to_string(psu.virtual_memory().free)
    option.format_print(f"Ram Usages in MB\t\t: {ram}", style=u"info")

    load_average: str = os.getloadavg()

    return {
        u"OS": {
            u"Release": os_release,
            u"Virtual Machine": virtual_machine,
            u"# of Cores": cpu_count,
            u"Type": os_type,
            u"Kernel": kernel_release,
            u"Logged Users": logged_users,
            u"Free Memory Ram": ram,
            u"Load Average": load_average
        },
        u"Network": {
            u"Connected": is_connected,
            u"Internal IP": internal_ip,
            u"External IP": external_ip
        }
    }


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
        option.format_print(u"Skipped due to non Linux Server", style=u"info")
        return recommendations, adjusted_vars

    option.format_print(u"Look for related Linux system recommendations", style=u"pretty")

    system_info(option)
    other_proc_mem: int = other_process_memory()

    option.format_print(f"User process except mysqld used {util.bytes_to_string(other_proc_mem)} RAM", style=u"info")

    if 0.15 * physical_memory < other_proc_mem:
        option.format_print((
            u"Other user process except mysqld used more than 15% of total physical memory "
            f"{util.percentage(other_proc_mem, physical_memory)}% "
            f"({util.bytes_to_string(other_proc_mem)} / {util.bytes_to_string(physical_memory)})"
        ), style=u"bad")
        recommendations.append(u"Consider stopping or dedicate server for additional process other than mysqld")
        adjusted_vars.append(
            u"DON'T APPLY SETTINGS BECAUSE THERE ARE TOO MANY PROCESSES RUNNING ON THIS SERVER. OOM KILL CAN OCCUR!"
        )
    else:
        option.format_print((
            u"Other user process except mysqld used more than 15% of total physical memory "
            f"{util.percentage(other_proc_mem, physical_memory)}% "
            f"({util.bytes_to_string(other_proc_mem)} / {util.bytes_to_string(physical_memory)})"
        ), style=u"info")

    if option.max_port_allowed > 0:
        open_ports: typ.Sequence[str] = opened_ports()
        option.format_print(f"There are {len(open_ports)} listening port(s) on this server", style=u"info")

        if len(open_ports) > option.max_port_allowed:
            option.format_print((
                f"There are too many listening ports: "
                f"{len(open_ports)} opened > {option.max_port_allowed} allowed"
            ), style=u"bad")
            recommendations.append(
                u"Consider dedicating a server for your database installation with less services running on!"
            )
        else:
            option.format_print(
                f"There are less than {option.max_port_allowed} opened ports on this server",
                style=u"info"
            )

    for banned_port in banned_ports:
        if is_open_port(banned_port):
            option.format_print(f"Banned port: {banned_port} is opened.", style=u"bad")
            recommendations.append(f"Port {banned_port} is opened. Consider stopping program handling this port.")
        else:
            option.format_print(f"{banned_port} is not opened.", style=u"good")

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

    option.format_print(u"Security Recommendations", style=u"subheader")
    if option.skip_password:
        option.format_print(u"Skipped due to --skip-password option", style=u"info")
        return recommendations, adjusted_vars

    password_column: str = u"PASSWORD"
    if (info.ver_major, info.ver_minor) >= (5, 7):
        password_column = u"AUTHENTICATION_STRING"

    # Looking for Anonymous users
    mysql_user_query: sqla.Text = info.query_from_file("user-query.sql")
    result = sess.execute(mysql_user_query)
    User = clct.namedtuple(u"User", result.keys())
    users: typ.Sequence[str] = [
        User(*user).GRANTEE
        for user in result.fetchall()
    ]

    option.format_print(f"{users}", style=u"debug")

    if users:
        for user in sorted(users):
            option.format_print(f"User '{user}' is an anonymous account.", style=u"bad")
        recommendations.append(
            f"Remove Anonymous User accounts - there are {len(users)} anonymous accounts."
        )
    else:
        option.format_print(u"There are no anonymous accounts for any database users", style=u"good")

    if (info.ver_major, info.ver_minor, info.ver_micro) <= (5, 1):
        option.format_print(u"No more password checks for MySQL <= 5.1", style=u"bad")
        option.format_print(u"MySQL version <= 5.1 are deprecated and are at end of support", style=u"bad")
        return recommendations, adjusted_vars

    # Looking for Empty Password
    if (info.ver_major, info.ver_minor, info.ver_micro) >= (5, 5):
        mysql_password_query: sqla.Text = info.query_from_file(u"password-query-5_5.sql")
    else:
        mysql_password_query: sqla.Text = info.query_from_file(u"password-query-5_4.sql")

    result = sess.execute(mysql_password_query, password_column=password_column)
    Password = clct.namedtuple(u"Password", result.keys())
    password_users: typ.Sequence[str] = [
        Password(*password).GRANTEE
        for password in result.fetchall()
    ]

    if password_users:
        for user in password_users:
            option.format_print(f"User '{user}' has no password set.", style=u"bad")
        recommendations.append((
            u"Set up a Password for user with the following SQL statement: "
            u"( SET PASSWORD FOR 'user'@'SpecificDNSorIp' = PASSWORD('secure_password'); )"
        ))
    else:
        option.format_print(u"All database users have passwords assigned", style=u"good")

    if (info.ver_major, info.ver_minor, info.ver_micro) >= (5, 7):
        mysql_plugin_query: sqla.Text = info.query_from_file(u"plugin-query.sql")

        result = sess.execute(mysql_plugin_query)
        Plugin = clct.namedtuple(u"Plugin", result.keys())
        plugin_amount: typ.Sequence[int] = int(*[
            Plugin(*plugin).COUNT
            for plugin in result.fetchall()
        ])

        if plugin_amount >= 1:
            option.format_print(
                u"Bug #80860 MySQL 5.7: Avoid testing password when validate_password is activated",
                style=u"info"
            )
            return recommendations, adjusted_vars

    # Looking for User with user/ uppercase /capitalise user as password
    mysql_capitalize_query: sqla.Text = info.query_from_file(u"capitalize-query.sql")
    result = sess.execute(mysql_capitalize_query, password_column=password_column)
    Capitalize = clct.namedtuple(u"Capitalize", result.keys())
    capitalize_users: typ.Sequence[Capitalize] = [
        Capitalize(*user).GRANTEE
        for user in result.fetchall()
    ]

    if capitalize_users:
        for user in capitalize_users:
            option.format_print(f"User '{user}' has user name as password", style=u"bad")
        recommendations.append((
            u"Set up a Password for user with the following SQL statement: "
            u"( SET PASSWORD FOR 'user'@'SpecificDNSorIP' = PASSWORD('secure_password'); )"
        ))
    mysql_host_query: sqla.Text = info.query_from_file(u"host-query.sql")
    result = sess.execute(mysql_host_query)
    Host = clct.namedtuple(u"Host", result.keys())
    host_users: typ.Sequence[str] = [
        Host(*user).GRANTEE
        for user in result.fetchall()
    ]

    if host_users:
        for user in host_users:
            option.format_print(f"User '{user}' does not have specific host restrictions.", style=u"bad")
        recommendations.append(u"Restrict Host for 'user'@'%' to 'user'@SpecificDNSorIP'")

    if os.path.isfile(option.basic_passwords_file):
        option.format_print(u"There is no basic password file list!", style=u"bad")
        return recommendations, adjusted_vars

    with open(option.basic_passwords_file, mode=u"r", encoding=u"utf-8") as bpf:
        passwords: typ.Sequence[str] = bpf.readlines()

    option.format_print(f"There are {len(passwords)} basic passwords in the list", style=u"info")
    bad_amount: int = 0

    if passwords:
        interpass_amount = 0
        for password in passwords:
            interpass_amount += 1

            # Looking for User with user/ uppercase /capitalise user as password
            mysql_capital_password_query: sqla.Text = info.query_from_file(u"capital-password-query.sql")
            result = sess.execute(mysql_capital_password_query, password=password, password_column=password_column)
            CapitalPassword = clct.namedtuple(u"CapitalPassword", result.keys())
            capital_password_users: typ.Sequence[str] = [
                CapitalPassword(*user).GRANTEE
                for user in result.fetchall()
            ]

            option.format_print(f"There are {len(capital_password_users)} items.", style=u"debug")
            if capital_password_users:
                for user in capital_password_users:
                    option.format_print((
                        f"User '{user}' is using weak password: "
                        f"{password} in a lower, upper, or capitalized derivative version."
                    ), style=u"bad")
                    bad_amount += 1
            if interpass_amount % 1000 == 0:
                option.format_print(f"{interpass_amount} / {len(passwords)}", style=u"debug")
    if bad_amount > 0:
        recommendations.append(
            f"{bad_amount} user(s) used a basic or weak password."
        )

    return recommendations, adjusted_vars


def replication_status(option: tuner.Option) -> None:
    option.format_print(u"Replication Metrics", style=u"subheader")
    # TODO get info from variable gathering function
    # option.format_print(f"Galera Synchronous replication {option.}", style=u"info")


def validate_mysql_version(option: tuner.Option, info: tuner.Info) -> None:
    """Check MySQL Version

    :param tuner.Option option: option object
    :param tuner.Info info: info object

    :return:
    """
    full_version: str = f"{info.ver_major}.{info.ver_minor}.{info.ver_micro}"

    if (info.ver_major, info.ver_major, info.ver_micro) < (5, 1):
        option.format_print(f"Your MySQL version {full_version} is EOL software! Upgrade soon!", style=u"bad")
    elif (6 <= info.ver_major <= 9) or info.ver_major >= 12:
        option.format_print(f"Currently running unsupported MySQL version {full_version}", style=u"bad")
    else:
        option.format_print(f"Currently running supported MySQL version {full_version}", style=u"good")


def check_architecture(option: tuner.Option) -> typ.Dict:
    """Checks architecture of system

    :param tuner.Option option: options object
    :return typ.Dict: results
    """
    # Checks for 32-bit boxes with more than 2GB of RAM
    if option.do_remote:
        return {}

    arch_bit: str = platform.architecture()[0]
    physical_memory: int = psu.virtual_memory().available

    if "64" in arch_bit:
        option.format_print("Operating on 64-bit architecture", style=u"good")
    else:
        if physical_memory > 2 ** 31:
            option.format_print(u"Switch to 64-bit OS - MySQL cannot currently use all of your RAM", style=u"bad")
        else:
            option.format_print(u"Operating on a 32-bit architecture with less than 2GB RAM", style=u"good")

    return {
        u"OS": {
            u"Architecture": arch_bit
        }
    }


def check_storage_engines(
    option: tuner.Option,
    info: tuner.Info,
    sess: orm.session.Session
) -> typ.Sequence[typ.List[str], typ.List[str], typ.Dict]:
    """Storage Engine information

    :param tuner.Option option:
    :param tuner.Info info:
    :param orm.session.Session sess:

    :return typ.Sequence[typ.List[str], typ.List[str], typ.Dict]:
        list of recommendations and list of adjusted variables, and results
    """
    recommendations: typ.List[str] = []
    adjusted_vars: typ.List[str] = []
    results: typ.DefaultDict[typ.DefaultDict] = clct.defaultdict(clct.defaultdict(clct.defaultdict(dict)))

    option.format_print(u"Storage Engine Statistics", style=u"subheader")
    if option.skip_size:
        option.format_print(u"Skipped due to --skip-size option", style=u"info")
        return recommendations, adjusted_vars, results

    engines: typ.List[str] = []
    if (info.ver_major, info.ver_minor, info.ver_micro) >= (5, 1, 5):
        engine_version: str = u"5_1"
        if (info.ver_major, info.ver_minor) == (5, 5):
            engine_version = u"5_5"

        engine_support_query: sqla.Text = info.query_from_file(f"engine-support-query-{engine_version}.sql")
        result = sess.execute(engine_support_query)
        EngineSupport = clct.namedtuple(u"EngineSupport", result.keys())
        engine_supports: typ.Sequence[typ.Tuple[str, str]] = [
            (engine_support.ENGINE, engine_support.SUPPORT)
            for engine_support in [
                EngineSupport(*engine_support)
                for engine_support in result.fetchall()
            ]
        ]
        for engine, support in engine_supports:
            if engine.strip() and support.strip():
                results[u"Engine"][engine][u"Enabled"] = support
                if support in (u"YES", u"ENABLED"):
                    engine_part: str = option.color_wrap(f"+{engine} ", color=u"green")
                else:
                    engine_part: str = option.color_wrap(f"+{engine} ", color=u"red")
                engines.append(engine_part)
    else:
        engines.append(
            option.color_wrap(u"+Archive", color=u"green")
            if info.have_archive
            else option.color_wrap(u"-Archive", color=u"red")
        )
        engines.append(
            option.color_wrap(u"+BDB", color=u"green")
            if info.have_bdb
            else option.color_wrap(u"-BDB", color=u"red")
        )
        engines.append(
            option.color_wrap(u"+Federated", color=u"green")
            if info.have_federated_engine
            else option.color_wrap(u"-Federated", color=u"red")
        )
        engines.append(
            option.color_wrap(u"+InnoDB", color=u"green")
            if info.have_innodb
            else option.color_wrap(u"-InnoDB", color=u"red")
        )
        engines.append(
            option.color_wrap(u"+MyISAM", color=u"green")
            if info.have_myisam
            else option.color_wrap(u"-MyISAM", color=u"red")
        )
        engines.append(
            option.color_wrap(u"+NDBCluster", color=u"green")
            if info.have_ndb_cluster
            else option.color_wrap(u"-NDBCLuster", color=u"red")
        )

    database_query: sqla.Text = info.query_from_file(u"all-databases.sql")
    result = sess.execute(database_query)
    Database = clct.namedtuple(u"Database", result.keys())
    databases: typ.Sequence[str] = [
        Database(*database).Database
        for database in result.fetchall()
    ]
    results[u"Databases"][u"List"]: typ.Sequence[str] = databases

    option.format_print(f"Status {engines}", style=u"info")

    if (info.ver_major, info.ver_minor, info.ver_micro) >= (5, 1, 5):
        # MySQL 5 servers can have table sizes calculated quickly from information schema
        engine_query: sqla.Text = info.query_from_file(u"engine-query.sql")
        result = sess.execute(engine_query)
        Engine = clct.namedtuple(u"Engine", result.keys())
        engine_sizes: typ.Sequence[typ.Tuple[str, int, int, int, int]] = [
            (engine.ENGINE, engine.SIZE, engine.COUNT, engine.DATA_SIZE, engine.INDEX_SIZE)
            for engine in [
                Engine(*engine)
                for engine in result.fetchall()
            ]
        ]

        for engine, size, count, data_size, index_size in engine_sizes:
            option.format_print(f"Engine Found: {engine}", style=u"debug")
            if not engine:
                continue
            engine_stats[engine] = count
            results[u"Engine"][engine] = {
                u"# of Tables": count,
                u"Total Size": size,
                u"Data Size": data_size,
                u"Index Size": index_size
            }
        # TODO STUFF
        if info.innodb_file_per_table:
            innodb_clause: str = u"AND `tbl`.`ENGINE` <> 'InnoDB'"
        else:
            innodb_clause: str = u""

        fragmented_tables_query: sqla.Text = info.query_from_file(u"fragmented-tables-query.sql")
        result = sess.execute(fragmented_tables_query, innodb_clause=innodb_clause)
        FragmentedTable = clct.namedtuple(u"FragmentedTable", result.keys())
        frag_table_sizes: typ.Sequence[typ.Tuple[str, int]] = [
            (frag_table.TABLE, frag_table.DATA_FREE)
            for frag_table in [
                FragmentedTable(*fragmented_table)
                for fragmented_table in result.fetchall()
            ]
        ]
        results[u"Tables"][u"Fragmented Tables"]: typ.Sequence[typ.Tuple[str, int]] = frag_table_sizes
    else:
        raise NotImplementedError

        # TODO set variables and add recommendations
        # TODO defragment tables
        # TODO etc

    return recommendations, adjusted_vars, results


def calculations(
    sess: orm.session.Session,
    option: tuner.Option,
    info: tuner.Info,
    stat: tuner.Stat,
    calc: tuner.Calc
) -> None:
    if stat.questions < 1:
        option.format_print(u"Your server has not answered any queries - cannot continue...", style=u"bad")
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

    option.format_print(f"Max Used Memory: {util.bytes_to_string(calc.max_used_memory)}", style=u"debug")
    option.format_print(f"Max Used Percentage RAM: {util.bytes_to_string(calc.pct_max_used_memory)}%", style=u"debug")
    option.format_print(f"Max Peak Memory: {util.bytes_to_string(calc.max_peak_memory)}", style=u"debug")
    option.format_print(
        f"Max Peak Percentage RAM: {util.bytes_to_string(calc.pct_max_physical_memory)}%",
        style=u"debug"
    )

    # Slow Queries
    calc.pct_slow_queries = int(stat.slow_queries / stat.questions * 100)

    # Connections
    calc.pct_connections_used = int(stat.max_used_connections / info.max_connections)
    calc.pct_connections_used = min(calc.pct_connections_used, 100)

    # Aborted Connections
    calc.pct_connections_aborted = util.percentage(stat.aborted_connections, stat.connections)
    option.format_print(f"Aborted Connections: {stat.aborted_connections}", style=u"debug")
    option.format_print(f"Connections: {stat.connections}", style=u"debug")
    option.format_print(f"Percent of Connections Aborted {calc.pct_connections_aborted}", style=u"debug")

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
        myisam_index_query: sqla.Text = info.query_from_file(u"myisam-index-query.sql")
        result = sess.execute(myisam_index_query)
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

        ariadb_index_query: sqla.Text = info.query_from_file(u"aria-index-query.sql")
        result = sess.execute(ariadb_index_query)
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
    option.format_print(f"pct_read_efficiency: {calc.pct_read_efficiency}", style=u"debug")
    option.format_print(f"innodb_buffer_pool_reads: {stat.innodb_buffer_pool_reads}", style=u"debug")
    option.format_print(f"innodb_buffer_pool_read_requests: {stat.innodb_buffer_pool_read_requests}", style=u"debug")

    # InnoDB log write cache efficiency
    calc.pct_write_efficiency = util.percentage(
        stat.innodb_log_write_requests - stat.innodb_log_writes
    )
    option.format_print(f"pct_write_efficiency: {calc.pct_write_efficiency}", style=u"debug")
    option.format_print(f"innodb_log_writes: {stat.innodb_log_writes}", style=u"debug")
    option.format_print(f"innodb_log_write_requests: {stat.innodb_log_write_requests}", style=u"debug")

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

    option.format_print(u"Performance Metrics", style=u"subheader")
    # Show uptime, queries per second, connections, traffic stats
    if stat.uptime > 0:
        qps: str = f"{round(stat.questions / stat.uptime, 3)}"

    if stat.uptime < 86400:
        recommendations.append(u"MySQL started within last 24 hours - recommendations may be inaccurate")

    option.format_print(u" ".join((
        f"Up for: {util.pretty_uptime(stat.uptime)}",
        f"({stat.questions} q [{qps} qps], {stat.connections} conn",
        f"TX: {util.bytes_to_string(stat.bytes_sent)}, RX: {util.bytes_to_string(stat.bytes_received)})"
    )), style=u"info")

    option.format_print(f"Reads / Writes {calc.pct_reads}% / {calc.pct_writes}%", style=u"info")

    # Binlog Cache
    if not info.log_bin:
        option.format_print(u"Binary logging is not enabled", style=u"info")
    else:
        option.format_print(f"Binary logging is enabled (GTID MODE: {info.gtid_mode}", style=u"info")

    # Memory Usage
    option.format_print(f"Physical Memory       : {util.bytes_to_string(stat.physical_memory)}", style=u"info")
    option.format_print(f"Max MySQL Memory      : {util.bytes_to_string(calc.max_peak_memory)}", style=u"info")
    option.format_print(f"Other Process Memory  : {util.bytes_to_string(other_process_memory())}", style=u"info")

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

    option.format_print(u"MyISAM Metrics", style=u"subheader")

    # Key Buffer usage
    key_buffer_used_msg: str = (
        f"Key Buffer used: {calc.pct_key_buffer_used}% "
        f"({util.bytes_to_string(int(info.key_buffer_size * calc.pct_key_buffer_used / 100))} "
        f"used / {util.bytes_to_string(info.key_buffer_size)} cache)"
    )

    if calc.pct_key_buffer_used == 90:
        option.format_print(key_buffer_used_msg, style=u"debug")
    elif calc.pct_key_buffer_used < 90:
        option.format_print(key_buffer_used_msg, style=u"bad")
    else:
        option.format_print(key_buffer_used_msg, style=u"good")

    # Key Buffer
    if calc.total_myisam_indexes == 0 and option.do_remote:
        recommendations.append(u"Unable to calculate MyISAM indexes on remote MySQL server < 5.0.0")
    elif calc.total_myisam_indexes == 0:
        option.format_print(u"None of your MyISAM tables are indexed - add indexes immediately", style=u"bad")
    else:
        key_buffer_size_msg: str = (
            f"Key Buffer Size / Total MyISAM indexes: "
            f"{util.bytes_to_string(info.key_buffer_size)} / "
            f"{util.bytes_to_string(calc.total_myisam_indexes)}"
        )
        if info.key_buffer_size < calc.total_myisam_indexes and calc.pct_keys_from_memory < 95:
            option.format_print(key_buffer_size_msg, style=u"bad")
            adjusted_vars.append(f"key_buffer_size (> {util.bytes_to_string(calc.total_myisam_indexes)})")
        else:
            option.format_print(key_buffer_size_msg, style=u"good")

        read_key_buffer_msg: str = (
            f"Read Key Buffer Hit Rate: {calc.pct_keys_from_memory}% "
            f"({util.bytes_to_string(stat.key_read_requests)} cached / "
            f"{util.bytes_to_string(stat.key_reads)} reads)"
        )
        if stat.key_read_requests > 0:
            if calc.pct_keys_from_memory < 95:
                option.format_print(read_key_buffer_msg, style=u"bad")
            else:
                option.format_print(read_key_buffer_msg, style=u"good")
        else:
            # No Queries have run that would use keys
            option.format_print(read_key_buffer_msg, style=u"debug")

        write_key_buffer_msg: str = (
            f"Write Key Buffer Hit Rate: {calc.pct_write_keys_from_memory}% "
            f"({util.bytes_to_string(stat.key_write_requests)} cached / "
            f"{util.bytes_to_string(stat.key_writes)} writes)"
        )
        if stat.key_write_requests > 0:
            if calc.pct_write_keys_from_memory < 95:
                option.format_print(write_key_buffer_msg, style=u"bad")
            else:
                option.format_print(write_key_buffer_msg, style=u"good")
        else:
            # No Queries have run that would use keys
            option.format_print(write_key_buffer_msg, style=u"debug")

    return recommendations, adjusted_vars


def mariadb_threadpool(option: tuner.Option, info: tuner.Info) -> typ.Sequence[typ.List[str], typ.List[str]]:
    """Recommendations for ThreadPool

    :param tuner.Option option:
    :param tuner.Info info:
    :return typ.Sequence[typ.List[str], typ.List[str]]: list of recommendations and list of adjusted variables
    """
    recommendations: typ.List[str] = []
    adjusted_vars: typ.List[str] = []

    option.format_print(u"ThreadPool Metrics", style=u"subheader")

    # AriaDB
    if not info.have_threadpool:
        option.format_print(u"ThreadPool stat is disabled.", style=u"info")
        return recommendations, adjusted_vars

    option.format_print(u"ThreadPool stat is enabled.", style=u"info")
    option.format_print(f"Thread Pool size: {info.thread_pool_size} thread(s)", style=u"info")

    versions: typ.Sequence[str] = (
        u"mariadb",
        u"percona"
    )
    if any(version in info.version.lower() for version in versions):
        option.format_print(f"Using default value is good enough for your version ({info.version})", style=u"info")
        return recommendations, adjusted_vars

    if info.have_innodb:
        if info.thread_pool_size < 16 or info.thread_pool_size > 36:
            option.format_print(u"thread_pool_size between 16 and 36 when using InnoDB storage engine.", style=u"bad")
            recommendations.append(
                f"Thread Pool size for InnoDB usage ({info.thread_pool_size})"
            )
            adjusted_vars.append(
                u"thread_pool_size between 16 and 36 for InnoDB usage"
            )
        else:
            option.format_print(u"thread_pool_size between 16 and 36 when using InnoDB storage engine", style=u"good")

    if info.have_myisam:
        if info.thread_pool_size < 4 or info.thread_pool_size > 8:
            option.format_print(u"thread_pool_size between 4 and 8 when using MyISAM storage engine.", style=u"bad")
            recommendations.append(
                f"Thread Pool size for MyISAM usage ({info.thread_pool_size})"
            )
            adjusted_vars.append(
                u"thread_pool_size between 4 and 8 for MyISAM usage"
            )
        else:
            option.format_print(u"thread_pool_size between 4 and 8 when using MyISAM storage engine", style=u"good")

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

    pf_memory_query: sqla.Text = info.query_from_file(u"performance_schema-memory-query.sql")
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
        option.format_print(u"AriaDB is disabled.", style=u"info")
        return recommendations, adjusted_vars

    option.format_print(u"AriaDB is enabled.", style=u"info")

    # Aria pagecache
    if calc.total_ariadb_indexes == 0 and option.do_remote:
        recommendations.append(
            u"Unable to calculate AriaDB indexes on remote MySQL server < 5.0.0"
        )
    elif calc.total_ariadb_indexes == 0:
        option.format_print(u"None of your AriaDB tables are indexed - add indexes immediately", style=u"bad")
    else:
        ariadb_pagecache_size_message: str = (
            u"AriaDB pagecache size / total AriaDB indexes: "
            f"{util.bytes_to_string(info.ariadb_pagecache_buffer_size)}/"
            f"{util.bytes_to_string(calc.total_ariadb_indexes)}"
        )
        if info.ariadb_pagecache_buffer_size < calc.total_ariadb_indexes and calc.pct_ariadb_keys_from_memory < 95:
            option.format_print(ariadb_pagecache_size_message, style=u"bad")
            adjusted_vars.append(
                f"ariadb_pagecache_buffer_size (> {util.bytes_to_string(calc.total_ariadb_indexes)})"
            )
        else:
            option.format_print(ariadb_pagecache_size_message, style=u"good")

        if stat.ariadb_pagecache_read_requests > 0:
            ariadb_pagecache_read_message: str = (
                f"AriaDB pagecache hit rate: {calc.pct_ariadb_keys_from_memory}% ("
                f"{util.bytes_to_string(stat.ariadb_pagecache_read_requests)} cached /"
                f"{util.bytes_to_string(stat.ariadb_pagecache_read_requests)} reads)"
            )
            if calc.pct_ariadb_keys_from_memory < 95:
                option.format_print(ariadb_pagecache_read_message, style=u"bad")
            else:
                option.format_print(ariadb_pagecache_read_message, style=u"good")

    return recommendations, adjusted_vars


def mariadb_tokudb(option: tuner.Option, info: tuner.Info) -> None:
    """Recommendations for TokuDB

    :param tuner.Option option:
    :param tuner.Info info:
    :return:
    """
    option.format_print(u"TokuDB Metrics", style=u"subheader")

    # Toku DB
    if not info.have_tokudb:
        option.format_print(u"TokuDB is disabled.", style=u"info")
        return

    option.format_print(u"TokuDB is enabled.", style=u"info")


def mariadb_xtradb(option: tuner.Option, info: tuner.Info) -> None:
    """Recommendations for XtraDB

    :param tuner.Option option:
    :param tuner.Info info:
    :return:
    """
    option.format_print(u"XtraDB Metrics", style=u"subheader")

    # Xtra DB
    if not info.have_xtradb:
        option.format_print(u"XtraDB is disabled.", style=u"info")
        return

    option.format_print(u"XtraDB is enabled.", style=u"info")


def mariadb_rocksdb(option: tuner.Option, info: tuner.Info) -> None:
    """Recommendations for RocksDB

    :param tuner.Option option:
    :param tuner.Info info:
    :return:
    """
    option.format_print(u"RocksDB Metrics", style=u"subheader")

    # Rocks DB
    if not info.have_rocksdb:
        option.format_print(u"RocksDB is disabled.", style=u"info")
        return

    option.format_print(u"RocksDB is enabled.", style=u"info")


def mariadb_spider(option: tuner.Option, info: tuner.Info) -> None:
    """Recommendations for Spider

    :param tuner.Option option:
    :param tuner.Info info:
    :return:
    """
    option.format_print(u"Spider Metrics", style=u"subheader")

    # Toku DB
    if not info.have_spider:
        option.format_print(u"Spider is disabled.", style=u"info")
        return

    option.format_print(u"Spider is enabled.", style=u"info")


def mariadb_connect(option: tuner.Option, info: tuner.Info) -> None:
    """Recommendations for Connect

    :param tuner.Option option:
    :param tuner.Info info:
    :return:
    """
    option.format_print(u"Connect Metrics", style=u"subheader")

    # Toku DB
    if not info.have_connect:
        option.format_print(u"Connect is disabled.", style=u"info")
        return

    option.format_print(u"Connect is enabled.", style=u"info")


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

    option.format_print(f"{galera_options}", style=u"debug")

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
) -> typ.Sequence[typ.List[str], typ.List[str], typ.DefaultDict]:
    """Recommendations for Galera

    :param orm.session.Session sess:
    :param tuner.Option option:
    :param tuner.Info info:
    :param tuner.Stat stat:
    :return typ.Sequence[typ.List[str], typ.List[str], typ.DefaultDict]:
        list of recommendations and list of adjusted variables, and results
    """
    recommendations: typ.List[str] = []
    adjusted_vars: typ.List[str] = []
    results: typ.DefaultDict = clct.defaultdict(clct.defaultdict(clct.defaultdict(dict)))

    option.format_print(u"Galera Metrics", style=u"subheader")

    # Galera Cluster
    if not info.have_galera:
        option.format_print(u"Galera is disabled.", style=u"info")
        return recommendations, adjusted_vars, results

    option.format_print(u"Galera is enabled.", style=u"info")

    option.format_print(u"Galera variables:", style=u"debug")
    galera_infos: typ.Sequence[typ.Tuple[str, typ.Any]] = [
        (galera_key, galera_value)
        for galera_key, galera_value in util.class_variables(info)
        if u"wsrep" in galera_key
        and galera_key != u"wsrep_provider_options"
    ]
    for galera_info, galera_value in galera_infos:
        option.format_print(f"\t{galera_info} = {galera_value}", style=u"debug")
        results[u"Galera"][u"Info"][galera_info]: typ.Any = galera_value

    option.format_print(u"Galera wsrep provider options:", style=u"debug")
    galera_options: typ.Sequence[str] = wsrep_options(option, info)
    results[u"Galera"][u"wsrep options"]: typ.Sequence[str] = galera_options
    for galera_option in galera_options:
        option.format_print(f"\t{galera_option.strip()}", style=u"debug")

    option.format_print(u"Galera status:", style=u"debug")
    galera_stats: typ.Sequence[typ.Tuple[str, typ.Any]] = [
        (galera_key, galera_value)
        for galera_key, galera_value in util.class_variables(stat)
        if u"wsrep" in galera_key
    ]
    for galera_stat, galera_value in galera_stats:
        option.format_print(f"\t{galera_stat} = {galera_value}", style=u"debug")
        results[u"Galera"][u"Status"][galera_stat]: typ.Any = galera_value

    option.format_print(
        f"GCache is using {util.bytes_to_string(wsrep_option(option, info, key=u'gcache.mem_size'))}",
        style=u"info"
    )

    wsrep_slave_threads: int = wsrep_option(option, info, key=u"wsrep_slave_threads")
    cpu_count: int = psu.cpu_count()
    if wsrep_slave_threads < 3 * cpu_count or wsrep_slave_threads > 4 * cpu_count:
        option.format_print(u"wsrep_slave_threads is not between 3 to 4 times the number of CPU(s)", style=u"bad")
        adjusted_vars.append(u"wsrep_slave_threads = 4 * # of Core CPU")
    else:
        option.format_print(u"wsrep_slave_threads is between 3 to 4 times the number of CPU(s)", style=u"good")

    gcs_limit: int = wsrep_option(option, info, key=u"gcs.limit")
    if gcs_limit != 5 * wsrep_slave_threads:
        option.format_print(u"gcs.limit should be equal to 5 * wsrep_slave_threads", style=u"bad")
        adjusted_vars.append(u"wsrep_slave_threads = 5 * # wsrep_slave_threads")
    else:
        option.format_print(u"gcs.limit is equal to 5 * wsrep_slave_threads", style=u"good")

    wsrep_flow_control_paused: float = wsrep_option(option, info, key=u"wsrep_flow_control_paused")
    if wsrep_flow_control_paused > 0.02:
        option.format_print(u"Flow control fraction > 0.02", style=u"bad")
    else:
        option.format_print(u"Flow control fraction seems to be OK", style=u"good")

    non_primary_key_table_query: sqla.Text = info.query_from_file(u"non_primary-key-table-query.sql")
    result = sess.execute(non_primary_key_table_query)
    NonPrimaryKeyTable = clct.namedtuple(u"NonPrimaryKeyTable", result.keys())
    non_primary_key_tables: typ.Sequence[str] = [
        NonPrimaryKeyTable(*non_primary_key_table).TABLE
        for non_primary_key_table in result.fetchall()
    ]

    results[u"Tables without a Primary Key"]: typ.Sequence[str] = []
    if len(non_primary_key_tables) > 0:
        option.format_print(u"Following table(s) don't have primary keys:", style=u"bad")
        for non_primary_key_table in non_primary_key_tables:
            option.format_print(f"\t{non_primary_key_table}", style=u"bad")
            results[u"Tables without a Primary Key"].append(non_primary_key_table)
    else:
        option.format_print(u"All tables have a primary key", style=u"good")

    non_innodb_table_query: sqla.Text = info.query_from_file(u"non_innodb-table-query.sql")
    result = sess.execute(non_innodb_table_query)
    NonInnoDBTable = clct.namedtuple(u"NonInnoDBTable", result.keys())
    non_innodb_tables: typ.Sequence[str] = [
        NonInnoDBTable(*non_innodb_table).TABLE
        for non_innodb_table in result.fetchall()
    ]

    if len(non_innodb_tables) > 0:
        option.format_print(u"Following table(s) are not InnoDB table(s):", style=u"bad")
        for non_innodb_table in non_innodb_tables:
            option.format_print(f"\t{non_innodb_table}", style=u"bad")
            recommendations.append(u"Ensure that all tables are InnoDB tables for Galera replication")
    else:
        option.format_print(u"All tables are InnoDB tables", style=u"good")

    if info.binlog_format != u"ROW":
        option.format_print(u"Binlog format should be in ROW mode.", style=u"bad")
        adjusted_vars.append(u"binlog_format = ROW")
    else:
        option.format_print(u"Binlog format is in ROW mode.", style=u"bad")

    if info.innodb_flush_log_at_trx_commit:
        option.format_print(u"InnoDB flush log at each commit should be disabled.", style=u"bad")
        adjusted_vars.append(u"innodb_flush_log_at_trx_commit = False")
    else:
        option.format_print(u"InnoDB flush log at each commit is disabled", style=u"good")

    option.format_print(f"Read consistency mode: {info.wsrep_causal_reads}", style=u"info")
    if info.wsrep_cluster_name and info.wsrep_on:
        option.format_print(u"Galera WsREP is enabled.", style=u"good")
        if info.wsrep_cluster_address.strip():
            option.format_print(f"Galera Cluster address is defined: {info.wsrep_cluster_address}", style=u"good")

            nodes: typ.Sequence[str] = info.wsrep_cluster_address.split(u",")
            option.format_print(f"There are {len(nodes)} nodes in wsrep_cluster_size", style=u"info")

            node_amount: int = stat.wsrep_cluster_size
            if node_amount in (3, 5):
                option.format_print(f"There are {node_amount} nodes in wsrep_cluster_size", style=u"good")
            else:
                option.format_print((
                    f"There are {node_amount} nodes in wsrep_cluster_size. "
                    u"Prefer 3 or 5 node architecture"
                ), style=u"bad")
                recommendations.append(u"Prefer 3 or 5 node architecture")

            # wsrep_cluster_address doesn't include garbd nodes
            if len(nodes) > node_amount:
                option.format_print((
                    u"All cluster nodes are not detected. "
                    u"wsrep_cluster_size less then node count in wsrep_cluster_address"
                ), style=u"bad")
            else:
                option.format_print(u"All cluster nodes detected.", style=u"good")
        else:
            option.format_print(u"Galera Cluster address is undefined", style=u"bad")
            adjusted_vars.append(u"Set up wsrep_cluster_name variable for Galera replication")

        if info.wsrep_node_name.strip():
            option.format_print(f"Galera node name is defined: {info.wsrep_node_name}", style=u"good")
        else:
            option.format_print(u"Galera node name is not defined", style=u"bad")
            adjusted_vars.append(u"Set up wsrep_node_name variable for Galera replication")

        if info.wsrep_notify_cmd.strip():
            option.format_print(f"Galera notify command is defined: {info.wsrep_notify_cmd}", style=u"good")
        else:
            option.format_print(u"Galera notify command is not defined", style=u"bad")
            adjusted_vars.append(u"Set up wsrep_notify_cmd variable for Galera replication")

        if "xtrabackup" in info.wsrep_sst_method.strip():
            option.format_print(f"Galera SST method is based on xtrabackup", style=u"good")
        else:
            option.format_print(u"Galera node name is not xtrabackup based", style=u"bad")
            adjusted_vars.append(u"Set up parameter wsrep_sst_method variable to xtrabackup based parameter")

        if info.wsrep_osu_method == "TOI":
            option.format_print(u"TOI is the default mode for upgrade.", style=u"good")
        else:
            option.format_print(u"Schema upgrades are not replicated automatically.", style=u"bad")
            adjusted_vars.append(u"Set wsrep_osu_method = 'TOI'")

        option.format_print(f"Max WsREP message: {util.bytes_to_string(info.wsrep_max_ws_size)}", style=u"info")
    else:
        option.format_print(u"Galera WsREP is disabled.", style=u"bad")

    if stat.wsrep_connected:
        option.format_print(u"Node is connected", style=u"good")
    else:
        option.format_print(u"Node is not connected", style=u"bad")

    if stat.wsrep_ready:
        option.format_print(u"Node is ready", style=u"good")
    else:
        option.format_print(u"Node is not ready", style=u"bad")

    option.format_print(f"Cluster status: {stat.wsrep_cluster_status}", style=u"info")
    if stat.wsrep_cluster_status.title() == u"Primary":
        option.format_print(u"Galera cluster is consistent and ready for operations", style=u"good")
    else:
        option.format_print(u"Galera cluster is not consistent and ready", style=u"bad")

    if stat.wsrep_local_state_uuid == stat.wsrep_cluster_state_uuid:
        option.format_print((
            f"Node and whole cluster at the same level: {stat.wsrep_cluster_state_uuid}"
        ), style=u"good")
    else:
        option.format_print(u"None and whole cluster not at same level", style=u"bad")
        option.format_print(f"Node    state uuid: {stat.wsrep_local_state_uuid}", style=u"info")
        option.format_print(f"Cluster state uuid: {stat.wsrep_cluster_state_uuid}", style=u"info")

    if stat.wsrep_local_state_comment.title() == u"Synced":
        option.format_print(u"Node is synced with whole cluster", style=u"good")
    else:
        option.format_print(u"Node is not synced", style=u"bad")
        option.format_print(f"Node state: {stat.wsrep_local_state_comment}", style=u"info")

    if stat.wsrep_local_cert_failures == 0:
        option.format_print(u"There are no certification failures detected", style=u"good")
    else:
        option.format_print(
            f"There are {stat.wsrep_local_cert_failures} certification failure(s) detected",
            style=u"bad"
        )

    wsrep_galera_stats: typ.Sequence[typ.Tuple[str, typ.Any]] = [
        (galera_key, galera_value)
        for galera_key, galera_value in util.class_variables(stat)
        if u"wsrep" in galera_key
        or u"galera" in galera_key
    ]
    for wsrep_galera_stat, wsrep_galera_value in wsrep_galera_stats:
        option.format_print(f"WsRep: {wsrep_galera_stat} = {wsrep_galera_value}", style=u"debug")

    option.format_print(",".join(wsrep_options(option, info)), style=u"debug")

    return recommendations, adjusted_vars, results


def mysql_innodb(
    option: tuner.Option,
    info: tuner.Info,
    stat: tuner.Stat,
    calc: tuner.Calc
) -> typ.Sequence[typ.List[str], typ.List[str], typ.DefaultDict]:
    """Recommendations for InnoDB

    :param tuner.Option option:
    :param tuner.Info info:
    :param tuner.Stat stat:
    :param tuner.Calc calc:

    :return typ.Sequence[typ.List[str], typ.List[str], typ.DefaultDict]:
        list of recommendations and list of adjusted variables, and results
    """
    recommendations: typ.List[str] = []
    adjusted_vars: typ.List[str] = []
    results: typ.DefaultDict = clct.defaultdict(clct.defaultdict(clct.defaultdict(dict)))

    option.format_print(u"InnoDB Metrics", style=u"subheader")

    # InnoDB
    if not info.have_innodb:
        option.format_print(u"InnoDB is disabled.", style=u"info")
        if (info.ver_major, info.ver_minor) >= (5, 5):
            option.format_print(
                u"InnoDB Storage Engine is disabled. InnoDB is the default storage engine",
                style=u"bad"
            )

        return recommendations, adjusted_vars

    option.format_print(u"InnoDB is enabled.", style=u"info")

    if option.buffers:
        option.format_print(u"InnoDB Buffers", style=u"info")

        option.format_print(
            f" +-- InnoDB Buffer Pool: {util.bytes_to_string(info.innodb_buffer_pool_size)}",
            style=u"info"
        )

        option.format_print((
            u" +-- InnoDB Buffer Pool Instances:"
            f" {util.bytes_to_string(info.innodb_buffer_pool_instances)}"
        ), style=u"info")

        option.format_print((
            u" +-- InnoDB Buffer Pool Chunk Size:"
            f" {util.bytes_to_string(info.innodb_buffer_pool_chunk_size)}"
        ), style=u"info")

        option.format_print((
            u" +-- InnoDB Additional Mem Pool:"
            f" {util.bytes_to_string(info.innodb_additional_mem_pool_size)}"
        ), style=u"info")

        option.format_print((
            u" +-- InnoDB Log File Size:"
            f" {util.bytes_to_string(info.innodb_log_file_size)}"
            f"({calc.innodb_log_size_pct}% of buffer pool)"
        ), style=u"info")

        option.format_print((
            u" +-- InnoDB Log Files In Group:"
            f" {util.bytes_to_string(info.innodb_log_files_in_group)}"
        ), style=u"info")

        option.format_print((
            u" +-- InnoDB Total Log File Size:"
            f" {util.bytes_to_string(info.innodb_log_files_in_group * info.innodb_log_file_size)}"
        ), style=u"info")

        option.format_print((
            u" +-- InnoDB Log Buffer:"
            f" {util.bytes_to_string(info.innodb_log_buffer_size)}"
        ), style=u"info")

        option.format_print((
            u" +-- InnoDB Log Buffer Free:"
            f" {util.bytes_to_string(stat.innodb_buffer_pool_pages_free)}"
        ), style=u"info")

        option.format_print((
            u" +-- InnoDB Log Buffer Used:"
            f" {util.bytes_to_string(stat.innodb_buffer_pool_pages_total)}"
        ), style=u"info")

    option.format_print((
        u" +-- InnoDB Thread Concurrency:"
        f" {util.bytes_to_string(info.innodb_thread_concurrency)}"
    ), style=u"info")

    if info.innodb_file_per_table:
        option.format_print(u"InnoDB file per table is activated", style=u"good")
    else:
        option.format_print(u"InnoDB file per table is not activated", style=u"bad")
        adjusted_vars.append(u"innodb_file_per_table=ON")

    # TODO figure out engine_stat
    # InnoDB Buffer Pool Size
    if info.innodb_buffer_pool_size > engine_stat.innodb:
        option.format_print((
            u"InnoDB Buffer Pool / Data size: "
            f"{util.bytes_to_string(info.innodb_buffer_pool_size)}/"
            f"{util.bytes_to_string(engine_stat.innodb)}"
        ), style=u"good")
    else:
        option.format_print((
            u"InnoDB Buffer Pool / Data size: "
            f"{util.bytes_to_string(info.innodb_buffer_pool_size)}/"
            f"{util.bytes_to_string(engine_stat.innodb)}"
        ), style=u"bad")
        adjusted_vars.append(
            f"innodb_buffer_pool_size (>= {util.bytes_to_string(engine_stat.innodb)}) if possible."
        )

    if 20 <= calc.innodb_log_size_pct <= 30:
        option.format_print((
            u"InnoDB Log file size / InnoDB Buffer pool size "
            f"({calc.innodb_log_size_pct}%): "
            f"{util.bytes_to_string(info.innodb_log_file_size)} * "
            f"{info.innodb_log_files_in_group} / "
            f"{util.bytes_to_string(info.innodb_buffer_pool_size)} "
            u"should be equal 25%"
        ), style=u"good")
    else:
        option.format_print((
            u"InnoDB Log file size / InnoDB Buffer pool size "
            f"({calc.innodb_log_size_pct}%): "
            f"{util.bytes_to_string(info.innodb_log_file_size)} * "
            f"{info.innodb_log_files_in_group} / "
            f"{util.bytes_to_string(info.innodb_buffer_pool_size)} "
            u"should be equal 25%"
        ), style=u"bad")
        adjusted_vars.append((
            u"innodb_log_file_size * innodb_log_files_in_group should be equal to 25% of buffer pool size "
            f"(={util.bytes_to_string(int(info.innodb_buffer_pool_size * info.innodb_log_files_in_group / 4))}) "
            u"if possible"
        ))

    # InnoDB Buffer Pool Instances (MySQL 5.6.6+)
    # Bad Value if > 64
    if info.innodb_buffer_pool_instances > 64:
        option.format_print(f"InnoDB Buffer pool instances: {info.innodb_buffer_pool_instances}", style=u"bad")
        adjusted_vars.append(u"innodb_buffer_pool_instances (<= 64)")

    # InnoDB Buffer Pool Size > 1 GB
    if info.innodb_buffer_pool_size > 1 * 1024 ** 3:
        # InnoDB Buffer Pool Size / 1 GB = InnoDB Buffer Pool Instances limited to 64 max.
        # InnoDB Buffer Pool Size > 64 GB
        max_innodb_buffer_pool_instances: int = min(int(info.innodb_buffer_pool_size / (1024 ** 3)), 64)

        if info.innodb_buffer_pool_instances == max_innodb_buffer_pool_instances:
            option.format_print(f"InnoDB Buffer pool instances: {info.innodb_buffer_pool_instances}", style=u"good")
        else:
            option.format_print(f"InnoDB Buffer pool instances: {info.innodb_buffer_pool_instances}", style=u"bad")
            adjusted_vars.append(f"innodb_buffer_pool_instances (= {max_innodb_buffer_pool_instances})")
    else:
        if info.innodb_buffer_pool_instances == 1:
            option.format_print(f"InnoDB Buffer pool instances {info.innodb_buffer_pool_instances}", style=u"good")
        else:
            option.format_print(u"InnoDB Buffer pool <= 1 GB and innodb_buffer_pool_instances != 1", style=u"bad")
            adjusted_vars.append(u"innodb_buffer_pool_instances (== 1)")

    # InnoDB Used Buffer Pool Size vs CHUNK size
    if info.innodb_buffer_pool_chunk_size:
        option.format_print(u"InnoDB Buffer Pool Chunk Size not used or defined in your version", style=u"info")
    else:
        option.format_print((
            u"Number of InnoDB Buffer Pool Chunks: "
            f"{info.innodb_buffer_pool_size} / {info.innodb_buffer_pool_chunk_size} for "
            f"{info.innodb_buffer_pool_instances} Buffer Pool Instance(s)"
        ), style=u"info")

        if info.innodb_buffer_pool_size % (info.innodb_buffer_pool_chunk_size * info.innodb_buffer_pool_instances) == 0:
            option.format_print((
                u"innodb_buffer_pool_size aligned with innodb_buffer_pool_chunk_size & innodb_buffer_pool_instances"
            ), style=u"good")
        else:
            option.format_print((
                u"innodb_buffer_pool_size not aligned with innodb_buffer_pool_chunk_size & innodb_buffer_pool_instances"
            ), style=u"bad")
            adjusted_vars.append((
                u"innodb_buffer_pool_size must always be equal to "
                u"or a multiple of innodb_buffer_pool_chunk_size * innodb_buffer_pool_instances"
            ))

    # InnoDB Read Efficiency
    if calc.pct_read_efficiency > 90:
        option.format_print((
            f"{calc.pct_read_efficiency}% "
            f"({stat.innodb_buffer_pool_read_requests - stat.innodb_buffer_pool_reads} hits / "
            f"{stat.innodb_buffer_pool_read_requests} total)"
        ), style=u"good")
    else:
        option.format_print((
            f"{calc.pct_read_efficiency}% "
            f"({stat.innodb_buffer_pool_read_requests - stat.innodb_buffer_pool_reads} hits / "
            f"{stat.innodb_buffer_pool_read_requests} total)"
        ), style=u"bad")

    # InnoDB Write Efficiency
    if calc.pct_write_efficiency > 90:
        option.format_print((
            f"{calc.pct_read_efficiency}% "
            f"({stat.innodb_log_write_requests - stat.innodb_log_writes} hits / "
            f"{stat.innodb_log_write_requests} total)"
        ), style=u"good")
    else:
        option.format_print((
            f"{calc.pct_read_efficiency}% "
            f"({stat.innodb_log_write_requests - stat.innodb_log_writes} hits / "
            f"{stat.innodb_log_write_requests} total)"
        ), style=u"bad")

    # InnoDB Log Waits
    if calc.pct_read_efficiency > 90:
        option.format_print((
            u"InnoDB Log Waits:"
            f"{util.percentage(stat.innodb_log_waits, stat.innodb_log_writes)}% "
            f"({stat.innodb_log_waits} waits / "
            f"{stat.innodb_log_writes} writes)"
        ), style=u"good")
    else:
        option.format_print((
            u"InnoDB Log Waits:"
            f"{util.percentage(stat.innodb_log_waits, stat.innodb_log_writes)}% "
            f"({stat.innodb_log_waits} waits / "
            f"{stat.innodb_log_writes} writes)"
        ), style=u"bad")
        adjusted_vars.append(
            f"innodb_log_buffer_size (>= {util.bytes_to_string(info.innodb_log_buffer_size)})"
        )

    results[u"Calculations"]: typ.Dict = {
        attr: getattr(calc, attr)
        for attr in dir(calc)
        if not callable(getattr(calc, attr))
        and not attr.startswith(u"__")
    }

    return recommendations, adjusted_vars, results


def mysql_databases(
    sess: orm.session.Session,
    option: tuner.Option,
    info: tuner.Info
) -> typ.Sequence[typ.List[str], typ.List[str], typ.DefaultDict]:
    """Recommendations for database metrics

    :param orm.session.Session sess:
    :param tuner.Option option:
    :param tuner.Info info:
    :return typ.Sequence[typ.List[str], typ.List[str], typ.DefaultDict]:
        list of recommendations and list of adjusted variables, and results
    """
    recommendations: typ.List[str] = []
    adjusted_vars: typ.List[str] = []
    results: typ.DefaultDict = clct.defaultdict(clct.defaultdict(clct.defaultdict(dict)))

    if not option.db_stat:
        return recommendations, adjusted_vars, results

    option.format_print(u"Database Metrics", style=u"subheader")
    if (info.ver_major, info.ver_minor) >= (5, 5):
        option.format_print(u"Skip Database metrics from information schema missing in this version", style=u"info")
        return recommendations, adjusted_vars

    database_query: sqla.Text = info.query_from_file(u"all-databases.sql")
    result = sess.execute(database_query)
    Database = clct.namedtuple(u"Database", result.keys())
    databases: typ.Sequence[str] = [
        Database(*database).Database
        for database in result.fetchall()
    ]

    option.format_print(f"There are {len(databases)} Databases", style=u"info")

    databases_info_query: sqla.Text = info.query_from_file(u"databases-info-query.sql")
    result = sess.execute(databases_info_query)
    DatabasesInfo = clct.namedtuple(u"DatabasesInfo", result.keys())
    databases_info: DatabasesInfo = [
        DatabasesInfo(*databases_info)
        for databases_info in result.fetchall()
    ][0]
    option.format_print(u"All Databases:", style=u"info")
    option.format_print(f" +-- TABLE      : {databases_info.TABLE_COUNT}", style=u"info")
    option.format_print(f" +-- ROWS       : {databases_info.ROW_AMOUNT}", style=u"info")
    option.format_print((
        f" +-- DATA       : {util.bytes_to_string(databases_info.DATA_SIZE)} "
        f"({util.percentage(databases_info.DATA_SIZE, databases_info.TOTAL_SIZE)}%)"
    ), style=u"info")
    option.format_print((
        f" +-- INDEX      : {util.bytes_to_string(databases_info.INDEX_SIZE)} "
        f"({util.percentage(databases_info.INDEX_SIZE, databases_info.TOTAL_SIZE)}%)"
    ), style=u"info")

    table_collation_query: sqla.Text = info.query_from_file(u"all-table-collations-query.sql")
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
    option.format_print((
        f" +-- COLLATION  : {databases_info.COLLATION_COUNT} "
        f"({all_table_collations})"
    ), style=u"info")

    table_engine_query: sqla.Text = info.query_from_file(u"all-table-engines-query.sql")
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
    option.format_print((
        f" +-- ENGINE     : {databases_info.ENGINE_COUNT} "
        f"({all_table_engines})"
    ), style=u"info")

    results[u"Databases"]: typ.Dict = {
        u"Rows": databases_info.ROW_AMOUNT,
        u"Data Size": databases_info.DATA_SIZE,
        u"Data Percent": util.percentage(databases_info.DATA_SIZE, databases_info.TOTAL_SIZE),
        u"Index Size": databases_info.INDEX_SIZE,
        u"Index Percent": util.percentage(databases_info.INDEX_SIZE, databases_info.TOTAL_SIZE),
        u"Total Size": databases_info.TOTAL_SIZE
    }

    if not (option.silent and option.json):
        print(u"\n")

    database_info_query: sqla.Text = info.query_from_file(u"database-info-query.sql")
    for database in databases:
        result = sess.execute(database_info_query, TABLE_SCHEMA=database)
        DatabaseInfo = clct.namedtuple(u"DatabaseInfo", result.keys())
        database_info: DatabaseInfo = [
            DatabaseInfo(*database_info)
            for database_info in result.fetchall()
        ][0]
        option.format_print(f"Database: {database}", style=u"info")
        option.format_print(f" +-- TABLE      : {database_info.TABLE_COUNT}", style=u"info")
        option.format_print(f" +-- ROWS       : {database_info.ROW_AMOUNT}", style=u"info")
        option.format_print((
            f" +-- DATA       : {util.bytes_to_string(database_info.DATA_SIZE)} "
            f"({util.percentage(database_info.DATA_SIZE, database_info.TOTAL_SIZE)}%)"
        ), style=u"info")
        option.format_print((
            f" +-- INDEX      : {util.bytes_to_string(database_info.INDEX_SIZE)} "
            f"({util.percentage(database_info.INDEX_SIZE, database_info.TOTAL_SIZE)}%)"
        ), style=u"info")

        table_collation_query: sqla.Text = info.query_from_file(u"table-collations-query.sql")
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
        option.format_print((
            f" +-- COLLATION  : {database_info.COLLATION_COUNT} "
            f"({all_table_collations})"
        ), style=u"info")

        table_engine_query: sqla.Text = info.query_from_file(u"table-engines-query.sql")
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
        option.format_print((
            f" +-- ENGINE     : {database_info.ENGINE_COUNT} "
            f"({all_table_engines})"
        ), style=u"info")

        if database_info.DATA_LENGTH < database_info.INDEX_LENGTH:
            option.format_print(f"Index size is larger than data size for {database}", style=u"bad")
        if database_info.ENGINE_COUNT > 1:
            option.format_print(f"There are {database_info.ENGINE_COUNT} storage engines. Be careful.", style=u"bad")

        results[u"Databases"][database]: typ.Dict = {
            u"Rows": database_info.ROW_AMOUNT,
            u"Tables": database_info.TABLE_COUNT,
            u"Collations": database_info.COLLATION_COUNT,
            u"Data Size": database_info.DATA_SIZE,
            u"Data Percent": util.percentage(database_info.DATA_SIZE, database_info.TOTAL_SIZE),
            u"Index Size": databases_info.INDEX_SIZE,
            u"Index Percent": util.percentage(database_info.INDEX_SIZE, database_info.TOTAL_SIZE),
            u"Total Size": database_info.TOTAL_SIZE
        }

        if database_info.COLLATION_COUNT > 1:
            option.format_print(
                f"{database_info.COLLATION_COUNT} different collations for database {database}",
                style=u"bad"
            )
            recommendations.append(
                f"Check all table collations are identical for all tables in {database} database"
            )
        else:
            option.format_print(f"{database_info.COLLATION_COUNT} collation for database {database}", style=u"good")

        if database_info.ENGINE_COUNT > 1:
            option.format_print(f"{database_info.ENGINE_COUNT} different engines for database {database}", style=u"bad")
            recommendations.append(
                f"Check all table engines are identical for all tables in {database} database"
            )
        else:
            option.format_print(f"{database_info.ENGINE_COUNT} engine for database {database}", style=u"good")

        character_set_query: sqla.Text = info.query_from_file(u"character-set-query.sql")
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

        option.format_print(f"Character sets for {database} database table column: {all_character_sets}", style=u"info")

        character_set_count: int = len(all_character_sets)
        if character_set_count > 1:
            option.format_print(
                f"{character_set_count} table columns have several character sets defined for all text like columns",
                style=u"bad"
            )
            recommendations.append(
                f"Limit character sets for column to one character set if possible for {database} database"
            )
        else:
            option.format_print(
                f"{character_set_count} table columns have several character sets defined for all text like columns",
                style=u"good"
            )

        collation_query: sqla.Text = info.query_from_file(u"collation-query.sql")
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

        option.format_print(f"Collations for {database} database table column: {all_collations}", style=u"info")

        collation_count: int = len(all_collations)
        if collation_count > 1:
            option.format_print(
                f"{collation_count} table columns have several collations defined for all text like columns",
                style=u"bad"
            )
            recommendations.append(
                f"Limit collations for column to one collation if possible for {database} database"
            )
        else:
            option.format_print(
                f"{collation_count} table columns have several collations defined for all text like columns",
                style=u"good"
            )

    return recommendations, adjusted_vars, results


def mysql_indexes(
    sess: orm.session.Session,
    option: tuner.Option,
    info: tuner.Info,
) -> typ.Sequence[typ.List[str], typ.List[str], typ.DefaultDict]:
    """

    :param orm.session.Session sess:
    :param tuner.Option option:
    :param tuner.Info info:
    :return typ.Sequence[typ.List[str], typ.List[str], typ.DefaultDict]:
        list of recommendations and list of adjusted variables, and results    """
    recommendations: typ.List[str] = []
    adjusted_vars: typ.List[str] = []

    if not option.idx_stat:
        return recommendations, adjusted_vars

    option.format_print(u"Indexes Metrics", style=u"subheader")
    if (info.ver_major, info.ver_minor, info.ver_minor) < (5, 5):
        option.format_print(u"Skip Index metrics from information schema missing in this version", style=u"info")
        return recommendations, adjusted_vars

    worst_indexes_query: sqla.Text = info.query_from_file(u"worst-indexes-query.sql")
    result = sess.execute(worst_indexes_query)
    WorstIndex = clct.namedtuple(u"WorstIndex", result.keys())
    worst_indexes: typ.Sequence[WorstIndex] = [
        WorstIndex(*worst_index)
        for worst_index in result.fetchall()
    ]
    option.format_print(u"Worst Selectivity Indexes", style=u"info")
    for worst_index in worst_indexes:
        option.format_print(f"{worst_index}", style=u"debug")
        option.format_print(f"Index: {worst_index.INDEX}", style=u"info")

        option.format_print(f" +-- COLUMN      : {worst_index.SCHEMA_TABLE}", style=u"info")
        option.format_print(f" +-- SEQ_NUM     : {worst_index.SEQ_IN_INDEX} sequence(s)", style=u"info")
        option.format_print(f" +-- MAX_COLS    : {worst_index.MAX_COLUMNS} column(s)", style=u"info")
        option.format_print(f" +-- CARDINALITY : {worst_index.CARDINALITY} distinct values", style=u"info")
        option.format_print(f" +-- ROW_AMOUNT  : {worst_index.ROW_AMOUNT} rows", style=u"info")
        option.format_print(f" +-- INDEX_TYPE  : {worst_index.INDEX_TYPE}", style=u"info")
        option.format_print(f" +-- SELECTIVITY : {worst_index.SELECTIVITY}%", style=u"info")

        # TODO fill result object

        if worst_index.SELECTIVITY < 25:
            option.format_print(f"{worst_index.INDEX} has a low selectivity", style=u"bad")

    if not info.performance_schema:
        return recommendations, adjusted_vars

    unused_indexes_query: sqla.Text = info.query_from_file(u"unused-indexes-query.sql")
    result = sess.execute(unused_indexes_query)
    UnusedIndex = clct.namedtuple(u"UnusedIndex", result.keys())
    unused_indexes: typ.Sequence[UnusedIndex] = [
        UnusedIndex(*unused_index)
        for unused_index in result.fetchall()
    ]
    option.format_print(u"Unused Indexes", style=u"info")
    if len(unused_indexes) > 0:
        recommendations.append(u"Remove unused indexes.")
    for unused_index in unused_indexes:
        option.format_print(f"{unused_index}", style=u"debug")
        option.format_print(f"Index: {unused_index.INDEX} on {unused_index.SCHEMA_TABLE} is not used", style=u"bad")
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
    option.format_print(u"Recommendations", style=u"subheader")

    if recommendations:
        option.format_print(u"General Recommendations:", style=u"pretty")
        for recommendation in recommendations:
            option.format_print(f"\t{recommendation}", style=u"pretty")

    if adjusted_vars:
        option.format_print(u"Variables to Adjust:", style=u"pretty")
        if calc.pct_max_physical_memory > 90:
            option.format_print(u"  *** MySQL's maximum memory usage is dangerously high ***", style=u"pretty")
            option.format_print(u"  *** Add RAM before increasing MySQL buffer variables ***", style=u"pretty")
        for adjusted_var in adjusted_vars:
            option.format_print(f"\t{adjusted_var}", style=u"pretty")

    if not recommendations and not adjusted_vars:
        option.format_print(u"No additional performance recommendations are available.", style=u"pretty")


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
        option.format_print(f"{result}", style=u"debug")

    option.format_print(f"HTML REPORT: {option.report_file}", style=u"debug")

    if option.report_file:
        _template_model: str = template_model(option, info)
        with open(option.report_file, mode=u"w", encoding="utf-8") as rf:
            rf.write(_template_model.replace(u":data", json.dumps(result, sort_keys=True, indent=4)))

    if option.json:
        if option.pretty_json:
            print(json.dumps(result, sort_keys=True, indent=4))
        else:
            print(json.dumps(result))
