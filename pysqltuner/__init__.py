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
    option.format_print(header_message, style=tuner.Print.PRETTY)


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
    :return typ.Dict: results
    """
    # du_flags: str = u"-b" if re.match(r"Linux", current_os) else u""
    if option.force_mem is not None and option.force_mem > 0:
        physical_memory: int = option.force_mem * 1024 ** 2
        option.format_print(f"Assuming {option.force_mem} MB of physical memory", style=tuner.Print.INFO)

        if option.force_swap is not None and option.force_swap > 0:
            swap_memory: int = option.force_swap * 1024 ** 2
            option.format_print(f"Assuming {option.force_swap} MB of swap space", style=tuner.Print.INFO)
        else:
            swap_memory: int = 0
            option.format_print(u"Assuming 0 MB of swap space (Use --force-swap to specify)", style=tuner.Print.BAD)
    else:
        physical_memory: int = psu.virtual_memory().available
        swap_memory: int = psu.swap_memory().total

    option.format_print(f"Physical Memory: {physical_memory}", style=tuner.Print.DEBUG)
    option.format_print(f"Swap Memory: {swap_memory}", style=tuner.Print.DEBUG)

    process_memory: int = other_process_memory()

    results: typ.Dict = {
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

    return results


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
        option.format_print(f"Unable to find the mysqladmin command you specified {mysqladmin_command}", style=tuner.Print.BAD)
        raise FileNotFoundError
    elif not os.path.exists(mysqladmin_command):
        option.format_print(u"Couldn't find mysqladmin in your $PATH. Is MySQL installed?", style=tuner.Print.BAD)
        raise FileNotFoundError

    if option.mysqlcmd:
        mysql_command: str = option.mysqlcmd.strip()
    else:
        mysql_command: str = shutil.which(u"mysql").strip()

    if not os.path.exists(mysql_command) and option.mysqlcmd:
        option.format_print(f"Unable to find the mysql command you specified {mysql_command}", style=tuner.Print.BAD)
        raise FileNotFoundError
    elif not os.path.exists(mysql_command):
        option.format_print(u"Couldn't find mysql in your $PATH. Is MySQL installed?", style=tuner.Print.BAD)
        raise FileNotFoundError

    mysql_defaults_command: typ.Sequence[str] = (
        mysql_command,
        u"--print-defaults"
    )
    mysql_cli_defaults: str = util.get(mysql_defaults_command)
    option.format_print(f"MySQL Client: {mysql_cli_defaults}", style=tuner.Print.DEBUG)

    if re.match(r"auto-vertical-output", mysql_cli_defaults):
        option.format_print(u"Avoid auto-vertical-output in configuration file(s) for MySQL like", style=tuner.Print.BAD)
        raise Exception

    option.format_print(f"MySQL Client {mysql_command}", style=tuner.Print.DEBUG)

    option.port = 3306 if not option.port else option.port

    if option.socket:
        option.remote_connect: str = f"-S {option.socket} -P {option.port}"

    if option.host:
        option.host = option.host.strip()

        if not option.force_mem and option.host not in (u"127.0.0.1", u"localhost"):
            option.format_print(u"The --force-mem option is required for remote connections", style=tuner.Print.BAD)
            raise ConnectionRefusedError

        option.format_print(f"Performing tests on {option.host}:{option.port}", style=tuner.Print.INFO)
        option.remote_connect: str = f"-h {option.host} -P {option.port}"

        if option.host not in (u"127.0.0.1", u"localhost"):
            option.do_remote: bool = True

    if option.user and option.password:
        try:
            sess.execute("SELECT 1;")
            option.format_print(u"Logged in using credentials passed on the command line", style=tuner.Print.GOOD)
            return True
        except sqla.exc.SQLAlchemyError:
            option.format_print(u"Attempted to use login credentials, but they were invalid", style=tuner.Print.BAD)
            raise ConnectionRefusedError

    svcprop_exe: str = shutil.which(u"svcprop")
    if svcprop_exe.startswith(u"/"):
        try:
            sess.execute("SELECT 1;")
            option.format_print(u"Logged in using credentials passed from mysql-quickbackup", style=tuner.Print.GOOD)
            return True
        except sqla.exc.SQLAlchemyError:
            option.format_print(
                u"Attempted to use login credentials from mysql-quickbackup, they were invalid",
                style=tuner.Print.BAD
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
                style=tuner.Print.BAD
            )
            raise ConnectionRefusedError

    elif util.is_readable(u"/usr/local/directadmin/conf/mysql.conf") and not option.do_remote:
        # It's a DirectAdmin box, use the available credentials
        try:
            sess.execute("SELECT 1;")
            return True
        except sqla.exc.SQLAlchemyError:
            option.format_print(u"Attempted to use login credentials from DirectAdmin, but they failed", style=tuner.Print.BAD)
            raise ConnectionRefusedError

    elif util.is_readable(u"/etc/mysql/debian.cnf") and not option.do_remote:
        # We have a debian maintenance account, use the available credentials
        try:
            sess.execute("SELECT 1;")
            return True
        except sqla.exc.SQLAlchemyError:
            option.format_print(u"Logged in using credentials from debian maintenance account.", style=tuner.Print.GOOD)
            raise ConnectionRefusedError

    elif option.defaults_file and util.is_readable(option.defaults_file):
        # Defaults File
        option.format_print(f"defaults file detected: {option.defaults_file}", style=tuner.Print.DEBUG)
        try:
            sess.execute("SELECT 1;")
            option.format_print(u"Logged in using credentials from defaults file account.", style=tuner.Print.GOOD)
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
                option.format_print(u"Successfully authenticated with no password - SECURITY RISK!", style=tuner.Print.BAD)

            return True

        except sqla.exc.SQLAlchemyError:
            if option.no_ask:
                option.format_print(u"Attempted to use login credentials, but they were invalid", style=tuner.Print.BAD)
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
                            style=tuner.Print.BAD
                        )

                return True
            except sqla.exc.SQLAlchemyError:
                option.format_print(u"Attempted to use login credentials but they were invalid", style=tuner.Print.BAD)
                raise ConnectionRefusedError


def tuning_info(sess: orm.session.Session, option: tuner.Option) -> typ.Dict:
    """Gathers tuning information

    :param orm.session.Session sess:
    :param tuner.Option option:
    :return typ.Dict: results
    """
    results: typ.DefaultDict[typ.DefaultDict] = clct.defaultdict(clct.defaultdict(clct.defaultdict(dict)))

    result = sess.execute(r"\w\s")
    filtered_values: typ.Sequence[str] = (
        u"Threads:",
        u"Connection id:",
        u"pager:",
        u"Using"
    )
    info_pattern: str = r"\s*(.*):\s*(.*)"
    for line in result.fetchall():
        if all(line not in filtered_value for filtered_value in filtered_values):
            matched = re.match(info_pattern, line)
            key, val = matched.group(1).strip(), matched.group(2).strip()
            results[u"MySQL Client"][key] = val

    results[u"MySQL Client"][u"Client Path"]: str = option.mysqlcmd
    results[u"MySQL Client"][u"Admin Path"]: str = option.mysqladmin
    results[u"MySQL Client"][u"Authentication Info"]: str = option.mysqllogin

    return results


def mysql_status_vars(option: tuner.Option, info: tuner.Info, sess: orm.session.Session) -> typ.Dict:
    """Gathers all status variables

    :param tuner.Option option: options object
    :param tuner.Info info: info object
    :param orm.session.Session sess: session
    :return typ.Dict: results
    """
    results: typ.DefaultDict[typ.DefaultDict] = clct.defaultdict(clct.defaultdict(clct.defaultdict(dict)))

    # We need to initiate at least one query so that our data is usable
    version_query: sqla.Text = info.query_from_file(u"version_query.sql")
    try:
        result = sess.execute(version_query)
    except Exception:
        option.format_print(u"Not enough privileges for running PySQLTuner", style=tuner.Print.BAD)
        raise

    Version = clct.namedtuple(u"Version", result.keys())
    version: str = [
        Version(*version).VERSION.split("-")[0]
        for version in result.fetchall()
    ][0]
    results[u"MySQL Client"][u"Version"]: str = version

    option.format_print(f"VERSION: {version}", style=tuner.Print.DEBUG)

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
    results[u"Variables"]: typ.Sequence[typ.Tuple[str, str]] = variables

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
    results[u"Status"]: typ.Sequence[typ.Tuple[str, str]] = statuses

    if info.wsrep_provider_options:
        info.have_galera = True
        option.format_print(f"Galera options: {info.wsrep_provider_options}", style=tuner.Print.DEBUG)

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
    engine_supports: typ.Sequence[typ.Tuple[str, str]] = [
        (engs.ENGINE, engs.SUPPORT)
        for engs in [
            EngineSupport(*engine_support)
            for engine_support in result.fetchall()
        ]
    ]

    for engine, support in engine_supports:
        if engine.lower() in (u"federated", u"blackhole"):
            engine_name: str = f"{engine}_engine"
        elif engine.lower() == u"berkeleydb":
            engine_name: str = u"bdb"
        else:
            engine_name: str = engine

        engine_value: str = "YES" if support == u"DEFAULT" else support

        setattr(info, f"have_{engine_name}", engine_value)
        results[u"Storage Engines"][engine_name] = support

    option.format_print(f"{engine_supports}", style=tuner.Print.DEBUG)
    mysql_slave: typ.Sequence[str] = sess.execute(sqla.Text(u"SHOW SLAVE STATUS\\G;")).fetchall()
    results[u"Replication"][u"Status"]: typ.Sequence[str] = mysql_slave
    info.replicas: typ.Sequence[str] = mysql_slave

    mysql_slaves: typ.Sequence[str] = sess.execute(sqla.Text(u"SHOW SLAVE HOSTS;")).fetchall()

    for slave in mysql_slaves:
        option.format_print(f"L: {slave}", style=tuner.Print.DEBUG)
        slave_items: typ.Sequence[str] = slave.split()
        info.slaves[slave_items[0]]: str = slave
        results[u"Replication"][u"Slaves"][slave_items[0]]: str = slave_items[4]

    return results


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
                option.format_print(f"Mount point {mount_point} is using {space_perc} % total space", style=tuner.Print.BAD)
                recommendations.append(
                    f"Add some space to {mount_point} mount point."
                )
            else:
                option.format_print(f"Mount point {mount_point} is using {space_perc} % total space", style=tuner.Print.INFO)

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
                    style=tuner.Print.BAD
                )
                recommendations.append(
                    f"Add some space to {mount_point} mount point."
                )
            else:
                option.format_print(
                    f"Mount point {mount_point} is using {inode_perc} % of max allowed inodes",
                    style=tuner.Print.INFO
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
    option.format_print(f"CMD: {cmd}", style=tuner.Print.DEBUG)

    result: str = tuple(
        info.strip()
        for info in util.get(command)
    )
    for info in result:
        option.format_print(f"{delimiter}{info}", style=tuner.Print.INFO)


def kernel_info(option: tuner.Option) -> typ.Sequence[typ.List[str], typ.List[str], typ.Dict]:
    """Recommendations for kernel

    :param tuner.Option option:
    :return typ.Sequence[typ.List[str], typ.List[str], typ.Dict]:
        list of recommendations and list of adjusted variables, and results
    """
    recommendations: typ.List[str] = []
    adjusted_vars: typ.List[str] = []
    results: typ.DefaultDict[typ.DefaultDict] = clct.defaultdict(clct.defaultdict(clct.defaultdict(dict)))

    params: typ.Sequence[str] = (
        u"fs.aio-max-nr",
        u"fs.aio-nr",
        u"fs.file-max",
        u"sunrpc.tcp_fin_timeout",
        u"sunrpc.tcp_max_slot_table_entries",
        u"sunrpc.tcp_slot_table_entries",
        u"vm.swappiness"
    )

    option.format_print(u"Information about kernel tuning:", style=tuner.Print.INFO)

    for param in params:
        sysctl_devnull_command: typ.Sequence[str] = (
            u"sysctl",
            param,
            u"2>/dev/null"
        )
        sysctl_n_devnull_command: typ.Sequence[str] = (
            u"sysctl",
            u"-n",
            param,
            u"2>/dev/null"
        )
        info_cmd(sysctl_devnull_command, option, delimiter=u"\t")
        results[u"OS"][u"Config"][param] = util.get(sysctl_n_devnull_command)

    sysctl_swap_command: typ.Sequence[str] = (
        u"sysctl",
        u"-n",
        u"vm.swappiness"
    )
    if int(util.get(sysctl_swap_command)) > 10:
        option.format_print(u"Swappiness is > 10, please consider having a value lower than 10", style=tuner.Print.BAD)
        recommendations.append(u"Setup swappiness  to be <= 10")
        adjusted_vars.append(u"vm.swappiness <= 10 (echo 0 > /proc/sys/vm/swappiness)")
    else:
        option.format_print(u"Swappiness is < 10.", style=tuner.Print.INFO)

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
            style=tuner.Print.BAD
        )
        recommendations.append(u"Setup Initial TCP slot entries > 100")
        adjusted_vars.append(
            u"sunrpc.tcp_slot_table_entries > 100 (echo 128 > /proc/sys/sunrpc/tcp_slot_table_entries)"
        )
    else:
        option.format_print(u"TCP slot entries is > 100.", style=tuner.Print.INFO)

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
        ), style=tuner.Print.BAD)
        recommendations.append(u"Setup max running number events greater than 1M")
        adjusted_vars.append(u"fs.aio-max-nr > 1M (echo 1048576 > /proc/sys/fs/aio-max-nr)")
    else:
        option.format_print(u"Max Number of AIO events is > 1M.", style=tuner.Print.INFO)

    return recommendations, adjusted_vars, results


def system_info(option: tuner.Option) -> typ.Dict:
    """Grabs system information

    :param tuner.Option option:
    :return:
    """
    os_release: str = platform.release()
    option.format_print(os_release, style=tuner.Print.INFO)

    virtual_machine: bool = is_virtual_machine()
    if virtual_machine:
        option.format_print(u"Machine Type\t\t\t\t\t: Virtual Machine", style=tuner.Print.INFO)
    else:
        option.format_print(u"Machine Type\t\t\t\t\t: Physical Machine", style=tuner.Print.INFO)

    is_connected: bool = req.get(u"http://ipecho.net/plain").status_code == 200
    if is_connected:
        option.format_print(u"Internet\t\t\t\t\t: Connected", style=tuner.Print.INFO)
    else:
        option.format_print(u"Internet\t\t\t\t\t: Disconnected", style=tuner.Print.BAD)

    cpu_count: int = psu.cpu_count()
    option.format_print(f"Number of Core CPU : {cpu_count}", style=tuner.Print.INFO)

    os_type: str = platform.system()
    option.format_print(f"Operating System Type : {os_type}", style=tuner.Print.INFO)

    kernel_release: str = platform.release()
    option.format_print(f"Kernel Release : {kernel_release}", style=tuner.Print.INFO)

    hostname: str = socket.gethostname()
    option.format_print(f"Hostname\t\t\t\t: {hostname}", style=tuner.Print.INFO)

    internal_ip: str = socket.gethostbyname(hostname)
    option.format_print(f"Internal IP\t\t\t\t: {internal_ip}", style=tuner.Print.INFO)

    option.format_print(u"Network Cards\t\t\t: ", style=tuner.Print.INFO)
    for network_card in psu.net_if_stats().keys():
        option.format_print(network_card)

    try:
        external_ip: str = req.get(u"http://ipecho.net/plain").text
        option.format_print(f"External IP\t\t\t\t: {external_ip}", style=tuner.Print.INFO)
    except req.exceptions.MissingSchema as err:
        option.format_print(f"External IP\t\t\t\t: Can't check because of Internet connectivity", style=tuner.Print.BAD)
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
    option.format_print(f"Name Servers\t\t\t\t: {name_servers}", style=tuner.Print.INFO)

    option.format_print(u"Logged in Users\t\t\t\t:", style=tuner.Print.INFO)
    logged_users: typ.Sequence[str] = [
        user.name
        for user in psu.users()
    ]
    for logged_user in logged_users:
        option.format_print(logged_user, style=tuner.Print.INFO)

    ram: str = util.bytes_to_string(psu.virtual_memory().free)
    option.format_print(f"Ram Usages in MB\t\t: {ram}", style=tuner.Print.INFO)

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
        option.format_print(u"Skipped due to non Linux Server", style=tuner.Print.INFO)
        return recommendations, adjusted_vars

    option.format_print(u"Look for related Linux system recommendations", style=tuner.Print.PRETTY)

    system_info(option)
    other_proc_mem: int = other_process_memory()

    option.format_print(f"User process except mysqld used {util.bytes_to_string(other_proc_mem)} RAM", style=tuner.Print.INFO)

    if 0.15 * physical_memory < other_proc_mem:
        option.format_print((
            u"Other user process except mysqld used more than 15% of total physical memory "
            f"{util.percentage(other_proc_mem, physical_memory)}% "
            f"({util.bytes_to_string(other_proc_mem)} / {util.bytes_to_string(physical_memory)})"
        ), style=tuner.Print.BAD)
        recommendations.append(u"Consider stopping or dedicate server for additional process other than mysqld")
        adjusted_vars.append(
            u"DON'T APPLY SETTINGS BECAUSE THERE ARE TOO MANY PROCESSES RUNNING ON THIS SERVER. OOM KILL CAN OCCUR!"
        )
    else:
        option.format_print((
            u"Other user process except mysqld used more than 15% of total physical memory "
            f"{util.percentage(other_proc_mem, physical_memory)}% "
            f"({util.bytes_to_string(other_proc_mem)} / {util.bytes_to_string(physical_memory)})"
        ), style=tuner.Print.INFO)

    if option.max_port_allowed > 0:
        open_ports: typ.Sequence[str] = opened_ports()
        option.format_print(f"There are {len(open_ports)} listening port(s) on this server", style=tuner.Print.INFO)

        if len(open_ports) > option.max_port_allowed:
            option.format_print((
                f"There are too many listening ports: "
                f"{len(open_ports)} opened > {option.max_port_allowed} allowed"
            ), style=tuner.Print.BAD)
            recommendations.append(
                u"Consider dedicating a server for your database installation with less services running on!"
            )
        else:
            option.format_print(
                f"There are less than {option.max_port_allowed} opened ports on this server",
                style=tuner.Print.INFO
            )

    for banned_port in banned_ports:
        if is_open_port(banned_port):
            option.format_print(f"Banned port: {banned_port} is opened.", style=tuner.Print.BAD)
            recommendations.append(f"Port {banned_port} is opened. Consider stopping program handling this port.")
        else:
            option.format_print(f"{banned_port} is not opened.", style=tuner.Print.GOOD)

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

    option.format_print(u"Security Recommendations", style=tuner.Print.SUBHEADER)
    if option.skip_password:
        option.format_print(u"Skipped due to --skip-password option", style=tuner.Print.INFO)
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

    option.format_print(f"{users}", style=tuner.Print.DEBUG)

    if users:
        for user in sorted(users):
            option.format_print(f"User '{user}' is an anonymous account.", style=tuner.Print.BAD)
        recommendations.append(
            f"Remove Anonymous User accounts - there are {len(users)} anonymous accounts."
        )
    else:
        option.format_print(u"There are no anonymous accounts for any database users", style=tuner.Print.GOOD)

    if (info.ver_major, info.ver_minor, info.ver_micro) <= (5, 1):
        option.format_print(u"No more password checks for MySQL <= 5.1", style=tuner.Print.BAD)
        option.format_print(u"MySQL version <= 5.1 are deprecated and are at end of support", style=tuner.Print.BAD)
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
            option.format_print(f"User '{user}' has no password set.", style=tuner.Print.BAD)
        recommendations.append((
            u"Set up a Password for user with the following SQL statement: "
            u"( SET PASSWORD FOR 'user'@'SpecificDNSorIp' = PASSWORD('secure_password'); )"
        ))
    else:
        option.format_print(u"All database users have passwords assigned", style=tuner.Print.GOOD)

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
                style=tuner.Print.INFO
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
            option.format_print(f"User '{user}' has user name as password", style=tuner.Print.BAD)
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
            option.format_print(f"User '{user}' does not have specific host restrictions.", style=tuner.Print.BAD)
        recommendations.append(u"Restrict Host for 'user'@'%' to 'user'@SpecificDNSorIP'")

    if os.path.isfile(option.basic_passwords_file):
        option.format_print(u"There is no basic password file list!", style=tuner.Print.BAD)
        return recommendations, adjusted_vars

    with open(option.basic_passwords_file, mode=u"r", encoding=u"utf-8") as bpf:
        passwords: typ.Sequence[str] = bpf.readlines()

    option.format_print(f"There are {len(passwords)} basic passwords in the list", style=tuner.Print.INFO)
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

            option.format_print(f"There are {len(capital_password_users)} items.", style=tuner.Print.DEBUG)
            if capital_password_users:
                for user in capital_password_users:
                    option.format_print((
                        f"User '{user}' is using weak password: "
                        f"{password} in a lower, upper, or capitalized derivative version."
                    ), style=tuner.Print.BAD)
                    bad_amount += 1
            if interpass_amount % 1000 == 0:
                option.format_print(f"{interpass_amount} / {len(passwords)}", style=tuner.Print.DEBUG)
    if bad_amount > 0:
        recommendations.append(
            f"{bad_amount} user(s) used a basic or weak password."
        )

    return recommendations, adjusted_vars


def replication_status(option: tuner.Option, info: tuner.Info) -> typ.Dict:
    """Replication status
    
    :param tuner.Option option: 
    :param tuner.Info info: 
    :return typ.Dict: results
    """
    results: typ.DefaultDict[typ.DefaultDict] = clct.defaultdict(clct.defaultdict(clct.defaultdict(dict)))

    option.format_print(u"Replication Metrics", style=tuner.Print.SUBHEADER)
    option.format_print(f"Galera Synchronous replication {info.have_galera}", style=tuner.Print.INFO)

    if not info.slaves:
        option.format_print(u"No replication slave(s) for this server", style=tuner.Print.INFO)
    else:
        option.format_print(f"This server is acting as master for {len(info.slaves)} servers", style=tuner.Print.INFO)

    if not info.replicas and not info.slaves:
        option.format_print(u"This is a standalone server", style=tuner.Print.INFO)
        return results

    if not info.replicas:
        option.format_print(u"No replication setup for this server", style=tuner.Print.INFO)
        return results

    results[u"Replication"][u"Status"] = info.replicas

    io_running: str = info.replicas[u"Slave_IO_Running"]
    option.format_print(f"IO RUNNING: {io_running}", style=tuner.Print.DEBUG)
    sql_running: str = info.replicas[u"Slave_SQL_Running"]
    option.format_print(f"SQL RUNNING: {sql_running}", style=tuner.Print.DEBUG)
    seconds_behind_master: int = info.replicas[u"Seconds_Behind_Master"]
    option.format_print(f"SECONDS: {seconds_behind_master}", style=tuner.Print.DEBUG)

    if u"yes" not in io_running.lower() or u"yes" not in sql_running.lower():
        option.format_print(u"This replication slave is not running but seems to be configured", style=tuner.Print.BAD)

    if u"yes" in io_running.lower() and u"yes" in sql_running.lower():
        if not info.read_only:
            option.format_print(u"This replication slave is running with the read_only option disabled", style=tuner.Print.BAD)
        else:
            option.format_print(u"This replication slave is running with the read_only option enabled.", style=tuner.Print.GOOD)

        if seconds_behind_master > 0:
            seconds_behind_msg: str = u" ".join((
                u"This replication slave is lagging and slave is",
                f"{seconds_behind_master} second(s) behind master host."
            ))
            option.format_print(seconds_behind_msg, style=tuner.Print.BAD)
        else:
            option.format_print(u"This replication slave is up to date with master", style=tuner.Print.GOOD)

    return results


def validate_mysql_version(option: tuner.Option, info: tuner.Info) -> None:
    """Check MySQL Version

    :param tuner.Option option: option object
    :param tuner.Info info: info object

    :return:
    """
    full_version: str = f"{info.ver_major}.{info.ver_minor}.{info.ver_micro}"

    if (info.ver_major, info.ver_major, info.ver_micro) < (5, 1):
        option.format_print(f"Your MySQL version {full_version} is EOL software! Upgrade soon!", style=tuner.Print.BAD)
    elif (6 <= info.ver_major <= 9) or info.ver_major >= 12:
        option.format_print(f"Currently running unsupported MySQL version {full_version}", style=tuner.Print.BAD)
    else:
        option.format_print(f"Currently running supported MySQL version {full_version}", style=tuner.Print.GOOD)


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
        option.format_print("Operating on 64-bit architecture", style=tuner.Print.GOOD)
    else:
        if physical_memory > 2 ** 31:
            option.format_print(u"Switch to 64-bit OS - MySQL cannot currently use all of your RAM", style=tuner.Print.BAD)
        else:
            option.format_print(u"Operating on a 32-bit architecture with less than 2GB RAM", style=tuner.Print.GOOD)

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
    engine_stats: typ.Dict[str, int] = {}
    engine_count: typ.Dict[str, int] = {}

    option.format_print(u"Storage Engine Statistics", style=tuner.Print.SUBHEADER)
    if option.skip_size:
        option.format_print(u"Skipped due to --skip-size option", style=tuner.Print.INFO)
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

    option.format_print(f"Status {engines}", style=tuner.Print.INFO)

    fragmented_table_count: int = 0

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
            option.format_print(f"Engine Found: {engine}", style=tuner.Print.DEBUG)
            if not engine:
                continue
            engine_stats[engine] = count
            results[u"Engine"][engine] = {
                u"# of Tables": count,
                u"Total Size": size,
                u"Data Size": data_size,
                u"Index Size": index_size
            }

        if not info.innodb_file_per_table:
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
        table_infos: typ.List[typ.List] = []
        for db in info.databases:
            # MySQL < 5 servers take a lot of work to get table sizes
            # MySQL 3.23/4.0 keeps Data_Length in the 5th (0-based) column, else 6th
            if (info.ver_major, info.ver_minor, info.ver_micro) < (4, 1):
                indexes: typ.Tuple[int, int, int] = (1, 6, 9)
            else:
                indexes: typ.Tuple[int, int, int] = (1, 5, 8)

            result = sess.execute(sqla.Text(f"SHOW TABLE STATUS FROM `{db}`"))
            for info in result.fetchall():
                table_infos.append([info.split()[index].strip() for index in indexes])

        # Parse through the table list to generate storage engine counts/statistics
        fragmented_table_count: int = 0
        for table_info in table_infos:
            option.format_print(f"Data Dump {table_info}", style=tuner.Print.DEBUG)
            engine, size, free_data = table_info
            size: int = int(size) if size != u"NULL" else 0
            free_data: int = int(free_data) if free_data != u"NULL" else 0

            if engine_stats[engine]:
                engine_stats[engine] += size
                engine_count[engine] += 1
            else:
                engine_stats[engine] = size
                engine_count[engine] = 1

            if free_data == 0:
                fragmented_table_count += 1

    for engine, size in engine_stats.items():
        option.format_print((
            f"Data in {engine} tables: {util.string_to_bytes(size)} "
            f"(Tables: {engine_count[engine]})"
        ), style=tuner.Print.INFO)

    # If the storage engine isn't being used, recommend it to be disabled
    if engine_stats[u"InnoDB"] and info.have_innodb:
        option.format_print(u"InnoDB is enabled but isn't being used", style=tuner.Print.BAD)
        recommendations.append(u"Add skip-innodb to MySQL configuration to disable InnoDB")

    if engine_stats[u"BerkeleyDB"] and info.have_bdb:
        option.format_print(u"BDB is enabled but isn't being used", style=tuner.Print.BAD)
        recommendations.append(u"Add skip-bdb to MySQL configuration to disable BDB")

    if engine_stats[u"ISAM"] and info.have_myisam:
        option.format_print(u"MyISAM is enabled but isn't being used", style=tuner.Print.BAD)
        recommendations.append(u"Add skip-isam to MySQL configuration to disable MyISAM (MySQL > 4.1.0)")

    # Fragmented tables
    if fragmented_table_count > 0:
        option.format_print(f"Total fragmented tables: {fragmented_table_count}", style=tuner.Print.BAD)
        recommendations.append(u"Run OPTIMIZE to defragment tables for better performance")

        free_total: int = 0
        for table_size in results[u"Tables"][u"Fragmented Tables"]:
            table, free_data = table_size
            free_data: int = 0 if not free_data else int(free_data) / 1024 ** 2
            free_total += free_data
            recommendations.append(f"OPTIMIZE TABLE {table}; -- Can Free {free_data} MB")
    else:
        option.format_print(f"Total fragmented tables: {fragmented_table_count}", style=tuner.Print.GOOD)

    # Find the maximum integer
    results[u"MaxInt"]: int = int(sess.execute(sqla.Text(u"SELECT ~0")).fetchall())
    max_int: int = results[u"MaxInt"]

    table_infos: typ.List[typ.List] = []
    for db in info.databases:
        # MySQL < 5 servers take a lot of work to get table sizes
        # MySQL 3.23/4.0 keeps Data_Length in the 5th (0-based) column, else 6th
        if (info.ver_major, info.ver_minor, info.ver_micro) < (4, 1):
            indexes: typ.Tuple[int, int] = (0, 10)
        else:
            indexes: typ.Tuple[int, int] = (0, 9)

        result = sess.execute(sqla.Text(f"SHOW TABLE STATUS FROM `{db}`"))
        for info in result.fetchall():
            table_infos.append([info.split()[index].strip() for index in indexes])

    for db in info.databases:
        for table_info in table_infos:
            table, auto_increment = table_info
            if info.database_tables[table]:
                try:
                    auto_increment: float = float(auto_increment.strip())
                    percent: float = util.percentage(auto_increment, max_int)
                    results[u"PctAutoIncrement"][f"`{db}`.`{table}"]: float = percent
                    if percent > 75:
                        option.format_print((
                            f"Table `{db}`.`{table}` has an autoincrement value near max capacity ({percent}%)"
                        ), style=tuner.Print.BAD)
                except ValueError:
                    pass

    return recommendations, adjusted_vars, results


def calculations(
    sess: orm.session.Session,
    option: tuner.Option,
    info: tuner.Info,
    stat: tuner.Stat,
    calc: tuner.Calc
) -> None:
    if stat.questions < 1:
        option.format_print(u"Your server has not answered any queries - cannot continue...", style=tuner.Print.BAD)
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

    option.format_print(f"Max Used Memory: {util.bytes_to_string(calc.max_used_memory)}", style=tuner.Print.DEBUG)
    option.format_print(f"Max Used Percentage RAM: {util.bytes_to_string(calc.pct_max_used_memory)}%", style=tuner.Print.DEBUG)
    option.format_print(f"Max Peak Memory: {util.bytes_to_string(calc.max_peak_memory)}", style=tuner.Print.DEBUG)
    option.format_print(
        f"Max Peak Percentage RAM: {util.bytes_to_string(calc.pct_max_physical_memory)}%",
        style=tuner.Print.DEBUG
    )

    # Slow Queries
    calc.pct_slow_queries = int(stat.slow_queries / stat.questions * 100)

    # Connections
    calc.pct_connections_used = int(stat.max_used_connections / info.max_connections)
    calc.pct_connections_used = min(calc.pct_connections_used, 100)

    # Aborted Connections
    calc.pct_connections_aborted = util.percentage(stat.aborted_connections, stat.connections)
    option.format_print(f"Aborted Connections: {stat.aborted_connections}", style=tuner.Print.DEBUG)
    option.format_print(f"Connections: {stat.connections}", style=tuner.Print.DEBUG)
    option.format_print(f"Percent of Connections Aborted {calc.pct_connections_aborted}", style=tuner.Print.DEBUG)

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
    option.format_print(f"pct_read_efficiency: {calc.pct_read_efficiency}", style=tuner.Print.DEBUG)
    option.format_print(f"innodb_buffer_pool_reads: {stat.innodb_buffer_pool_reads}", style=tuner.Print.DEBUG)
    option.format_print(f"innodb_buffer_pool_read_requests: {stat.innodb_buffer_pool_read_requests}", style=tuner.Print.DEBUG)

    # InnoDB log write cache efficiency
    calc.pct_write_efficiency = util.percentage(
        stat.innodb_log_write_requests - stat.innodb_log_writes
    )
    option.format_print(f"pct_write_efficiency: {calc.pct_write_efficiency}", style=tuner.Print.DEBUG)
    option.format_print(f"innodb_log_writes: {stat.innodb_log_writes}", style=tuner.Print.DEBUG)
    option.format_print(f"innodb_log_write_requests: {stat.innodb_log_write_requests}", style=tuner.Print.DEBUG)

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


def mysql_stats(
    option: tuner.Option,
    info: tuner.Info,
    stat: tuner.Stat,
    calc: tuner.Calc,
    physical_memory: int,
    arch: int
 ) -> typ.Sequence[typ.List[str], typ.List[str], typ.Dict]:
    """MySQL stats

    :param tuner.Option option:
    :param tuner.Info info:
    :param tuner.Stat stat:
    :param tuner.Calc calc:
    :param int physical_memory: amount of physical memory in bytes
    :param int arch: what bit the architecture is (32 / 64)
    :return typ.Sequence[typ.List[str], typ.List[str], typ.Dict]:
        list of recommendations and list of adjusted variables, and results
    """
    recommendations: typ.List[str] = []
    adjusted_vars: typ.List[str] = []
    results: typ.DefaultDict[typ.DefaultDict] = clct.defaultdict(clct.defaultdict(clct.defaultdict(dict)))

    option.format_print(u"Performance Metrics", style=tuner.Print.SUBHEADER)
    # Show uptime, queries per second, connections, traffic stats
    if stat.uptime > 0:
        qps: str = f"{round(stat.questions / stat.uptime, 3)}"

    if stat.uptime < 86400:
        recommendations.append(u"MySQL started within last 24 hours - recommendations may be inaccurate")

    option.format_print(u" ".join((
        f"Up for: {util.pretty_uptime(stat.uptime)}",
        f"({stat.questions} q [{qps} qps], {stat.connections} conn",
        f"TX: {util.bytes_to_string(stat.bytes_sent)}, RX: {util.bytes_to_string(stat.bytes_received)})"
    )), style=tuner.Print.INFO)

    option.format_print(f"Reads / Writes {calc.pct_reads}% / {calc.pct_writes}%", style=tuner.Print.INFO)

    # Binlog Cache
    if not info.log_bin:
        option.format_print(u"Binary logging is not enabled", style=tuner.Print.INFO)
    else:
        option.format_print(f"Binary logging is enabled (GTID MODE: {info.gtid_mode}", style=tuner.Print.INFO)

    # Memory Usage
    option.format_print(f"Physical Memory       : {util.bytes_to_string(stat.physical_memory)}", style=tuner.Print.INFO)
    option.format_print(f"Max MySQL Memory      : {util.bytes_to_string(calc.max_peak_memory)}", style=tuner.Print.INFO)
    option.format_print(f"Other Process Memory  : {util.bytes_to_string(other_process_memory())}", style=tuner.Print.INFO)

    option.format_print((
        f"Total Buffers: {util.bytes_to_string(calc.server_buffers)} global "
        f"+ {util.bytes_to_string(calc.per_thread_buffers)} per thread "
        f"({info.max_connections} max threads)"
    ), style=tuner.Print.INFO)

    option.format_print(f"P_S Max Memory Usage: {util.bytes_to_string(performance_memory(info, sess))}", style=tuner.Print.INFO)

    opm: int = other_process_memory()
    results[u"P_S"][u"Memory"]: int = opm
    results[u"P_S"][u"Pretty_Memory"]: str = util.bytes_to_string(opm)

    gcache_mem: int = gcache_memory(option, info)
    option.format_print(f"Galera GCache Max Memory Usage: {util.bytes_to_string(gcache_mem)}", style=tuner.Print.INFO)
    results[u"Galera"][u"GCache"][u"Memory"]: int = gcache_mem
    results[u"Galera"][u"GCache"][u"Pretty_Memory"]: str = util.bytes_to_string(gcache_mem)

    if option.buffers:
        option.format_print(u"Global Buffers", style=tuner.Print.INFO)
        option.format_print(f" +-- Key Buffer: {util.bytes_to_string(info.key_buffer_size)}", style=tuner.Print.INFO)
        option.format_print(f" +-- Max Temp Table Size: {util.bytes_to_string(calc.max_temp_table_size)}", style=tuner.Print.INFO)

        if info.query_cache_type:
            option.format_print(u"Query Cache Buffers", style=tuner.Print.INFO)
            option.format_print(f" +-- Query Cache: {info.query_cache_type}", style=tuner.Print.INFO)
            option.format_print(f" +-- Query Cache: {util.bytes_to_string(info.query_cache_size)}", style=tuner.Print.INFO)

        option.format_print(u"Per Thread Buffers", style=tuner.Print.INFO)
        option.format_print(f" +-- Read Buffer: {util.bytes_to_string(info.read_buffer_size)}", style=tuner.Print.INFO)
        option.format_print(f" +-- Read RND Buffer: {util.bytes_to_string(info.read_rnd_buffer_size)}", style=tuner.Print.INFO)
        option.format_print(f" +-- Sort Buffer: {util.bytes_to_string(info.sort_buffer_size)}", style=tuner.Print.INFO)
        option.format_print(f" +-- Join Buffer: {util.bytes_to_string(info.join_buffer_size)}", style=tuner.Print.INFO)
        if info.log_bin:
            option.format_print(u"Binlog Cache Buffers", style=tuner.Print.INFO)
            option.format_print(f" +-- Binlog Cache: {util.bytes_to_string(info.binlog_cache_size)}", style=tuner.Print.INFO)

    if arch == 32 and calc.max_used_memory > 2 * 1024 ** 3:
        option.format_print(u"Allocation > 2 GB RAM on 32-bit systems can cause system instability", style=tuner.Print.BAD)
        option.format_print(f"Maximum reached Memory Usage {calc.max_used_memory} ({calc.pct_max_used_memory})% of installed RAM", style=tuner.Print.BAD)
    elif calc.pct_max_used_memory > 85:
        option.format_print(f"Maximum reached Memory Usage {calc.max_used_memory} ({calc.pct_max_used_memory})% of installed RAM", style=tuner.Print.BAD)
    else:
        option.format_print(f"Maximum reached Memory Usage {calc.max_used_memory} ({calc.pct_max_used_memory})% of installed RAM", style=tuner.Print.GOOD)

    if calc.pct_max_physical_memory > 85:
        option.format_print(f"Maximum possible Memory Usage {calc.max_peak_memory} ({calc.pct_max_physical_memory})% of installed RAM", style=tuner.Print.BAD)
        recommendations.append(u"Reduce your overall MySQL memory footprint for system stability")
    else:
        option.format_print(f"Maximum possible Memory Usage {calc.max_peak_memory} ({calc.pct_max_physical_memory})% of installed RAM", style=tuner.Print.GOOD)

    if physical_memory < calc.max_peak_memory * opm:
        option.format_print(u"Overall possible memory usage with other process exceeded memory", style=tuner.Print.BAD)
        recommendations.append(u"Dedicate this server to your database for highest performance")
    else:
        option.format_print(u"Overall possible memory usage with other process is compatible with memory available", style=tuner.Print.GOOD)

    # Slow Queries
    if calc.pct_slow_queries > 5:
        option.format_print(f"Slow queries: {calc.pct_slow_queries}% ({stat.slow_queries} / {stat.questions})", style=tuner.Print.BAD)
    else:
        option.format_print(f"Slow queries: {calc.pct_slow_queries}% ({stat.slow_queries} / {stat.questions})", style=tuner.Print.GOOD)

    if info.long_query_time > 10:
        adjusted_vars.append(u"long_query_time (<= 10)")
    if not info.log_slow_queries:
        recommendations.append(u"Enable the slow query log to troubleshoot bad queries")

    # Connections
    if calc.pct_connections_used > 85:
        option.format_print(f"Highest connection usage: {calc.pct_connections_used}% ({stat.max_used_connections} / {info.max_connections}", style=tuner.Print.BAD)
        adjusted_vars.extend((
            f"max_connections (> {info.max_connections})",
            f"wait_timeout (< {info.wait_timeout})",
            f"interactive_timeout (< {info.interactive_timeout})"
        ))
    else:
        option.format_print(f"Highest connection usage: {calc.pct_connections_used}% ({stat.max_used_connections} / {info.max_connections}", style=tuner.Print.GOOD)

    # Aborted Connections
    if calc.pct_connections_aborted > 3:
        option.format_print(f"Aborted Connections: {calc.pct_connections_aborted}% ({stat.aborted_connections} / {stat.connections}", style=tuner.Print.BAD)
        recommendations.append(u"Reduce or eliminate unclosed connections and network issues")
    else:
        option.format_print(f"Aborted Connections: {calc.pct_connections_aborted}% ({stat.aborted_connections} / {stat.connections}", style=tuner.Print.GOOD)

    # Name Resolution
    if results[u"Variables"][u"skip_networking"] == u"ON":
        option.format_print(u"Skipped name resolution test due to skip_networking = ON in system variables", style=tuner.Print.INFO)
    elif not results[u"Variables"][u"skip_name_resolve"]:
        option.format_print(u"Skipped name resolution test due to missing skip_name_resolve in system variables", style=tuner.Print.INFO)
    elif results[u"Variables"][u"skip_name_resolve"] == u"OFF":
        option.format_print(u"Name resolution is active: A reverse name resolution is named for each new connection and can reduce performace", style=tuner.Print.BAD)
        recommendations.append(u"Configure your accounts with IP or subnets only, then update your configuration with skip-name-resolve=1")

    # Query Cache
    if (info.ver_major, info.ver_minor, info.ver_micro) <= (4,):
        # MySQL versions < 4.01 don't support query caching
        recommendations.append(u"Upgrade MySQL to version 4.01+ to utilize query caching")
    elif (5, 5) <= (info.ver_major, info.ver_minor, info.ver_micro) < (10, 1) and info.query_cache_type == u"OFF":
        option.format_print(u"Query cache is disabled by default due to mutex contention on multiprocessor machines.", style=tuner.Print.GOOD)
    elif info.query_cache_size < 1:
        option.format_print(u"Query cache is disabled", style=tuner.Print.BAD)
        adjusted_vars.append(u"query_cache_size (>= 8M)")
    elif info.query_cache_type == u"OFF":
        option.format_print(u"Query cache is disabled", style=tuner.Print.BAD)
        adjusted_vars.append(u"query_cache_type (= 1)")
    elif stat.com_select == 0:
        option.format_print(u"Query cache cannot be analyzed - no SELECT statements executed.", style=tuner.Print.BAD)
    else:
        option.format_print(u"Query cache may be disabled by default due to mutex contention.", style=tuner.Print.BAD)
        adjusted_vars.append(u"query_cache_type (= 0)")

        if calc.query_cache_efficiency < 20:
            option.format_print(f"Query Cache efficiency: {calc.query_cache_efficiency}% ({stat.query_cache_hits} cached / {stat.query_cache_hits + stat.com_select} selects)", style=tuner.Print.BAD)
            adjusted_vars.append(f"query_cache_limit (> {info.query_cache_limit}, or use smaller result sets)")
        else:
            option.format_print(f"Query Cache efficiency: {calc.query_cache_efficiency}% ({stat.query_cache_hits} cached / {stat.query_cache_hits + stat.com_select} selects)", style=tuner.Print.GOOD)

        if calc.query_cache_prunes_per_day > 98:
            option.format_print(f"Query Cache prunes per day: {calc.query_cache_prunes_per_day}", style=tuner.Print.BAD)
            if info.query_cache_size > 128 * 1024 ** 2:
                recommendations.append(u"Increasing the query_cache_size over 128MB may reduce performance")
                adjusted_vars.append(f"query_cache_size (> {util.bytes_to_string(info.query_cache_size)}) [See Warning Above]")
            else:
                adjusted_vars.append(f"query_cache_size (> {util.bytes_to_string(info.query_cache_size)})")
        else:
            option.format_print(f"Query Cache prunes per day: {calc.query_cache_prunes_per_day}", style=tuner.Print.GOOD)

    # Sorting
    if calc.total_sorts == 0:
        option.format_print(u"No sort requiring temporary tables", style=tuner.Print.GOOD)
    elif calc.pct_temp_sort_table > 10:
        option.format_print(f"Sorts requiring temporary tables: {calc.pct_temp_sort_table}% ({stat.sort_merge_passes} temp sorts / {calc.total_sorts} sorts)", style=tuner.Print.BAD)
        adjusted_vars.extend((
            f"sort_buffer_size (> {util.bytes_to_string(info.sort_buffer_size)})"
            f"read_rnd_buffer_size (> {util.bytes_to_string(info.read_rnd_buffer_size)})"
        ))
    else:
        option.format_print(f"Sorts requiring temporary tables: {calc.pct_temp_sort_table}% ({stat.sort_merge_passes} temp sorts / {calc.total_sorts} sorts)", style=tuner.Print.GOOD)

    # Joins
    if calc.joins_without_indexes_per_day > 250:
        option.format_print(f"Joins performed without indexes: {calc.joins_without_indexes}", style=tuner.Print.BAD)
        adjusted_vars.append(f"join_buffer_size (> {util.bytes_to_string(info.join_buffer_size)}, or always use indexes with joins)")
        recommendations.append(u"Adjust your join queries to always utilize indexes")
    else:
        option.format_print(u"No joins without indexes", style=tuner.Print.GOOD)

    # Temporary tables
    if stat.created_temp_tables > 0:
        if calc.pct_temp_disk > 25 and calc.max_temp_table_size < 256 * 1024 ** 2:
            option.format_print(f"Temporary tables created on disk {calc.pct_temp_disk}% ({stat.created_temp_disk_tables} on disk / {stat.created_temp_tables} total", style=tuner.Print.BAD)
            adjusted_vars.extend((
                f"tmp_table_size (> {util.bytes_to_string(info.temp_table_size)})",
                f"max_heap_table_size (> {util.bytes_to_string(info.max_heap_table_size)})"
            ))
            recommendations.extend((
                u"When making adjustments, make tmp_table_size / max_heap_table_size equal",
                u"Reduce your SELECT DISTINCT queries without LIMIT clauses"
            ))
        elif calc.pct_temp_disk > 25 and calc.max_temp_table_size >= 256 * 1024 ** 2:
            option.format_print(f"Temporary tables created on disk {calc.pct_temp_disk}% ({stat.created_temp_disk_tables} on disk / {stat.created_temp_tables} total", style=tuner.Print.BAD)
            recommendations.extend((
                u"Temporary table size is already large - reduce result set size",
                u"Reduce your SELECT DISTINCT queries without LIMIT clauses"
            ))
        else:
            option.format_print(f"Temporary tables created on disk {calc.pct_temp_disk}% ({stat.created_temp_disk_tables} on disk / {stat.created_temp_tables} total", style=tuner.Print.GOOD)
    else:
        option.format_print(u"No temp tables created on disk", style=tuner.Print.GOOD)

    # Thread Cache
    if info.thread_cache_size == 0:
        option.format_print(u"Thread Cache is disabled", style=tuner.Print.BAD)
        recommendations.append(u"Set thread_cache_size to 4 as a starting value")
        adjusted_vars.append(u"thread_cache_size (start at 4)")
    else:
        if info.thread_handling == u"pools-of-threads":
            option.format_print(u"Thread cache hit rate: not used with pools-of-threads", style=tuner.Print.INFO)
        else:
            if calc.thread_cache_hit_rate <= 50:
                option.format_print(f"Thread Cache hit rate: {calc.thread_cache_hit_rate}% ({stat.created_threads} created / {stat.connections} connections)", style=tuner.Print.BAD)
                adjusted_vars.append(f"thread_cache_size (> {info.thread_cache_size})")
            else:
                option.format_print(f"Thread Cache hit rate: {calc.thread_cache_hit_rate}% ({stat.created_threads} created / {stat.connections} connections)", style=tuner.Print.GOOD)

    # Table Cache
    if stat.open_tables > 0:
        if calc.table_cache_hit_rate < 20:
            option.format_print(f"Table Cache hit rate: {calc.table_cache_hit_rate}% ({stat.open_tables} open / {stat.opened_tables} opened)", style=tuner.Print.BAD)
            if (info.ver_major, info.ver_minor, info.ver_micro) >= (5, 1):
                table_cache: str = u"table_open_cache"
            else:
                table_cache: str = u"table_cache"

            adjusted_vars.append(f"{table_cache} (> {getattr(info, table_cache)})")
            recommendations.extend((
                f"Increase {table_cache} gradually to avoid file descriptor limits",
                f"Read this before increasing {table_cache} over 64 http://bit.ly/1mi7c4C",
                f"Beware that open_files_limit ({info.open_files_limit}) variable should be greater than {table_cache} ({getattr(info, table_cache)})"
            ))
        else:
            option.format_print(f"Table Cache hit rate: {calc.table_cache_hit_rate}% ({stat.open_tables} open / {stat.opened_tables} opened)", style=tuner.Print.GOOD)

    # Open Files
    if calc.pct_files_open > 85:
        option.format_print(f"Open file limit used {calc.pct_files_open}% ({stat.open_files} / {info.open_files_limit})", style=tuner.Print.BAD)
        adjusted_vars.append(f"open_files_limit (> {info.open_files_limit})")
    else:
        option.format_print(f"Open file limit used {calc.pct_files_open}% ({stat.open_files} / {info.open_files_limit})", style=tuner.Print.GOOD)

    # Table Locks
    if calc.pct_immediate_table_locks < 95:
        option.format_print(f"Table locks acquired immediately: {calc.pct_immediate_table_locks}% ({stat.immediate_table_locks} immediate / {stat.waited_table_locks} locks", style=tuner.Print.BAD)
        recommendations.append(u"Optimize queries and/or use InnoDB to reduce lock wait")
    else:
        option.format_print(f"Table locks acquired immediately: {calc.pct_immediate_table_locks}% ({stat.immediate_table_locks} immediate / {stat.waited_table_locks} locks", style=tuner.Print.GOOD)

    # Binlog Cache
    if calc.pct_binlog_cache < 90 and stat.binlog_cache_use > 0:
        option.format_print(f"Binlog Cache Memory Access: {calc.pct_binlog_cache}% ({stat.binlog_cache_use - stat.binlog_cache_disk_use} memory / {stat.binlog_cache_use} total", style=tuner.Print.BAD)
        recommendations.append(f"Increase binlog_cache_size (Actual value: {info.binlog_cache_size})")
        adjusted_vars.append(f"binlog_cache_size ({util.bytes_to_string(info.binlog_cache_size + 16 * 1024 ** 2)})")
    else:
        option.format_print(f"Binlog Cache Memory Access: {calc.pct_binlog_cache}% ({stat.binlog_cache_use - stat.binlog_cache_disk_use} memory / {stat.binlog_cache_use} total", style=tuner.Print.GOOD)

    # Performance Options
    if (info.ver_major, info.ver_minor, info.ver_micro) < (5, 1):
        recommendations.append(u"Upgrade to MySQL 5.5+ to use asynchronous write")
    elif info.concurrent_insert:
        recommendations.append(u"Enable concurrent_insert by setting it to 1")

    return recommendations, adjusted_vars, results


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
    :param tuner.Calc calc:
    :return typ.Sequence[typ.List[str], typ.List[str]]: list of recommendations and list of adjusted variables
    """
    recommendations: typ.List[str] = []
    adjusted_vars: typ.List[str] = []

    option.format_print(u"MyISAM Metrics", style=tuner.Print.SUBHEADER)

    # Key Buffer usage
    key_buffer_used_msg: str = (
        f"Key Buffer used: {calc.pct_key_buffer_used}% "
        f"({util.bytes_to_string(int(info.key_buffer_size * calc.pct_key_buffer_used / 100))} "
        f"used / {util.bytes_to_string(info.key_buffer_size)} cache)"
    )

    if calc.pct_key_buffer_used == 90:
        option.format_print(key_buffer_used_msg, style=tuner.Print.DEBUG)
    elif calc.pct_key_buffer_used < 90:
        option.format_print(key_buffer_used_msg, style=tuner.Print.BAD)
    else:
        option.format_print(key_buffer_used_msg, style=tuner.Print.GOOD)

    # Key Buffer
    if calc.total_myisam_indexes == 0 and option.do_remote:
        recommendations.append(u"Unable to calculate MyISAM indexes on remote MySQL server < 5.0.0")
    elif calc.total_myisam_indexes == 0:
        option.format_print(u"None of your MyISAM tables are indexed - add indexes immediately", style=tuner.Print.BAD)
    else:
        key_buffer_size_msg: str = (
            f"Key Buffer Size / Total MyISAM indexes: "
            f"{util.bytes_to_string(info.key_buffer_size)} / "
            f"{util.bytes_to_string(calc.total_myisam_indexes)}"
        )
        if info.key_buffer_size < calc.total_myisam_indexes and calc.pct_keys_from_memory < 95:
            option.format_print(key_buffer_size_msg, style=tuner.Print.BAD)
            adjusted_vars.append(f"key_buffer_size (> {util.bytes_to_string(calc.total_myisam_indexes)})")
        else:
            option.format_print(key_buffer_size_msg, style=tuner.Print.GOOD)

        read_key_buffer_msg: str = (
            f"Read Key Buffer Hit Rate: {calc.pct_keys_from_memory}% "
            f"({util.bytes_to_string(stat.key_read_requests)} cached / "
            f"{util.bytes_to_string(stat.key_reads)} reads)"
        )
        if stat.key_read_requests > 0:
            if calc.pct_keys_from_memory < 95:
                option.format_print(read_key_buffer_msg, style=tuner.Print.BAD)
            else:
                option.format_print(read_key_buffer_msg, style=tuner.Print.GOOD)
        else:
            # No Queries have run that would use keys
            option.format_print(read_key_buffer_msg, style=tuner.Print.DEBUG)

        write_key_buffer_msg: str = (
            f"Write Key Buffer Hit Rate: {calc.pct_write_keys_from_memory}% "
            f"({util.bytes_to_string(stat.key_write_requests)} cached / "
            f"{util.bytes_to_string(stat.key_writes)} writes)"
        )
        if stat.key_write_requests > 0:
            if calc.pct_write_keys_from_memory < 95:
                option.format_print(write_key_buffer_msg, style=tuner.Print.BAD)
            else:
                option.format_print(write_key_buffer_msg, style=tuner.Print.GOOD)
        else:
            # No Queries have run that would use keys
            option.format_print(write_key_buffer_msg, style=tuner.Print.DEBUG)

    return recommendations, adjusted_vars


def mariadb_threadpool(option: tuner.Option, info: tuner.Info) -> typ.Sequence[typ.List[str], typ.List[str]]:
    """Recommendations for ThreadPool

    :param tuner.Option option:
    :param tuner.Info info:
    :return typ.Sequence[typ.List[str], typ.List[str]]: list of recommendations and list of adjusted variables
    """
    recommendations: typ.List[str] = []
    adjusted_vars: typ.List[str] = []

    option.format_print(u"ThreadPool Metrics", style=tuner.Print.SUBHEADER)

    # AriaDB
    if not info.have_threadpool:
        option.format_print(u"ThreadPool stat is disabled.", style=tuner.Print.INFO)
        return recommendations, adjusted_vars

    option.format_print(u"ThreadPool stat is enabled.", style=tuner.Print.INFO)
    option.format_print(f"Thread Pool size: {info.thread_pool_size} thread(s)", style=tuner.Print.INFO)

    versions: typ.Sequence[str] = (
        u"mariadb",
        u"percona"
    )
    if any(version in info.version.lower() for version in versions):
        option.format_print(f"Using default value is good enough for your version ({info.version})", style=tuner.Print.INFO)
        return recommendations, adjusted_vars

    if info.have_innodb:
        if info.thread_pool_size < 16 or info.thread_pool_size > 36:
            option.format_print(u"thread_pool_size between 16 and 36 when using InnoDB storage engine.", style=tuner.Print.BAD)
            recommendations.append(
                f"Thread Pool size for InnoDB usage ({info.thread_pool_size})"
            )
            adjusted_vars.append(
                u"thread_pool_size between 16 and 36 for InnoDB usage"
            )
        else:
            option.format_print(u"thread_pool_size between 16 and 36 when using InnoDB storage engine", style=tuner.Print.GOOD)

    if info.have_myisam:
        if info.thread_pool_size < 4 or info.thread_pool_size > 8:
            option.format_print(u"thread_pool_size between 4 and 8 when using MyISAM storage engine.", style=tuner.Print.BAD)
            recommendations.append(
                f"Thread Pool size for MyISAM usage ({info.thread_pool_size})"
            )
            adjusted_vars.append(
                u"thread_pool_size between 4 and 8 for MyISAM usage"
            )
        else:
            option.format_print(u"thread_pool_size between 4 and 8 when using MyISAM storage engine", style=tuner.Print.GOOD)

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


def performance_check(
    sess: orm.session.Session,
    option: tuner.Option,
    info: tuner.Info,
    subheader: str,
    query_file: str
) -> None:
    """Checks specific part of performance and prints information
    
    :param orm.session.Session sess: 
    :param tuner.Option option: 
    :param tuner.Info info:
    :param str subheader: subheader message
    :param str query_file: name of file containing query
    """
    option.format_print(subheader, style=tuner.Print.SUBHEADER)
    query: str = osp.join(info.query_dir, query_file)
    line_num: int = 0
    result = sess.execute(sqla.Text(query))
    for query_line in result.fetchall():
        option.format_print(f" +-- {line_num}: {query_line}")
        line_num += 1

    if line_num == 1:
        option.format_print(u"No information found, or indicators deactivated.", style=tuner.Print.INFO)


def mysql_pfs(
    sess: orm.session.Session,
    option: tuner.Option,
    info: tuner.Info,
    stat: tuner.Stat,
    calc: tuner.Calc
) -> typ.Sequence[typ.List[str], typ.List[str], typ.Dict]:
    """Recommendations for performance schema

    :param orm.session.Session sess:
    :param tuner.Option option:
    :param tuner.Info info:
    :param tuner.Stat stat:
    :param tuner.Calc calc:
    :return typ.Sequence[typ.List[str], typ.List[str], typ.Dict]:
        list of recommendations and list of adjusted variables, and results
    """
    recommendations: typ.List[str] = []
    adjusted_vars: typ.List[str] = []
    results: typ.DefaultDict[typ.DefaultDict] = clct.defaultdict(clct.defaultdict(clct.defaultdict(dict)))

    option.format_print(u"Performance Schema", style=tuner.Print.SUBHEADER)

    # Performance Schema
    if not info.performance_schema:
        option.format_print(u"Performance Schema is disabled", style=tuner.Print.INFO)
        if (info.ver_major, info.ver_minor, info.ver_micro) >= (5, 6):
            recommendations.append(u"Performance schema should be activated for better diagnostics")
            adjusted_vars.append(u"performance_schema = ON enable PFS")
        else:
            recommendations.append(u"Performance schema shouldn't be activated for MySQL and MariaDB 5.5 and lower versions")
            adjusted_vars.append(u"performance_schema = OFF disable PFS")

    option.format_print(f"Performance schema is {'ON' if info.performance_schema else 'OFF'}", style=tuner.Print.DEBUG)
    option.format_print(f"Memory used by performance_schema: {util.bytes_to_string(performance_memory(info, sess))}", style=tuner.Print.INFO)

    if u"sys" not in info.databases:
        option.format_print(u"Sys schema is not installed.", style=tuner.Print.INFO)
        recommendations.append(u"Consider installing sys schema from https://github.com/mysql/mysql-sys")
        return recommendations, adjusted_vars, results
    else:
        option.format_print(u"Sys schema is installed.", style=tuner.Print.INFO)

    if not option.pf_stat or not info.performance_schema:
        return recommendations, adjusted_vars, results

    result = sess.execute(sqla.Text(u"SELECT `ver`.`sys_version` AS `SYS_VERSION` FROM `sys`.`version` AS `ver`;"))
    sys_version: str = list(result.fetchall())[0].SYS_VERSION

    option.format_print(f"Sys Schema Version: {sys_version}", style=tuner.Print.INFO)

    # TODO create and fill in query files

    # Top Users per connection
    performance_check(sess, option, info, u"Performance schema: Top 5 users per connection", query_file)

    # Top Users per statement
    performance_check(sess, option, info, u"Performance schema: Top 5 users per statement", query_file)

    # Top Users per statement latency
    performance_check(sess, option, info, u"Performance schema: Top 5 users per statement latency", query_file)

    # Top Users per lock latency
    performance_check(sess, option, info, u"Performance schema: Top 5 users per per lock latency", query_file)

    # Top Users per full scans
    performance_check(sess, option, info, u"Performance schema: Top 5 users per full scan", query_file)

    # Top Users per rows sent
    performance_check(sess, option, info, u"Performance schema: Top 5 users per rows sent", query_file)

    # Top Users per rows modified
    performance_check(sess, option, info, u"Performance schema: Top 5 users per rows modified", query_file)

    # Top Users per io
    performance_check(sess, option, info, u"Performance schema: Top 5 users per io", query_file)

    # Top Users per io latency
    performance_check(sess, option, info, u"Performance schema: Top 5 users per io latency", query_file)

    # Top Hosts per connection
    performance_check(sess, option, info, u"Performance schema: Top 5 hosts per connection", query_file)

    # Top Hosts per statement
    performance_check(sess, option, info, u"Performance schema: Top 5 hosts per statement", query_file)

    # Top Hosts per statement latency
    performance_check(sess, option, info, u"Performance schema: Top 5 hosts per statement latency", query_file)

    # Top Hosts per lock latency
    performance_check(sess, option, info, u"Performance schema: Top 5 hosts per lock latency", query_file)

    # Top Hosts per full scans
    performance_check(sess, option, info, u"Performance schema: Top 5 hosts per full scans", query_file)

    # Top Hosts per rows sent
    performance_check(sess, option, info, u"Performance schema: Top 5 hosts per rows sent", query_file)

    # Top Hosts per rows modified
    performance_check(sess, option, info, u"Performance schema: Top 5 hosts per rows modified", query_file)

    # Top Hosts per io
    performance_check(sess, option, info, u"Performance schema: Top 5 hosts per io", query_file)

    # Top Hosts per io latency
    performance_check(sess, option, info, u"Performance schema: Top 5 hosts per io latency", query_file)

    # Top IO Type order by total io
    performance_check(sess, option, info, u"Performance schema: Top IO Type order by total io", query_file)

    # Top IO Type order by total latency
    performance_check(sess, option, info, u"Performance schema: Top IO Type order by total latency", query_file)

    # Top IO Type order by max latency
    performance_check(sess, option, info, u"Performance schema: Top IO Type order by max latency", query_file)

    # Top Stages order by total io
    performance_check(sess, option, info, u"Performance schema: Top Stages order by total io", query_file)

    # Top Stages order by total latency
    performance_check(sess, option, info, u"Performance schema: Top Stages order by total latency", query_file)

    # Top Stages order by avg latency
    performance_check(sess, option, info, u"Performance schema: Top Stages order by avg latency", query_file)

    # Top Hosts per per table scans
    performance_check(sess, option, info, u"Performance schema: Top 5 hosts per table scans", query_file)

    # InnoDB Buffer Pool by Schema
    performance_check(sess, option, info, u"Performance schema: InnoDB Buffer Pool by Schema", query_file)

    # InnoDB Buffer Pool by Table
    performance_check(sess, option, info, u"Performance schema: InnoDB Buffer Pool by Table", query_file)

    # Process per allocated memory
    performance_check(sess, option, info, u"Performance schema: Process per allocated memory", query_file)

    # InnoDB Lock Waits
    performance_check(sess, option, info, u"Performance schema: InnoDB Lock Waits", query_file)

    # Threads IO Latency
    performance_check(sess, option, info, u"Performance schema: Threads IO Latency", query_file)

    # High Cost SQL statements
    performance_check(sess, option, info, u"Performance schema: High Cost SQL statements", query_file)

    # Top 5% slower queries
    performance_check(sess, option, info, u"Performance schema: Top 5% slower queries", query_file)

    # Top 10 Statement type
    performance_check(sess, option, info, u"Performance schema: Top 10 Statement type", query_file)

    # Top 10 Statements by total latency
    performance_check(sess, option, info, u"Performance schema: Top 10 Statements by total latency", query_file)

    # Top 10 Statements by lock latency
    performance_check(sess, option, info, u"Performance schema: Top 10 Statements by lock latency", query_file)

    # Top 10 Statements by full scans
    performance_check(sess, option, info, u"Performance schema: Top 10 Statements by full scans", query_file)

    # Top 10 Statements by rows sent
    performance_check(sess, option, info, u"Performance schema: Top 10 Statements by rows sent", query_file)

    # Top 10 Statements by rows modified
    performance_check(sess, option, info, u"Performance schema: Top 10 Statements by rows modified", query_file)

    # Use Temporary tables
    performance_check(sess, option, info, u"Performance schema: Some queries using temporary tables", query_file)

    # Unused Indexes
    performance_check(sess, option, info, u"Performance schema: Unused Indexes", query_file)

    # Full table scans
    performance_check(sess, option, info, u"Performance schema: Tables with full table scans", query_file)

    # Latest 10 files IO by latency
    performance_check(sess, option, info, u"Performance schema: Latest 10 files IO by latency", query_file)

    # Top 15 Files by IO read bytes
    performance_check(sess, option, info, u"Performance schema: Top 15 Files by IO read bytes", query_file)

    # Top 15 Files by IO written bytes
    performance_check(sess, option, info, u"Performance schema: Top 15 Files by IO written bytes", query_file)

    # Top 20 Files per IO total latency
    performance_check(sess, option, info, u"Performance schema: Top 20 Files per IO total latency", query_file)

    # Top 20 Files per IO read latency
    performance_check(sess, option, info, u"Performance schema: Top 20 Files per IO read latency", query_file)

    # Top 20 Files per IO write latency
    performance_check(sess, option, info, u"Performance schema: Top 20 Files per IO write latency", query_file)

    # Top 15 Event Wait by read bytes
    performance_check(sess, option, info, u"Performance schema: Top 15 Event Wait by read bytes", query_file)

    # Top 15 Event Wait by write bytes
    performance_check(sess, option, info, u"Performance schema: Top 15 Event Wait by write bytes", query_file)

    # Top 20 Events per wait total latency
    performance_check(sess, option, info, u"Performance schema: Top 20 Events per wait total latency", query_file)

    # Top 20 Events per wait read latency
    performance_check(sess, option, info, u"Performance schema: Top 20 Events per wait read latency", query_file)

    # Top 20 Events per wait write latency
    performance_check(sess, option, info, u"Performance schema: Top 20 Events per wait write latency", query_file)

    # schema_index_statistics
    # Top 15 most read indexes
    performance_check(sess, option, info, u"Performance schema: Top 15 most read indexes", query_file)

    # Top 15 most modified indexes
    performance_check(sess, option, info, u"Performance schema: Top 15 most modified indexes", query_file)

    # Top 15 high read latency indexes
    performance_check(sess, option, info, u"Performance schema: Top 15 high read latency indexes", query_file)

    # Top 15 high insert latency indexes
    performance_check(sess, option, info, u"Performance schema: Top 15 high insert latency indexex", query_file)

    # Top 15 high update latency indexes
    performance_check(sess, option, info, u"Performance schema: Top 15 high update latency indexes", query_file)

    # Top 15 high delete latency indexes
    performance_check(sess, option, info, u"Performance schema: Top 15 high delete latency indexes", query_file)

    # Top 15 most read tables
    performance_check(sess, option, info, u"Performance schema: Top 15 most read tables", query_file)

    # Top 15 most modified tables
    performance_check(sess, option, info, u"Performance schema: Top 15 most modified tables", query_file)

    # Top 15 high read latency tables
    performance_check(sess, option, info, u"Performance schema: Top 15 high read latency tables", query_file)

    # Top 15 high insert latency tables
    performance_check(sess, option, info, u"Performance schema: Top 15 high insert latency tables", query_file)

    # Top 15 high update latency tables
    performance_check(sess, option, info, u"Performance schema: Top 15 high update latency tables", query_file)

    # Top 15 high delete latency tables
    performance_check(sess, option, info, u"Performance schema: Top 15 high delete latency tables", query_file)

    # Redundant indexes
    performance_check(sess, option, info, u"Performance schema: Redundant indexes", query_file)

    # Tables not using InnoDB buffer
    performance_check(sess, option, info, u"Performance schema: Tables not using InnoDB buffer", query_file)

    # Top 15 Tables using InnoDB buffer
    performance_check(sess, option, info, u"Performance schema: Top 15 Tables using InnoDB buffer", query_file)

    # Top 15 Tables with InnoDB buffer free
    performance_check(sess, option, info, u"Performance schema: Top 15 Tables with InnoDB buffer free", query_file)

    # Top 15 Most executed queries
    performance_check(sess, option, info, u"Performance schema: Top 15 Most executed queries", query_file)

    # Latest 100 SQL queries in errors or warnings
    performance_check(sess, option, info, u"Performance schema: Latest 100 SQL queries in errors or warnings", query_file)

    # Top 20 queries with full table scans
    performance_check(sess, option, info, u"Performance schema: Top 20 queries with full table scans", query_file)
    # Last 50 queries with full table scans
    performance_check(sess, option, info, u"Performance schema: Last 50 queries with full table scans", query_file)
    # Top 15 reader queries (95% percentile)
    performance_check(sess, option, info, u"Performance schema: Top 15 reader queries (95% percentile)", query_file)
    # Top 15 most row look queries (95% percentile)
    performance_check(sess, option, info, u"Performance schema: Top 15 most row look queries (95% percentile)", query_file)
    # Top 15 total latency queries (95% percentile)
    performance_check(sess, option, info, u"Performance schema: Top 15 total latency queries (95% percentile)", query_file)
    # Top 15 max latency queries (95% percentile)
    performance_check(sess, option, info, u"Performance schema: Top 15 max latency queries (95% percentile)", query_file)
    # Top 15 average latency queries (95% percentile)
    performance_check(sess, option, info, u"Performance schema: Top 15 average latency queries (95% percentile)", query_file)
    # Top 20 queries with sort
    performance_check(sess, option, info, u"Performance schema: Top 20 queries with sort", query_file)
    # Last 50 queries with sort
    performance_check(sess, option, info, u"Performance schema: Last 50 queries with sort", query_file)
    # Top 15 row sorting queries with sort
    performance_check(sess, option, info, u"Performance schema: Top 15 row sorting queries with sort", query_file)
    # Top 15 total latency queries with sort
    performance_check(sess, option, info, u"Performance schema: Top 15 total latency queries with sort", query_file)
    # Top 15 merge queries with sort
    performance_check(sess, option, info, u"Performance schema: Top 15 merge queries with sort", query_file)
    # Top 15 average sort merges queries with sort
    performance_check(sess, option, info, u"Performance schema: Top 15 average sort merges queries with sort", query_file)
    # Top 15 scans queries with sort
    performance_check(sess, option, info, u"Performance schema: Top 15 scans queries with sort", query_file)
    # Top 15 range queries with sort
    performance_check(sess, option, info, u"Performance schema: Top 15 range queries with sort", query_file)
    # Top Top 20 queries with temp table
    performance_check(sess, option, info, u"Performance schema: Top 20 queries with temp table", query_file)
    # Top Last 50 queries with temp table
    performance_check(sess, option, info, u"Performance schema: Last 50 queries with temp table", query_file)
    # Top 15 total latency queries with temp table
    performance_check(sess, option, info, u"Performance schema: Top 15 total latency queries with temp table", query_file)
    # Top 15 queries with temp table to disk
    performance_check(sess, option, info, u"Performance schema: Top 15 queries with temp table to disk", query_file)
    # Top 15 class events by number
    performance_check(sess, option, info, u"Performance schema: Top 15 class events by number", query_file)
    # Top 30 events by number
    performance_check(sess, option, info, u"Performance schema: Top 30 events by number", query_file)
    # Top 15 class events by total latency
    performance_check(sess, option, info, u"Performance schema: Top 15 class events by total latency", query_file)
    # Top 30 events by total latency
    performance_check(sess, option, info, u"Performance schema: Top 30 events by total latency", query_file)
    # Top 15 class events by max latency
    performance_check(sess, option, info, u"Performance schema: Top 15 class events by max latency", query_file)
    # Top 30 events by max latency
    performance_check(sess, option, info, u"Performance schema: Top 30 events by max latency", query_file)

    return recommendations, adjusted_vars, results


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
        option.format_print(u"AriaDB is disabled.", style=tuner.Print.INFO)
        return recommendations, adjusted_vars

    option.format_print(u"AriaDB is enabled.", style=tuner.Print.INFO)

    # Aria pagecache
    if calc.total_ariadb_indexes == 0 and option.do_remote:
        recommendations.append(
            u"Unable to calculate AriaDB indexes on remote MySQL server < 5.0.0"
        )
    elif calc.total_ariadb_indexes == 0:
        option.format_print(u"None of your AriaDB tables are indexed - add indexes immediately", style=tuner.Print.BAD)
    else:
        ariadb_pagecache_size_message: str = (
            u"AriaDB pagecache size / total AriaDB indexes: "
            f"{util.bytes_to_string(info.ariadb_pagecache_buffer_size)}/"
            f"{util.bytes_to_string(calc.total_ariadb_indexes)}"
        )
        if info.ariadb_pagecache_buffer_size < calc.total_ariadb_indexes and calc.pct_ariadb_keys_from_memory < 95:
            option.format_print(ariadb_pagecache_size_message, style=tuner.Print.BAD)
            adjusted_vars.append(
                f"ariadb_pagecache_buffer_size (> {util.bytes_to_string(calc.total_ariadb_indexes)})"
            )
        else:
            option.format_print(ariadb_pagecache_size_message, style=tuner.Print.GOOD)

        if stat.ariadb_pagecache_read_requests > 0:
            ariadb_pagecache_read_message: str = (
                f"AriaDB pagecache hit rate: {calc.pct_ariadb_keys_from_memory}% ("
                f"{util.bytes_to_string(stat.ariadb_pagecache_read_requests)} cached /"
                f"{util.bytes_to_string(stat.ariadb_pagecache_read_requests)} reads)"
            )
            if calc.pct_ariadb_keys_from_memory < 95:
                option.format_print(ariadb_pagecache_read_message, style=tuner.Print.BAD)
            else:
                option.format_print(ariadb_pagecache_read_message, style=tuner.Print.GOOD)

    return recommendations, adjusted_vars


def mariadb_tokudb(option: tuner.Option, info: tuner.Info) -> None:
    """Recommendations for TokuDB

    :param tuner.Option option:
    :param tuner.Info info:
    :return:
    """
    option.format_print(u"TokuDB Metrics", style=tuner.Print.SUBHEADER)

    # Toku DB
    if not info.have_tokudb:
        option.format_print(u"TokuDB is disabled.", style=tuner.Print.INFO)
        return

    option.format_print(u"TokuDB is enabled.", style=tuner.Print.INFO)


def mariadb_xtradb(option: tuner.Option, info: tuner.Info) -> None:
    """Recommendations for XtraDB

    :param tuner.Option option:
    :param tuner.Info info:
    :return:
    """
    option.format_print(u"XtraDB Metrics", style=tuner.Print.SUBHEADER)

    # Xtra DB
    if not info.have_xtradb:
        option.format_print(u"XtraDB is disabled.", style=tuner.Print.INFO)
        return

    option.format_print(u"XtraDB is enabled.", style=tuner.Print.INFO)


def mariadb_rocksdb(option: tuner.Option, info: tuner.Info) -> None:
    """Recommendations for RocksDB

    :param tuner.Option option:
    :param tuner.Info info:
    :return:
    """
    option.format_print(u"RocksDB Metrics", style=tuner.Print.SUBHEADER)

    # Rocks DB
    if not info.have_rocksdb:
        option.format_print(u"RocksDB is disabled.", style=tuner.Print.INFO)
        return

    option.format_print(u"RocksDB is enabled.", style=tuner.Print.INFO)


def mariadb_spider(option: tuner.Option, info: tuner.Info) -> None:
    """Recommendations for Spider

    :param tuner.Option option:
    :param tuner.Info info:
    :return:
    """
    option.format_print(u"Spider Metrics", style=tuner.Print.SUBHEADER)

    # Toku DB
    if not info.have_spider:
        option.format_print(u"Spider is disabled.", style=tuner.Print.INFO)
        return

    option.format_print(u"Spider is enabled.", style=tuner.Print.INFO)


def mariadb_connect(option: tuner.Option, info: tuner.Info) -> None:
    """Recommendations for Connect

    :param tuner.Option option:
    :param tuner.Info info:
    :return:
    """
    option.format_print(u"Connect Metrics", style=tuner.Print.SUBHEADER)

    # Toku DB
    if not info.have_connect:
        option.format_print(u"Connect is disabled.", style=tuner.Print.INFO)
        return

    option.format_print(u"Connect is enabled.", style=tuner.Print.INFO)


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

    option.format_print(f"{galera_options}", style=tuner.Print.DEBUG)

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

    option.format_print(u"Galera Metrics", style=tuner.Print.SUBHEADER)

    # Galera Cluster
    if not info.have_galera:
        option.format_print(u"Galera is disabled.", style=tuner.Print.INFO)
        return recommendations, adjusted_vars, results

    option.format_print(u"Galera is enabled.", style=tuner.Print.INFO)

    option.format_print(u"Galera variables:", style=tuner.Print.DEBUG)
    galera_infos: typ.Sequence[typ.Tuple[str, typ.Any]] = [
        (galera_key, galera_value)
        for galera_key, galera_value in util.class_variables(info)
        if u"wsrep" in galera_key
        and galera_key != u"wsrep_provider_options"
    ]
    for galera_info, galera_value in galera_infos:
        option.format_print(f"\t{galera_info} = {galera_value}", style=tuner.Print.DEBUG)
        results[u"Galera"][u"Info"][galera_info]: typ.Any = galera_value

    option.format_print(u"Galera wsrep provider options:", style=tuner.Print.DEBUG)
    galera_options: typ.Sequence[str] = wsrep_options(option, info)
    results[u"Galera"][u"wsrep options"]: typ.Sequence[str] = galera_options
    for galera_option in galera_options:
        option.format_print(f"\t{galera_option.strip()}", style=tuner.Print.DEBUG)

    option.format_print(u"Galera status:", style=tuner.Print.DEBUG)
    galera_stats: typ.Sequence[typ.Tuple[str, typ.Any]] = [
        (galera_key, galera_value)
        for galera_key, galera_value in util.class_variables(stat)
        if u"wsrep" in galera_key
    ]
    for galera_stat, galera_value in galera_stats:
        option.format_print(f"\t{galera_stat} = {galera_value}", style=tuner.Print.DEBUG)
        results[u"Galera"][u"Status"][galera_stat]: typ.Any = galera_value

    option.format_print(
        f"GCache is using {util.bytes_to_string(wsrep_option(option, info, key=u'gcache.mem_size'))}",
        style=tuner.Print.INFO
    )

    wsrep_slave_threads: int = wsrep_option(option, info, key=u"wsrep_slave_threads")
    cpu_count: int = psu.cpu_count()
    if wsrep_slave_threads < 3 * cpu_count or wsrep_slave_threads > 4 * cpu_count:
        option.format_print(u"wsrep_slave_threads is not between 3 to 4 times the number of CPU(s)", style=tuner.Print.BAD)
        adjusted_vars.append(u"wsrep_slave_threads = 4 * # of Core CPU")
    else:
        option.format_print(u"wsrep_slave_threads is between 3 to 4 times the number of CPU(s)", style=tuner.Print.GOOD)

    gcs_limit: int = wsrep_option(option, info, key=u"gcs.limit")
    if gcs_limit != 5 * wsrep_slave_threads:
        option.format_print(u"gcs.limit should be equal to 5 * wsrep_slave_threads", style=tuner.Print.BAD)
        adjusted_vars.append(u"wsrep_slave_threads = 5 * # wsrep_slave_threads")
    else:
        option.format_print(u"gcs.limit is equal to 5 * wsrep_slave_threads", style=tuner.Print.GOOD)

    wsrep_flow_control_paused: float = wsrep_option(option, info, key=u"wsrep_flow_control_paused")
    if wsrep_flow_control_paused > 0.02:
        option.format_print(u"Flow control fraction > 0.02", style=tuner.Print.BAD)
    else:
        option.format_print(u"Flow control fraction seems to be OK", style=tuner.Print.GOOD)

    non_primary_key_table_query: sqla.Text = info.query_from_file(u"non_primary-key-table-query.sql")
    result = sess.execute(non_primary_key_table_query)
    NonPrimaryKeyTable = clct.namedtuple(u"NonPrimaryKeyTable", result.keys())
    non_primary_key_tables: typ.Sequence[str] = [
        NonPrimaryKeyTable(*non_primary_key_table).TABLE
        for non_primary_key_table in result.fetchall()
    ]

    results[u"Tables without a Primary Key"]: typ.Sequence[str] = []
    if len(non_primary_key_tables) > 0:
        option.format_print(u"Following table(s) don't have primary keys:", style=tuner.Print.BAD)
        for non_primary_key_table in non_primary_key_tables:
            option.format_print(f"\t{non_primary_key_table}", style=tuner.Print.BAD)
            results[u"Tables without a Primary Key"].append(non_primary_key_table)
    else:
        option.format_print(u"All tables have a primary key", style=tuner.Print.GOOD)

    non_innodb_table_query: sqla.Text = info.query_from_file(u"non_innodb-table-query.sql")
    result = sess.execute(non_innodb_table_query)
    NonInnoDBTable = clct.namedtuple(u"NonInnoDBTable", result.keys())
    non_innodb_tables: typ.Sequence[str] = [
        NonInnoDBTable(*non_innodb_table).TABLE
        for non_innodb_table in result.fetchall()
    ]

    if len(non_innodb_tables) > 0:
        option.format_print(u"Following table(s) are not InnoDB table(s):", style=tuner.Print.BAD)
        for non_innodb_table in non_innodb_tables:
            option.format_print(f"\t{non_innodb_table}", style=tuner.Print.BAD)
            recommendations.append(u"Ensure that all tables are InnoDB tables for Galera replication")
    else:
        option.format_print(u"All tables are InnoDB tables", style=tuner.Print.GOOD)

    if info.binlog_format != u"ROW":
        option.format_print(u"Binlog format should be in ROW mode.", style=tuner.Print.BAD)
        adjusted_vars.append(u"binlog_format = ROW")
    else:
        option.format_print(u"Binlog format is in ROW mode.", style=tuner.Print.BAD)

    if info.innodb_flush_log_at_trx_commit:
        option.format_print(u"InnoDB flush log at each commit should be disabled.", style=tuner.Print.BAD)
        adjusted_vars.append(u"innodb_flush_log_at_trx_commit = False")
    else:
        option.format_print(u"InnoDB flush log at each commit is disabled", style=tuner.Print.GOOD)

    option.format_print(f"Read consistency mode: {info.wsrep_causal_reads}", style=tuner.Print.INFO)
    if info.wsrep_cluster_name and info.wsrep_on:
        option.format_print(u"Galera WsREP is enabled.", style=tuner.Print.GOOD)
        if info.wsrep_cluster_address.strip():
            option.format_print(f"Galera Cluster address is defined: {info.wsrep_cluster_address}", style=tuner.Print.GOOD)

            nodes: typ.Sequence[str] = info.wsrep_cluster_address.split(u",")
            option.format_print(f"There are {len(nodes)} nodes in wsrep_cluster_size", style=tuner.Print.INFO)

            node_amount: int = stat.wsrep_cluster_size
            if node_amount in (3, 5):
                option.format_print(f"There are {node_amount} nodes in wsrep_cluster_size", style=tuner.Print.GOOD)
            else:
                option.format_print((
                    f"There are {node_amount} nodes in wsrep_cluster_size. "
                    u"Prefer 3 or 5 node architecture"
                ), style=tuner.Print.BAD)
                recommendations.append(u"Prefer 3 or 5 node architecture")

            # wsrep_cluster_address doesn't include garbd nodes
            if len(nodes) > node_amount:
                option.format_print((
                    u"All cluster nodes are not detected. "
                    u"wsrep_cluster_size less then node count in wsrep_cluster_address"
                ), style=tuner.Print.BAD)
            else:
                option.format_print(u"All cluster nodes detected.", style=tuner.Print.GOOD)
        else:
            option.format_print(u"Galera Cluster address is undefined", style=tuner.Print.BAD)
            adjusted_vars.append(u"Set up wsrep_cluster_name variable for Galera replication")

        if info.wsrep_node_name.strip():
            option.format_print(f"Galera node name is defined: {info.wsrep_node_name}", style=tuner.Print.GOOD)
        else:
            option.format_print(u"Galera node name is not defined", style=tuner.Print.BAD)
            adjusted_vars.append(u"Set up wsrep_node_name variable for Galera replication")

        if info.wsrep_notify_cmd.strip():
            option.format_print(f"Galera notify command is defined: {info.wsrep_notify_cmd}", style=tuner.Print.GOOD)
        else:
            option.format_print(u"Galera notify command is not defined", style=tuner.Print.BAD)
            adjusted_vars.append(u"Set up wsrep_notify_cmd variable for Galera replication")

        if "xtrabackup" in info.wsrep_sst_method.strip():
            option.format_print(f"Galera SST method is based on xtrabackup", style=tuner.Print.GOOD)
        else:
            option.format_print(u"Galera node name is not xtrabackup based", style=tuner.Print.BAD)
            adjusted_vars.append(u"Set up parameter wsrep_sst_method variable to xtrabackup based parameter")

        if info.wsrep_osu_method == "TOI":
            option.format_print(u"TOI is the default mode for upgrade.", style=tuner.Print.GOOD)
        else:
            option.format_print(u"Schema upgrades are not replicated automatically.", style=tuner.Print.BAD)
            adjusted_vars.append(u"Set wsrep_osu_method = 'TOI'")

        option.format_print(f"Max WsREP message: {util.bytes_to_string(info.wsrep_max_ws_size)}", style=tuner.Print.INFO)
    else:
        option.format_print(u"Galera WsREP is disabled.", style=tuner.Print.BAD)

    if stat.wsrep_connected:
        option.format_print(u"Node is connected", style=tuner.Print.GOOD)
    else:
        option.format_print(u"Node is not connected", style=tuner.Print.BAD)

    if stat.wsrep_ready:
        option.format_print(u"Node is ready", style=tuner.Print.GOOD)
    else:
        option.format_print(u"Node is not ready", style=tuner.Print.BAD)

    option.format_print(f"Cluster status: {stat.wsrep_cluster_status}", style=tuner.Print.INFO)
    if stat.wsrep_cluster_status.title() == u"Primary":
        option.format_print(u"Galera cluster is consistent and ready for operations", style=tuner.Print.GOOD)
    else:
        option.format_print(u"Galera cluster is not consistent and ready", style=tuner.Print.BAD)

    if stat.wsrep_local_state_uuid == stat.wsrep_cluster_state_uuid:
        option.format_print((
            f"Node and whole cluster at the same level: {stat.wsrep_cluster_state_uuid}"
        ), style=tuner.Print.GOOD)
    else:
        option.format_print(u"None and whole cluster not at same level", style=tuner.Print.BAD)
        option.format_print(f"Node    state uuid: {stat.wsrep_local_state_uuid}", style=tuner.Print.INFO)
        option.format_print(f"Cluster state uuid: {stat.wsrep_cluster_state_uuid}", style=tuner.Print.INFO)

    if stat.wsrep_local_state_comment.title() == u"Synced":
        option.format_print(u"Node is synced with whole cluster", style=tuner.Print.GOOD)
    else:
        option.format_print(u"Node is not synced", style=tuner.Print.BAD)
        option.format_print(f"Node state: {stat.wsrep_local_state_comment}", style=tuner.Print.INFO)

    if stat.wsrep_local_cert_failures == 0:
        option.format_print(u"There are no certification failures detected", style=tuner.Print.GOOD)
    else:
        option.format_print(
            f"There are {stat.wsrep_local_cert_failures} certification failure(s) detected",
            style=tuner.Print.BAD
        )

    wsrep_galera_stats: typ.Sequence[typ.Tuple[str, typ.Any]] = [
        (galera_key, galera_value)
        for galera_key, galera_value in util.class_variables(stat)
        if u"wsrep" in galera_key
        or u"galera" in galera_key
    ]
    for wsrep_galera_stat, wsrep_galera_value in wsrep_galera_stats:
        option.format_print(f"WsRep: {wsrep_galera_stat} = {wsrep_galera_value}", style=tuner.Print.DEBUG)

    option.format_print(",".join(wsrep_options(option, info)), style=tuner.Print.DEBUG)

    return recommendations, adjusted_vars, results


def mysql_innodb(
    option: tuner.Option,
    info: tuner.Info,
    stat: tuner.Stat,
    calc: tuner.Calc,
    engine_stats: typ.Dict[str, int]
) -> typ.Sequence[typ.List[str], typ.List[str], typ.DefaultDict]:
    """Recommendations for InnoDB

    :param tuner.Option option:
    :param tuner.Info info:
    :param tuner.Stat stat:
    :param tuner.Calc calc:
    :param typ.Dict[str, int] engine_stats: Engine size
    :return typ.Sequence[typ.List[str], typ.List[str], typ.DefaultDict]:
        list of recommendations and list of adjusted variables, and results
    """
    recommendations: typ.List[str] = []
    adjusted_vars: typ.List[str] = []
    results: typ.DefaultDict = clct.defaultdict(clct.defaultdict(clct.defaultdict(dict)))

    option.format_print(u"InnoDB Metrics", style=tuner.Print.SUBHEADER)

    # InnoDB
    if not info.have_innodb:
        option.format_print(u"InnoDB is disabled.", style=tuner.Print.INFO)
        if (info.ver_major, info.ver_minor) >= (5, 5):
            option.format_print(
                u"InnoDB Storage Engine is disabled. InnoDB is the default storage engine",
                style=tuner.Print.BAD
            )

        return recommendations, adjusted_vars

    option.format_print(u"InnoDB is enabled.", style=tuner.Print.INFO)

    if option.buffers:
        option.format_print(u"InnoDB Buffers", style=tuner.Print.INFO)

        option.format_print(
            f" +-- InnoDB Buffer Pool: {util.bytes_to_string(info.innodb_buffer_pool_size)}",
            style=tuner.Print.INFO
        )

        option.format_print((
            u" +-- InnoDB Buffer Pool Instances:"
            f" {util.bytes_to_string(info.innodb_buffer_pool_instances)}"
        ), style=tuner.Print.INFO)

        option.format_print((
            u" +-- InnoDB Buffer Pool Chunk Size:"
            f" {util.bytes_to_string(info.innodb_buffer_pool_chunk_size)}"
        ), style=tuner.Print.INFO)

        option.format_print((
            u" +-- InnoDB Additional Mem Pool:"
            f" {util.bytes_to_string(info.innodb_additional_mem_pool_size)}"
        ), style=tuner.Print.INFO)

        option.format_print((
            u" +-- InnoDB Log File Size:"
            f" {util.bytes_to_string(info.innodb_log_file_size)}"
            f"({calc.innodb_log_size_pct}% of buffer pool)"
        ), style=tuner.Print.INFO)

        option.format_print((
            u" +-- InnoDB Log Files In Group:"
            f" {util.bytes_to_string(info.innodb_log_files_in_group)}"
        ), style=tuner.Print.INFO)

        option.format_print((
            u" +-- InnoDB Total Log File Size:"
            f" {util.bytes_to_string(info.innodb_log_files_in_group * info.innodb_log_file_size)}"
        ), style=tuner.Print.INFO)

        option.format_print((
            u" +-- InnoDB Log Buffer:"
            f" {util.bytes_to_string(info.innodb_log_buffer_size)}"
        ), style=tuner.Print.INFO)

        option.format_print((
            u" +-- InnoDB Log Buffer Free:"
            f" {util.bytes_to_string(stat.innodb_buffer_pool_pages_free)}"
        ), style=tuner.Print.INFO)

        option.format_print((
            u" +-- InnoDB Log Buffer Used:"
            f" {util.bytes_to_string(stat.innodb_buffer_pool_pages_total)}"
        ), style=tuner.Print.INFO)

    option.format_print((
        u" +-- InnoDB Thread Concurrency:"
        f" {util.bytes_to_string(info.innodb_thread_concurrency)}"
    ), style=tuner.Print.INFO)

    if info.innodb_file_per_table:
        option.format_print(u"InnoDB file per table is activated", style=tuner.Print.GOOD)
    else:
        option.format_print(u"InnoDB file per table is not activated", style=tuner.Print.BAD)
        adjusted_vars.append(u"innodb_file_per_table=ON")

    # InnoDB Buffer Pool Size
    if info.innodb_buffer_pool_size > engine_stats[u"InnoDB"]:
        option.format_print((
            u"InnoDB Buffer Pool / Data size: "
            f"{util.bytes_to_string(info.innodb_buffer_pool_size)}/"
            f"{util.bytes_to_string(engine_stats[u'InnoDB'])}"
        ), style=tuner.Print.GOOD)
    else:
        option.format_print((
            u"InnoDB Buffer Pool / Data size: "
            f"{util.bytes_to_string(info.innodb_buffer_pool_size)}/"
            f"{util.bytes_to_string(engine_stats[u'InnoDB'])}"
        ), style=tuner.Print.BAD)
        adjusted_vars.append(
            f"innodb_buffer_pool_size (>= {util.bytes_to_string(engine_stats[u'InnoDB'])}) if possible."
        )

    if 20 <= calc.innodb_log_size_pct <= 30:
        option.format_print((
            u"InnoDB Log file size / InnoDB Buffer pool size "
            f"({calc.innodb_log_size_pct}%): "
            f"{util.bytes_to_string(info.innodb_log_file_size)} * "
            f"{info.innodb_log_files_in_group} / "
            f"{util.bytes_to_string(info.innodb_buffer_pool_size)} "
            u"should be equal 25%"
        ), style=tuner.Print.GOOD)
    else:
        option.format_print((
            u"InnoDB Log file size / InnoDB Buffer pool size "
            f"({calc.innodb_log_size_pct}%): "
            f"{util.bytes_to_string(info.innodb_log_file_size)} * "
            f"{info.innodb_log_files_in_group} / "
            f"{util.bytes_to_string(info.innodb_buffer_pool_size)} "
            u"should be equal 25%"
        ), style=tuner.Print.BAD)
        adjusted_vars.append((
            u"innodb_log_file_size * innodb_log_files_in_group should be equal to 25% of buffer pool size "
            f"(={util.bytes_to_string(int(info.innodb_buffer_pool_size * info.innodb_log_files_in_group / 4))}) "
            u"if possible"
        ))

    # InnoDB Buffer Pool Instances (MySQL 5.6.6+)
    # Bad Value if > 64
    if info.innodb_buffer_pool_instances > 64:
        option.format_print(f"InnoDB Buffer pool instances: {info.innodb_buffer_pool_instances}", style=tuner.Print.BAD)
        adjusted_vars.append(u"innodb_buffer_pool_instances (<= 64)")

    # InnoDB Buffer Pool Size > 1 GB
    if info.innodb_buffer_pool_size > 1 * 1024 ** 3:
        # InnoDB Buffer Pool Size / 1 GB = InnoDB Buffer Pool Instances limited to 64 max.
        # InnoDB Buffer Pool Size > 64 GB
        max_innodb_buffer_pool_instances: int = min(int(info.innodb_buffer_pool_size / (1024 ** 3)), 64)

        if info.innodb_buffer_pool_instances == max_innodb_buffer_pool_instances:
            option.format_print(f"InnoDB Buffer pool instances: {info.innodb_buffer_pool_instances}", style=tuner.Print.GOOD)
        else:
            option.format_print(f"InnoDB Buffer pool instances: {info.innodb_buffer_pool_instances}", style=tuner.Print.BAD)
            adjusted_vars.append(f"innodb_buffer_pool_instances (= {max_innodb_buffer_pool_instances})")
    else:
        if info.innodb_buffer_pool_instances == 1:
            option.format_print(f"InnoDB Buffer pool instances {info.innodb_buffer_pool_instances}", style=tuner.Print.GOOD)
        else:
            option.format_print(u"InnoDB Buffer pool <= 1 GB and innodb_buffer_pool_instances != 1", style=tuner.Print.BAD)
            adjusted_vars.append(u"innodb_buffer_pool_instances (== 1)")

    # InnoDB Used Buffer Pool Size vs CHUNK size
    if info.innodb_buffer_pool_chunk_size:
        option.format_print(u"InnoDB Buffer Pool Chunk Size not used or defined in your version", style=tuner.Print.INFO)
    else:
        option.format_print((
            u"Number of InnoDB Buffer Pool Chunks: "
            f"{info.innodb_buffer_pool_size} / {info.innodb_buffer_pool_chunk_size} for "
            f"{info.innodb_buffer_pool_instances} Buffer Pool Instance(s)"
        ), style=tuner.Print.INFO)

        if info.innodb_buffer_pool_size % (info.innodb_buffer_pool_chunk_size * info.innodb_buffer_pool_instances) == 0:
            option.format_print((
                u"innodb_buffer_pool_size aligned with innodb_buffer_pool_chunk_size & innodb_buffer_pool_instances"
            ), style=tuner.Print.GOOD)
        else:
            option.format_print((
                u"innodb_buffer_pool_size not aligned with innodb_buffer_pool_chunk_size & innodb_buffer_pool_instances"
            ), style=tuner.Print.BAD)
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
        ), style=tuner.Print.GOOD)
    else:
        option.format_print((
            f"{calc.pct_read_efficiency}% "
            f"({stat.innodb_buffer_pool_read_requests - stat.innodb_buffer_pool_reads} hits / "
            f"{stat.innodb_buffer_pool_read_requests} total)"
        ), style=tuner.Print.BAD)

    # InnoDB Write Efficiency
    if calc.pct_write_efficiency > 90:
        option.format_print((
            f"{calc.pct_read_efficiency}% "
            f"({stat.innodb_log_write_requests - stat.innodb_log_writes} hits / "
            f"{stat.innodb_log_write_requests} total)"
        ), style=tuner.Print.GOOD)
    else:
        option.format_print((
            f"{calc.pct_read_efficiency}% "
            f"({stat.innodb_log_write_requests - stat.innodb_log_writes} hits / "
            f"{stat.innodb_log_write_requests} total)"
        ), style=tuner.Print.BAD)

    # InnoDB Log Waits
    if calc.pct_read_efficiency > 90:
        option.format_print((
            u"InnoDB Log Waits:"
            f"{util.percentage(stat.innodb_log_waits, stat.innodb_log_writes)}% "
            f"({stat.innodb_log_waits} waits / "
            f"{stat.innodb_log_writes} writes)"
        ), style=tuner.Print.GOOD)
    else:
        option.format_print((
            u"InnoDB Log Waits:"
            f"{util.percentage(stat.innodb_log_waits, stat.innodb_log_writes)}% "
            f"({stat.innodb_log_waits} waits / "
            f"{stat.innodb_log_writes} writes)"
        ), style=tuner.Print.BAD)
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

    option.format_print(u"Database Metrics", style=tuner.Print.SUBHEADER)
    if (info.ver_major, info.ver_minor) >= (5, 5):
        option.format_print(u"Skip Database metrics from information schema missing in this version", style=tuner.Print.INFO)
        return recommendations, adjusted_vars

    database_query: sqla.Text = info.query_from_file(u"all-databases.sql")
    result = sess.execute(database_query)
    Database = clct.namedtuple(u"Database", result.keys())
    databases: typ.Sequence[str] = [
        Database(*database).Database
        for database in result.fetchall()
    ]

    option.format_print(f"There are {len(databases)} Databases", style=tuner.Print.INFO)

    databases_info_query: sqla.Text = info.query_from_file(u"databases-info-query.sql")
    result = sess.execute(databases_info_query)
    DatabasesInfo = clct.namedtuple(u"DatabasesInfo", result.keys())
    databases_info: DatabasesInfo = [
        DatabasesInfo(*databases_info)
        for databases_info in result.fetchall()
    ][0]
    option.format_print(u"All Databases:", style=tuner.Print.INFO)
    option.format_print(f" +-- TABLE      : {databases_info.TABLE_COUNT}", style=tuner.Print.INFO)
    option.format_print(f" +-- ROWS       : {databases_info.ROW_AMOUNT}", style=tuner.Print.INFO)
    option.format_print((
        f" +-- DATA       : {util.bytes_to_string(databases_info.DATA_SIZE)} "
        f"({util.percentage(databases_info.DATA_SIZE, databases_info.TOTAL_SIZE)}%)"
    ), style=tuner.Print.INFO)
    option.format_print((
        f" +-- INDEX      : {util.bytes_to_string(databases_info.INDEX_SIZE)} "
        f"({util.percentage(databases_info.INDEX_SIZE, databases_info.TOTAL_SIZE)}%)"
    ), style=tuner.Print.INFO)

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
    ), style=tuner.Print.INFO)

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
    ), style=tuner.Print.INFO)

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
        option.format_print(f"Database: {database}", style=tuner.Print.INFO)
        option.format_print(f" +-- TABLE      : {database_info.TABLE_COUNT}", style=tuner.Print.INFO)
        option.format_print(f" +-- ROWS       : {database_info.ROW_AMOUNT}", style=tuner.Print.INFO)
        option.format_print((
            f" +-- DATA       : {util.bytes_to_string(database_info.DATA_SIZE)} "
            f"({util.percentage(database_info.DATA_SIZE, database_info.TOTAL_SIZE)}%)"
        ), style=tuner.Print.INFO)
        option.format_print((
            f" +-- INDEX      : {util.bytes_to_string(database_info.INDEX_SIZE)} "
            f"({util.percentage(database_info.INDEX_SIZE, database_info.TOTAL_SIZE)}%)"
        ), style=tuner.Print.INFO)

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
        ), style=tuner.Print.INFO)

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
        ), style=tuner.Print.INFO)

        if database_info.DATA_LENGTH < database_info.INDEX_LENGTH:
            option.format_print(f"Index size is larger than data size for {database}", style=tuner.Print.BAD)
        if database_info.ENGINE_COUNT > 1:
            option.format_print(f"There are {database_info.ENGINE_COUNT} storage engines. Be careful.", style=tuner.Print.BAD)

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
                style=tuner.Print.BAD
            )
            recommendations.append(
                f"Check all table collations are identical for all tables in {database} database"
            )
        else:
            option.format_print(f"{database_info.COLLATION_COUNT} collation for database {database}", style=tuner.Print.GOOD)

        if database_info.ENGINE_COUNT > 1:
            option.format_print(f"{database_info.ENGINE_COUNT} different engines for database {database}", style=tuner.Print.BAD)
            recommendations.append(
                f"Check all table engines are identical for all tables in {database} database"
            )
        else:
            option.format_print(f"{database_info.ENGINE_COUNT} engine for database {database}", style=tuner.Print.GOOD)

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

        option.format_print(f"Character sets for {database} database table column: {all_character_sets}", style=tuner.Print.INFO)

        character_set_count: int = len(all_character_sets)
        if character_set_count > 1:
            option.format_print(
                f"{character_set_count} table columns have several character sets defined for all text like columns",
                style=tuner.Print.BAD
            )
            recommendations.append(
                f"Limit character sets for column to one character set if possible for {database} database"
            )
        else:
            option.format_print(
                f"{character_set_count} table columns have several character sets defined for all text like columns",
                style=tuner.Print.GOOD
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

        option.format_print(f"Collations for {database} database table column: {all_collations}", style=tuner.Print.INFO)

        collation_count: int = len(all_collations)
        if collation_count > 1:
            option.format_print(
                f"{collation_count} table columns have several collations defined for all text like columns",
                style=tuner.Print.BAD
            )
            recommendations.append(
                f"Limit collations for column to one collation if possible for {database} database"
            )
        else:
            option.format_print(
                f"{collation_count} table columns have several collations defined for all text like columns",
                style=tuner.Print.GOOD
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
        list of recommendations and list of adjusted variables, and results
    """
    recommendations: typ.List[str] = []
    adjusted_vars: typ.List[str] = []
    results: typ.DefaultDict[typ.DefaultDict] = clct.defaultdict(clct.defaultdict(clct.defaultdict(dict)))

    if not option.idx_stat:
        return recommendations, adjusted_vars, results

    option.format_print(u"Indexes Metrics", style=tuner.Print.SUBHEADER)
    if (info.ver_major, info.ver_minor, info.ver_minor) < (5, 5):
        option.format_print(u"Skip Index metrics from information schema missing in this version", style=tuner.Print.INFO)
        return recommendations, adjusted_vars, results

    worst_indexes_query: sqla.Text = info.query_from_file(u"worst-indexes-query.sql")
    result = sess.execute(worst_indexes_query)
    WorstIndex = clct.namedtuple(u"WorstIndex", result.keys())
    worst_indexes: typ.Sequence[WorstIndex] = [
        WorstIndex(*worst_index)
        for worst_index in result.fetchall()
    ]
    option.format_print(u"Worst Selectivity Indexes", style=tuner.Print.INFO)
    for worst_index in worst_indexes:
        option.format_print(f"{worst_index}", style=tuner.Print.DEBUG)
        option.format_print(f"Index: {worst_index.INDEX}", style=tuner.Print.INFO)

        option.format_print(f" +-- COLUMN      : {worst_index.SCHEMA_TABLE}", style=tuner.Print.INFO)
        option.format_print(f" +-- SEQ_NUM     : {worst_index.SEQ_IN_INDEX} sequence(s)", style=tuner.Print.INFO)
        option.format_print(f" +-- MAX_COLS    : {worst_index.MAX_COLUMNS} column(s)", style=tuner.Print.INFO)
        option.format_print(f" +-- CARDINALITY : {worst_index.CARDINALITY} distinct values", style=tuner.Print.INFO)
        option.format_print(f" +-- ROW_AMOUNT  : {worst_index.ROW_AMOUNT} rows", style=tuner.Print.INFO)
        option.format_print(f" +-- INDEX_TYPE  : {worst_index.INDEX_TYPE}", style=tuner.Print.INFO)
        option.format_print(f" +-- SELECTIVITY : {worst_index.SELECTIVITY}%", style=tuner.Print.INFO)

        results[u"Indexes"][worst_index.INDEX]: typ.Dict = {
            u"Column": worst_index.SCHEMA_TABLE,
            u"Sequence Number": worst_index.SEQ_IN_INDEX,
            u"Number of Columns": worst_index.MAX_COLUMNS,
            u"Cardinality": worst_index.CARDINALITY,
            u"Row Number": worst_index.ROW_AMOUNT,
            u"Index Type": worst_index.INDEX_TYPE,
            u"Selectivity": worst_index.SELECTIVITY
        }

        if worst_index.SELECTIVITY < 25:
            option.format_print(f"{worst_index.INDEX} has a low selectivity", style=tuner.Print.BAD)

    if not info.performance_schema:
        return recommendations, adjusted_vars, results

    unused_indexes_query: sqla.Text = info.query_from_file(u"unused-indexes-query.sql")
    result = sess.execute(unused_indexes_query)
    UnusedIndex = clct.namedtuple(u"UnusedIndex", result.keys())
    unused_indexes: typ.Sequence[UnusedIndex] = [
        UnusedIndex(*unused_index)
        for unused_index in result.fetchall()
    ]
    option.format_print(u"Unused Indexes", style=tuner.Print.INFO)
    if len(unused_indexes) > 0:
        recommendations.append(u"Remove unused indexes.")

    results[u"Indexes"]["Unused Indexes"]: typ.List = []
    for unused_index in unused_indexes:
        option.format_print(f"{unused_index}", style=tuner.Print.DEBUG)
        option.format_print(f"Index: {unused_index.INDEX} on {unused_index.SCHEMA_TABLE} is not used", style=tuner.Print.BAD)
        results[u"Indexes"]["Unused Indexes"].append(f"{unused_index.SCHEMA_TABLE}.{unused_index.INDEX}")

    return recommendations, adjusted_vars, results


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
    option.format_print(u"Recommendations", style=tuner.Print.SUBHEADER)

    if recommendations:
        option.format_print(u"General Recommendations:", style=tuner.Print.PRETTY)
        for recommendation in recommendations:
            option.format_print(f"\t{recommendation}", style=tuner.Print.PRETTY)

    if adjusted_vars:
        option.format_print(u"Variables to Adjust:", style=tuner.Print.PRETTY)
        if calc.pct_max_physical_memory > 90:
            option.format_print(u"  *** MySQL's maximum memory usage is dangerously high ***", style=tuner.Print.PRETTY)
            option.format_print(u"  *** Add RAM before increasing MySQL buffer variables ***", style=tuner.Print.PRETTY)
        for adjusted_var in adjusted_vars:
            option.format_print(f"\t{adjusted_var}", style=tuner.Print.PRETTY)

    if not recommendations and not adjusted_vars:
        option.format_print(u"No additional performance recommendations are available.", style=tuner.Print.PRETTY)


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
        option.format_print(f"{result}", style=tuner.Print.DEBUG)

    option.format_print(f"HTML REPORT: {option.report_file}", style=tuner.Print.DEBUG)

    if option.report_file:
        _template_model: str = template_model(option, info)
        with open(option.report_file, mode=u"w", encoding="utf-8") as rf:
            rf.write(_template_model.replace(u":data", json.dumps(result, sort_keys=True, indent=4)))

    if option.json:
        if option.pretty_json:
            print(json.dumps(result, sort_keys=True, indent=4))
        else:
            print(json.dumps(result))
