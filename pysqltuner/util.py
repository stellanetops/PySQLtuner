"""
Utilities module for random functions
"""

import collections as clct
import contextlib as ctxt
import math
import os
import re
import sqlalchemy.orm as orm
import subprocess as sbpr
import typing as typ
import yaml


def get(command: typ.Sequence) -> str:
    """Stdout from command line standardized for PySQLtuner

    :param typ.Sequence command: input command
    :return str: formatted stdout
    """
    return str(sbpr.check_output(command, shell=True, universal_newlines=True).strip())


def run(command: typ.Sequence) -> None:
    """Runs command

    :param typ.Sequence command: input command
    :return:
    """
    sbpr.run(command, shell=True, encoding=u"utf-8")


def is_readable(read_path: str) -> bool:
    """Checks if file is readable

    :param str read_path: readable file path
    :return bool:
    """
    return os.path.isfile(read_path) and os.access(read_path, os.R_OK)


def bytes_to_string(amount: int=0) -> str:
    """Converts amount of bytes as integer into string representation
    Rounds to two decimal places

    :param int amount: amount of bytes
    :return str: string representation
    """
    unit_name: typ.Sequence[str] = (
        u"B",
        u"KB",
        u"MB",
        u"GB",
        u"TB",
        u"PB",
        u"EB",
        u"ZB",
        u"YB",
    )

    index: int = int(math.floor(math.log(amount, 1024)))
    power: float = math.pow(1024, index)
    num: float = round(amount / power, 2)
    unit: str = unit_name[index]

    return f"{num}{unit}"


def string_to_bytes(value: str=None) -> int:
    """Converts string representation of bytes into amount of bytes

    :param str value: byte value as string
    :return int: amount of bytes
    """
    if value is None:
        return 0

    units: typ.Sequence[typ.Sequence[int, str]] = (
        (0, r"^(\d+\.?\d*)B$"),
        (1, r"^(\d+\.?\d*)KB$"),
        (2, r"^(\d+\.?\d*)MB$"),
        (3, r"^(\d+\.?\d*)GB$"),
        (4, r"^(\d+\.?\d*)TB$"),
        (5, r"^(\d+\.?\d*)PB$"),
        (6, r"^(\d+\.?\d*)EB$"),
        (7, r"^(\d+\.?\d*)ZB$"),
        (8, r"^(\d+\.?\d*)YB$"),
    )

    for exp, unit in reversed(units):
        amount = re.match(unit, value)
        if amount:
            return int(math.pow(1024, exp) * float(amount.group(1)))
    else:
        raise ValueError


def percentage(value: float=0, total: float=100) -> float:
    """Calculates percentage

    :param int value:
    :param int total:
    :return int: percentage
    """
    return round(value * 100 / total, 2)


def pretty_uptime(uptime: int) -> str:
    """Parse uptime into human friendly format

    :param int uptime: uptime in seconds
    :return str:
    """
    seconds = int(uptime % 60)
    minutes = int(uptime % 3600 / 60)
    hours = int(uptime % 86400 / 3600)
    days = int(uptime % 3600)

    if days > 0:
        hf_uptime: str = f"{days}d {hours}h {minutes}m {seconds}s"
    elif hours > 0:
        hf_uptime: str = f"{hours}h {minutes}m {seconds}s"
    elif minutes > 0:
        hf_uptime: str = f"{minutes}m {seconds}s"
    else:
        hf_uptime: str = f"{seconds}s"

    return hf_uptime


def connection_params(config_file: str=None,
                      host: str=None, username: str=None, password: str=None,
                      database: str= None) -> typ.Dict[str, str]:
    parsed_config: typ.Dict[str, typ.Any] = yaml.load(config_file)
    Config = clct.namedtuple("Config", parsed_config.keys())
    config: Config = Config(*parsed_config)
    return {
        "drivername": "mysql+mysqldb",
        "host": host or config.host,
        "username": username or config.username,
        "password": password or config.password,
        "database": database or config.database,
        "port": 3306
    }


@ctxt.contextmanager
def session_scope(engine):
    """Session generator for databases

    :param object engine: engine object

    :yield: session object
    """
    get_session = orm.scoped_session(orm.sessionmaker(bind=engine))
    session: orm.session.Session = get_session()
    try:
        yield session
        session.commit()
    except:
        session.rollback()
        raise
    finally:
        session.close()
