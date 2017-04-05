"""
Module to contain the tuner classes
"""

import collections as clct
import functools as funct
import getpass as gp
import os.path as osp
import sqlalchemy.orm as orm
import typing as typ


class Option:
    def __init__(self) -> None:
        self.me: str = gp.getuser()
        self.silent: bool = False
        self._no_color: bool = False
        self.no_good: bool = False
        self.no_info: bool = False
        self.no_bad: bool = False
        self.debug: bool = False
        self.good_out: str = None
        self.bad_out: str = None
        self.info_out: str = None
        self.debug_out: str = None
        self.cmd_out: str = None
        self.end_out: str = None
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
        self._banned_ports: typ.Sequence[int] = None
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
        self._verbose: bool = False
        self.defaults_file: str = None
        self.mysqladmin: str = None
        self.mysqlcmd: str = None
        self.do_remote: bool = False
        self.remote_connect: str = None
        self._cve_file: str = None
        self.basic_passwords_file: str = None

    @property
    def verbose(self) -> bool:
        return self._verbose

    @verbose.setter
    def verbose(self, value: bool) -> None:
        self._verbose = value
        if self._verbose:
            self.check_version = True
            self.db_stat = True
            self.idx_stat = True
            self.sys_stat = True
            self.buffers = True
            self.pf_stat = True
            self._cve_file = u"vulnerabilities.csv"

    @funct.lru_cache()
    @property
    def cve_file(self) -> str:
        if not self._cve_file or not osp.isfile(self._cve_file):
            self._cve_file = u"/usr/share/pysqltuner/vulnerabilities.csv"
        if osp.isfile(u"./vulnerabilities.csv"):
            self._cve_file = u"./vulnerabilities.csv"

        return self._cve_file

    @funct.lru_cache()
    @property
    def banned_ports(self) -> typ.Sequence[int]:
        return self._banned_ports

    @banned_ports.setter
    def banned_ports(self, value: str) -> None:
        if value:
            self._banned_ports = tuple(
                banned_port
                for banned_port in value.split(u",")
            )

    @funct.lru_cache()
    @property
    def no_color(self) -> bool:
        return self._no_color

    @no_color.setter
    def no_color(self, value: bool) -> None:
        self._no_color = value

        if not self._no_color:
            self.good_out = u"[\e[0;32mOK\e[0m]"
            self.bad_out = u"[\e[0;31m!!\e[0m]"
            self.info_out = u"[\e[0;34m--\e[0m]"
            self.debug_out = u"[\e[0;31mDG\e[0m]"
            self.cmd_out = f"\e[1;32m[CMD]({self.me})"
            self.end_out = u"\e[0m"
        else:
            self.good_out = u"[OK]"
            self.bad_out = u"[!!]"
            self.info_out = u"[--]"
            self.debug_out = u"[DG]"
            self.cmd_out = f"[CMD]({self.me})"
            self.end_out = u""


class Info:
    def __init__(self, sess: orm.session.Session):
        """Initializes info object

        :param orm.session.Session sess: session object
        """
        self._ver_major: int = 0
        self._ver_minor: int = 0
        self._ver_micro: int = 0
        self.data_dir: str = None
        self.script_dir: str = osp.dirname(__file__)
        self.query_dir: str = osp.join(osp.dirname(__file__), u"../query")
        self.have_archive: bool = False
        self.have_bdb: bool = False
        self.have_federated_engine: bool = True
        self.have_innodb: bool = True
        self.have_myisam: bool = True
        self.have_ndb_cluster: bool = False
        self.max_connections: int = 0
        self.read_buffer_size: int = 0
        self.read_rnd_buffer_size: int = 0
        self.sort_buffer_size: int = 0
        self.thread_stack: int = 0
        self.join_buffer_size: int = 0
        self.record_buffer: int = 0
        self.record_rnd_buffer: int = 0
        self.temp_table_size: int = 0
        self.max_heap_table_size: int = 0
        self.key_buffer_size: int = 0
        self.innodb_buffer_pool_size: int = 0
        self.innodb_buffer_pool_instances: int = 0
        self.innodb_buffer_pool_chunk_size: int = 0
        self.innodb_additional_mem_pool_size: int = 0
        self.innodb_log_buffer_size: int = 0
        self.query_cache_size: int = 0
        self.ariadb_pagecache_buffer_size: int = 0
        self.key_cache_block_size: int = 0
        self.open_files_limit: int = 0
        self.innodb_log_file_size: int = 0
        self.innodb_log_files_in_group: int = 0
        self.innodb_thread_concurrency: int = 0
        self.innodb_file_per_table: bool = True
        self.log_bin: bool = False
        self.have_threadpool: bool = False
        self.thread_pool_size: int = 0
        self.version: str = None
        self.performance_schema: bool = True
        self.have_galera: bool = False
        self.have_ariadb: bool = False
        self.have_tokudb: bool = False
        self.have_xtradb: bool = False
        self.have_rocksdb: bool = False
        self.have_spider: bool = False
        self.have_connect: bool = False
        self.wsrep_provider_options: str = None
        self.log_error_file: str = None
        self.ignore_builtin_innodb: bool = False
        self.gtid_mode = None
        self.gtid_strict_mode = None

        version_query_file: str = osp.join(self.query_dir, u"version-query.sql")

        with open(version_query_file, mode=u"r", encoding=u"utf-8") as vqf:
            version_query: str = vqf.read()

        result = sess.execute(version_query)
        Version = clct.namedtuple(u"Version", result.keys())
        versions: typ.Sequence[str] = [
            Version(*version).VERSION.split("-")[0].split(".")
            for version in result.fetchall()
        ]
        self._ver_major, self._ver_minor, self._ver_micro = [
            int(version)
            for version in versions[0]
        ]

    @property
    def ver_major(self) -> int:
        """Returns major version

        :return int: major version
        """
        return self._ver_major

    @property
    def ver_minor(self) -> int:
        """Returns minor version

        :return int: minor version
        """
        return self._ver_minor

    @property
    def ver_micro(self) -> int:
        """Returns micro version

        :return int: micro version
        """
        return self._ver_micro


class Stat:
    def __init__(self):
        self.questions: int = 0
        self.connections: int = 0
        self.aborted_connections: int = 0
        self.max_used_connections: int = 0
        self.physical_memory: int = 0
        self.slow_queries: int = 0
        self.key_blocks_unused: int = 0
        self.key_reads: int = 0
        self.key_read_requests: int = 0
        self.ariadb_pagecache_reads: int = 0
        self.ariadb_pagecache_read_requests: int = 0
        self.key_writes: int = 0
        self.key_write_requests: int = 0
        self.du_flags: str = None
        self.query_cache_hits: int = 0
        self.query_cache_free_memory: int = 0
        self.query_cache_low_memory_prunes: int = 0
        self.com_select: int = 0
        self.com_insert: int = 0
        self.com_delete: int = 0
        self.com_update: int = 0
        self.com_replace: int = 0
        self.uptime: int = 0
        self.sort_scan: int = 0
        self.sort_range: int = 0
        self.sort_merge_passes: int = 0
        self.select_range_check: int = 0
        self.select_full_join: int = 0
        self.created_temp_tables: int = 0
        self.created_temp_disk_tables: int = 0
        self.open_tables: int = 0
        self.opened_tables: int = 0
        self.open_files: int = 0
        self.immediate_table_locks: int = 0
        self.waited_table_locks: int = 0
        self.created_threads: int = 0
        self.innodb_buffer_pool_reads: int = 1
        self.innodb_buffer_pool_read_requests: int = 1
        self.innodb_log_writes: int = 1
        self.innodb_log_write_requests: int = 1
        self.innodb_buffer_pool_pages_free: int = 0
        self.innodb_buffer_pool_pages_total: int = 0
        self.innodb_log_waits: int = 0
        self.binlog_cache_use: int = 0
        self.binlog_cache_disk_use: int = 0


class Calc:
    def __init__(self):
        self.per_thread_buffers: int = 0
        self.total_per_thread_buffers: int = 0
        self.max_total_per_thread_buffers: int = 0
        self.max_temp_table_size: int = 0
        self.server_buffers: int = 0
        self.max_used_memory: int = 0
        self.pct_max_used_memory: float = 0
        self.max_peak_memory: int = 0
        self.pct_max_peak_memory: float = 0
        self.pct_max_physical_memory: float = 0
        self.pct_slow_queries: int = 0
        self.pct_connections_used: int = 0
        self.pct_connections_aborted: float = 0
        self.pct_key_buffer_used: float = 0
        self.pct_keys_from_memory: float = 0
        self.pct_ariadb_keys_from_memory: float = 0
        self.pct_write_keys_from_memory: float = 0
        self.total_myisam_indexes: int = 0
        self.total_ariadb_indexes: int = 0
        self.query_cache_efficiency: float = 0
        self.pct_query_cache_used: float = 0
        self.query_cache_prunes_per_day: int = 0
        self.total_sorts: int = 0
        self.pct_temp_store_table: int = 0
        self.joins_without_indexes: int = 0
        self.joins_without_indexes_per_day: int = 0
        self.pct_temp_disk: int = 0
        self.table_cache_hit_rate: int = 0
        self.pct_files_open: int = 0
        self.pct_immediate_table_locks: int = 0
        self.thread_cache_hit_rate: int = 0
        self.total_reads: int = 0
        self.total_writes: int = 0
        self.pct_reads: int = 0
        self.innodb_log_size_pct: int = 0
        self.pct_read_efficiency: float = 0
        self.pct_write_efficiency: float = 0
        self.pct_innodb_buffer_used: float = 0
        self.pct_binlog_cache: float = 0

    @property
    @funct.lru_cache()
    def pct_writes(self):
        return 100 - self.pct_reads
