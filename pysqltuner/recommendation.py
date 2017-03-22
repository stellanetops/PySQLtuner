"""
Module to generate recommendations for change to MySQL
"""

import os
import psycopg2
import typing as typ
import pysqltuner as tuner
import pysqltuner.fancy_print as fp


def log_file():
    # TODO complete log file recommendations function
    pass


def cve(option: tuner.Option, ver_major: int, ver_minor: int, ver_micro: int) -> None:
    fp.subheader_print(u"CVE Security Recommendations", option)
    if not option.cve_file or not os.path.isfile(option.cve_file):
        fp.info_print(u"Skipped due to --cve-file option undefined", option)
        return None

    cve_found: int = 0
    with open(option.cve_file, mode="r", encoding="utf-8") as cf:
        for line in cf:
            cve_: typ.Sequence[str] = line.split(u";")

            cve_ver_major, cve_ver_minor, cve_ver_micro = tuple(int(cve_ver) for cve_ver in cve_[1:4])

            ver_compare: str = " ".join((
                f"Comparing {ver_major}.{ver_minor}.{ver_micro}",
                u"with",
                f"{cve_ver_major}, {cve_ver_minor}, {cve_ver_micro}",
                u":",
                u"<=" if (ver_major, ver_minor, ver_micro) <= (cve_ver_major, cve_ver_minor, cve_ver_micro) else ">"
            ))
            fp.debug_print(ver_compare, option)

            if not cve_ver_major == ver_major or not cve_ver_minor == ver_minor:
                if cve_ver_micro >= ver_micro:
                    cve_compare: str = f"{cve_[4]} (<= {cve_ver_major}.{cve_ver_minor}.{cve_ver_micro} : {cve_[6]}"
                    fp.bad_print(cve_compare, option)
                    # TODO insert cve_compare into 'result' object

                    cve_found += 1
            else:
                continue

    # TODO set another result object value

    if cve_found == 0:
        fp.good_print(u"NO SECURITY CVE FOUND FOR YOUR VERSION", option)
        return None

    if (ver_major, ver_minor) == (5, 5):
        fp.info_print(u"False positive CVE(s) for MySQL and MariaDB 5.5.x can be found.", option)
        fp.info_print(u"Check careful each CVE for those particular versions", option)

    cve_alert: str = f"{cve_found} CVE(s) found for your MySQL release."
    fp.bad_print(cve_alert, option)

    # TODO add cve_alert to recommendations (object?)
    # recommendations.append(cve_alert)
