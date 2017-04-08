"""
Module to generate recommendations for change to MySQL
"""

import os
import psycopg2
import typing as typ
import pysqltuner.tuner as tuner
import pysqltuner.fancy_print as fp
import pysqltuner.util as util


def recommendation_template(option: tuner.Option) -> typ.Sequence[typ.List[str], typ.List[str]]:
    """Recommendations for XXX

    :param Option option:
    :return typ.Sequence[typ.List[str], typ.List[str]]: list of recommendations and list of adjusted variables
    """
    recommendations: typ.List[str] = []
    adjusted_vars: typ.List[str] = []

    return recommendations, adjusted_vars


def log_file_recommendations(option: tuner.Option, info: tuner.Info) -> typ.Sequence[typ.List[str], typ.List[str]]:
    """Recommendations for Log Files

    :param tuner.Option option:
    :param tuner.Info info:
    :return typ.Sequence[typ.List[str], typ.List[str]]: list of recommendations and list of adjusted variables
    """
    recommendations: typ.List[str] = []
    adjusted_vars: typ.List[str] = []

    option.subheader_print(u"Log File Recommendations")
    file_size: int = os.path.getsize(info.log_error_file)
    fp.info_print((
        f"Log File: {info.log_error_file}({util.bytes_to_string(file_size)})"
    ), option)

    if os.path.isfile(info.log_error_file):
        option.good_print(f"Log File {info.log_error_file} exists")
    else:
        option.bad_print(f"Log File {info.log_error_file} doesn't exist")

    if util.is_readable(info.log_error_file):
        option.good_print(f"Log File {info.log_error_file} is readable")
    else:
        option.bad_print(f"Log File {info.log_error_file} isn't readable")
        return recommendations, adjusted_vars

    if file_size > 0:
        option.good_print(f"Log File {info.log_error_file} is not empty")
    else:
        option.bad_print(f"Log File {info.log_error_file} is empty")

    if file_size < 32 * 1024 ** 2:
        option.good_print(f"Log File {info.log_error_file} is smaller than 32 MB")
    else:
        option.bad_print(f"Log File {info.log_error_file} is bigger than 32 MB")
        recommendations.append(
            f"{info.log_error_file} is > 32 MB, analyze why or implement a log rotation strategy such as logrotate!"
        )

    with open(info.log_error_file, mode=u"r", encoding="utf-8") as lef:
        last_shutdowns: typ.List[str] = []
        last_starts: typ.List[str] = []
        warnings: int = 0
        errors: int = 0
        for line_num, content in lef.readlines():
            if any(
                alert in content.lower()
                for alert in (
                    u"warning",
                    u"error"
                )
            ):
                option.debug_print(f"{line_num}: {content}")

            if u"error" in content.lower():
                errors += 1
            if u"warning" in content.lower():
                warnings += 1

            if u"Shutdown complete" in content and u"Innodb" not in content:
                last_shutdowns.append(content)
            if u"ready for connections" in content:
                last_starts.append(content)

    if warnings > 0:
        option.bad_print(f"{info.log_error_file} contains {warnings} warning(s).")
        recommendations.append(
            f"Control warning line(s) into {info.log_error_file} file"
        )
    else:
        option.good_print(f"{info.log_error_file} doesn't contain any warning.")

    if errors > 0:
        option.bad_print(f"{info.log_error_file} contains {errors} error(s).")
        recommendations.append(
            f"Control error line(s) into {info.log_error_file} file"
        )
    else:
        option.good_print(f"{info.log_error_file} doesn't contain any warning.")

    option.info_print(f"{len(last_starts)} start(s) detected in {info.log_error_file}")

    for index, last_start in enumerate(reversed(last_starts)):
        option.info_print(f"{index + 1}) {last_start}")

    for index, last_shutdown in enumerate(reversed(last_shutdowns)):
        option.info_print(f"{index + 1}) {last_shutdown}")

    return recommendations, adjusted_vars


def cve_recommendations(option: tuner.Option, info: tuner.Info) -> typ.Sequence[typ.List[str], typ.List[str]]:
    """Recommendations for XXX

    :param tuner.Option option:
    :param tuner.Info info:
    :return typ.Sequence[typ.List[str], typ.List[str]]: list of recommendations and list of adjusted variables
    """
    recommendations: typ.List[str] = []
    adjusted_vars: typ.List[str] = []

    option.subheader_print(u"CVE Security Recommendations")
    if not option.cve_file or not os.path.isfile(option.cve_file):
        option.info_print(u"Skipped due to --cve-file option undefined")
        return recommendations, adjusted_vars

    cve_found: int = 0
    with open(option.cve_file, mode="r", encoding="utf-8") as cf:
        for line in cf:
            cve_: typ.Sequence[str] = line.split(u";")

            cve_ver_major, cve_ver_minor, cve_ver_micro = tuple(int(cve_ver) for cve_ver in cve_[1:4])

            ver_compare: str = " ".join((
                f"Comparing {info.ver_major}.{info.ver_minor}.{info.ver_micro}",
                u"with",
                f"{cve_ver_major}, {cve_ver_minor}, {cve_ver_micro}",
                u":",
                u"<=" if (info.ver_major, info.ver_minor, info.ver_micro) <= (cve_ver_major, cve_ver_minor, cve_ver_micro) else ">"
            ))
            option.debug_print(ver_compare)

            # Avoid not major/minor version corresponding CVEs
            if not (cve_ver_major, cve_ver_minor) == (info.ver_major, info.ver_minor):
                if cve_ver_micro >= info.ver_micro:
                    cve_compare: str = f"{cve_[4]} (<= {cve_ver_major}.{cve_ver_minor}.{cve_ver_micro} : {cve_[6]}"
                    option.bad_print(cve_compare)
                    # TODO insert cve_compare into 'result' object

                    cve_found += 1
            else:
                continue

    # TODO set another result object value

    if cve_found == 0:
        option.good_print(u"NO SECURITY CVE FOUND FOR YOUR VERSION")
        return recommendations, adjusted_vars

    if (info.ver_major, info.ver_minor) == (5, 5):
        option.info_print(u"False positive CVE(s) for MySQL and MariaDB 5.5.x can be found.")
        option.info_print(u"Check careful each CVE for those particular versions")

    cve_alert: str = f"{cve_found} CVE(s) found for your MySQL release."
    option.bad_print(cve_alert)

    recommendations.append(
        f"{cve_found} CVE(s) found for your MySQL release. Consider upgrading your version!"
    )

    return recommendations, adjusted_vars
