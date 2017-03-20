"""
Module with modified print functions to allow color changing
Highlights different aspects of output
"""

import re
import typing as typ
import pysqltuner as tuner
import pysqltuner.util as util


class Color:
    red: str = "\e[0;31m"
    green: str = "\e[0;32m"
    end: str = "\e[0m"


me: str = util.get((r"whoami",))
opt: tuner.Option = tuner.Option()


class LineEdge:
    good: str = "[\e[0;32mOK\e[0m]" if opt.no_color else "[OK]"
    bad: str = "[\e[0;31m!!\e[0m]" if opt.no_color else "[!!]"
    info: str = "[\e[0;34m--\e[0m]" if opt.no_color else "[--]"
    debug: str = "[\e[0;31mDG\e[0m]" if opt.no_color else "[DG]"
    cmd: str = f"\e[1;32m[CMD]({me})" if opt.no_color else f"[CMD]({me})"
    end: str = "\e[0m" if opt.no_color else ""


def color_wrap(line: str, color: str) -> str:
    """Wraps string in formatting to color

    :param str line: string to be printed
    :param str color: color format string
    :return str: returns formatted string in input color
    """
    return "".join((color, line, Color.end))


def red_wrap(line: str, option: tuner.Option) -> str:
    """Wraps string in formatting to color red

    :param str line: string to be printed
    :param Option option: options object
    :return:
    """
    if option.no_color:
        return line
    else:
        return color_wrap(line, Color.red)


def green_wrap(line: str, option: tuner.Option) -> str:
    """Wraps string in formatting to color green

    :param str line: string to be printed
    :param Option option: options object
    :return:
    """
    if option.no_color:
        return line
    else:
        return color_wrap(line, Color.green)


def pretty_print(line: str, option: tuner.Option) -> None:
    """Base function for printing

    :param str line: string to be printed
    :param Option option: options
    :return:
    """
    if not (option.silent or option.json):
        print(line, "\n")


def good_print(line: str, option: tuner.Option) -> None:
    """Prints good messages

    :param str line: input message
    :param Option option: option object
    :return:
    """
    if not option.no_good:
        good_line: str = " ".join((LineEdge.good, line))
        pretty_print(good_line, option)


def bad_print(line: str, option: tuner.Option) -> None:
    """Prints bad messages

    :param str line: input message
    :param Option option: option object
    :return:
    """
    if not option.no_bad:
        bad_line: str = " ".join((LineEdge.bad, line))
        pretty_print(bad_line, option)


def info_print(line: str, option: tuner.Option) -> None:
    """Prints info messages

    :param str line: input message
    :param Option option: option object
    :return:
    """
    if not option.no_info:
        info_line: str = " ".join((LineEdge.info, line))
        pretty_print(info_line, option)


def debug_print(line: str, option: tuner.Option) -> None:
    """Prints debug messages

    :param str line: input message
    :param Option option: option object
    :return:
    """
    if option.debug:
        debug_line: str = " ".join((LineEdge.debug, line))
        pretty_print(debug_line, option)


def cmd_print(line: str, option: tuner.Option) -> None:
    """Prints cmd messages

    :param str line: input message
    :param Option option: option object
    :return:
    """
    cmd_line: str = " ".join((LineEdge.cmd, line))
    pretty_print(cmd_line, option)


def info_print_ml(lines: typ.Sequence[str], option: tuner.Option) -> None:
    """Prints each line in info array

    :param typ.Sequence[str] lines: array of info messages
    :param Option option: option object
    :return:
    """
    for line in lines:
        info_line: str = f"\t{line.strip()}"
        info_print(info_line, option)


def info_print_cmd(lines: typ.Sequence[str], option: tuner.Option) -> None:
    """Prints each line in command info array

    :param typ.Sequence[str] lines: array of info messages
    :param Option option: option object
    :return:
    """
    cmd_print(f"{lines}", option)
    info_lines: typ.Sequence[str] = [
        line
        for line in lines
        if line != ""
        and not re.match(r"/^\s*$/", line)
    ]
    info_print_ml(info_lines, option)


def subheader_print(line: str, option: tuner.Option, line_spaces: int=8, line_total: int=100) -> None:
    """Prints subheader

    :param str line: subheader title
    :param Option option: options object
    :param int line_spaces: indentation
    :param int line_total: total length of line
    :return:
    """
    line_size: int = len(line) + 2

    pretty_print(" ", option)
    line_start: str = "-" * line_spaces
    line_end: str = "-" * (line_total - line_size - line_spaces)
    subheader_line: str = " ".join((line_start, line, line_end))
    pretty_print(subheader_line, option)


def info_print_header_cmd(subheader_line: str, info_lines: typ.Sequence[str], option: tuner.Option) -> None:
    """Prints header and information

    :param str subheader_line: subheader
    :param typ.Sequence[str] info_lines: array of information
    :param Option option: options object
    :return:
    """
    subheader_print(subheader_line, option)
    info_print_cmd(info_lines, option)
