"""
Module with modified print functions to allow color changing
"""

import typing as typ


class Color:
    """Colors for output printing"""
    red: str = u"\e[0;31m"
    green: str = u"\e[0;32m"
    end: str = u"\e[0m"


def color_wrap(line: str, color: str) -> str:
    """Wraps string in formatting to color

    :param str line: string to be printed
    :param str color: color format string
    :return str: returns formatted string in input color
    """
    return u"".join((getattr(Color, color), line, Color.end))


def pretty_print(line: str, silent: bool, json: bool) -> None:
    """Base function for printing

    :param str line: string to be printed
    :param bool silent: whether to print
    :param bool json: whether to output as json only
    :return:
    """
    if not (silent or json):
        print(line, u"\n")


def format_print(line: str, no_format: bool, format_out: str, silent: bool, json: bool) -> None:
    """Prints color formatted messages

    :param str line: input message
    :param bool no_format: whether to print good results
    :param str format_out: formatting starter
    :param bool silent: whether to print
    :param bool json: whether to output as json only
    :return:
    """
    if not no_format:
        format_line: str = u" ".join((format_out, line))
        pretty_print(format_line, silent, json)


def subheader_print(line: str, silent: bool, json: bool, line_spaces: int=8, line_total: int=100) -> None:
    """Prints subheader

    :param str line: subheader title
    :param bool silent: whether to print
    :param bool json: whether to output as json only
    :param int line_spaces: indentation
    :param int line_total: total length of line
    :return:
    """
    line_size: int = len(line) + 2

    pretty_print(u" ", silent, json)
    line_start: str = u"-" * line_spaces
    line_end: str = u"-" * (line_total - line_size - line_spaces)
    subheader_line: str = u" ".join((line_start, line, line_end))
    pretty_print(subheader_line, silent, json)
