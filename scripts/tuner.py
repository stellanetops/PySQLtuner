"""
Reviews a MySQL installation
Allows tuning to increase performance and stability
"""

import argparse
import platform
import pysqltuner as tuner
import pysqltuner.fancy_print as fp

if __name__ == "__main__":
    option: tuner.Option = tuner.Option()
    os_name: str = platform.system()
    if os_name == u"MSWin32":
        fp.info_print(f"* Windows OS({os_name}) is not fully supported", option)
