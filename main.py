import sys
from ryu.cmd import manager
from ryu.controller.ofp_handler import OFPHandler


def main():
    OFPHandler.LOGGER_NAME = "ryu"  # type: ignore
    sys.argv.append("controller.switch")
    sys.argv.extend(["--log-config-file", "logconf.ini"])

    # sys.argv.append("--verbose")
    sys.argv.append("--enable-debugger")
    manager.main()


if __name__ == "__main__":
    main()
