import sys
from ryu.cmd import manager


def main():
    sys.argv.append("controller.switch")
    # sys.argv.append("--verbose")
    sys.argv.append("--enable-debugger")
    manager.main()


if __name__ == "__main__":
    main()
