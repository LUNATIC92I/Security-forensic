"""PyInstaller entry point: GUI by default, CLI when arguments are given."""
import multiprocessing
import sys

if __name__ == "__main__":
    multiprocessing.freeze_support()
    if len(sys.argv) > 1:
        from lunatic_forensics.cli import main
    else:
        from lunatic_forensics.gui.app import main
    sys.exit(main())
