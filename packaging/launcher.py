"""PyInstaller entry point: GUI by default, CLI when arguments are given."""
import sys

if len(sys.argv) > 1:
    from lunatic_forensics.cli import main
else:
    from lunatic_forensics.gui.app import main

sys.exit(main())
