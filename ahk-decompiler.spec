# PyInstaller 6.x: separate GUI and console entry points, both in one-file mode.
import sys
from PyInstaller.utils.hooks import collect_submodules

version_file = 'version_info.txt' if sys.platform == 'win32' else None

gui = Analysis(['main.py'], pathex=[], binaries=[], datas=[],
               hiddenimports=collect_submodules('core'), hookspath=[],
               hooksconfig={}, runtime_hooks=[], excludes=[], noarchive=False)
gui_pyz = PYZ(gui.pure)
gui_exe = EXE(gui_pyz, gui.scripts, gui.binaries, gui.datas, [],
              name='ahk-decompiler', console=False, debug=False, strip=False,
              upx=False, version=version_file)

cli = Analysis(['cli.py'], pathex=[], binaries=[], datas=[],
               hiddenimports=collect_submodules('core'), hookspath=[],
               hooksconfig={}, runtime_hooks=[], excludes=[], noarchive=False)
cli_pyz = PYZ(cli.pure)
cli_exe = EXE(cli_pyz, cli.scripts, cli.binaries, cli.datas, [],
              name='ahk-decompiler-cli', console=True, debug=False, strip=False,
              upx=False, version=version_file)
