import os
import re
import shutil
import tempfile
import zipfile
import zlib
import struct
from typing import Optional
from .utils import (
    setup_logger, run_command, run_command_stream, find_tool_path, ensure_dir,
    safe_delete, CRC32Fixer, generate_debug_keystore, Color,
    ensure_jar
)


class APKBuilder:
    def __init__(self, analyzer, output_apk: str, logger=None, keystore: Optional[str] = None, use_apktool=False):
        self.analyzer = analyzer
        self.output_apk = os.path.abspath(output_apk)
        self.logger = logger or setup_logger()
        self.keystore = keystore
        self.use_apktool = use_apktool
        self.temp_files = []
        self.crc_fixer = CRC32Fixer(self.logger)

    def build(self) -> Optional[str]:
        self.logger.info(f"\n{'=' * 60}")
        self.logger.info(f"[*] Building patched APK...")
        self.logger.info(f"{'=' * 60}")

        aligned_apk = self._build_apk()
        if not aligned_apk or not os.path.isfile(aligned_apk):
            self.logger.error("Failed to build APK")
            return None

        signed_apk = self._sign_apk(aligned_apk)
        if not signed_apk or not os.path.isfile(signed_apk):
            self.logger.warning("Signing failed, trying alternative method...")
            signed_apk = self._sign_apk_jarsigner(aligned_apk)
            if not signed_apk:
                self.logger.warning("All signing methods failed - will provide unsigned APK")
                signed_apk = aligned_apk

        if signed_apk != self.output_apk:
            try:
                ensure_dir(os.path.dirname(self.output_apk))
                shutil.copy2(signed_apk, self.output_apk)
            except Exception as e:
                self.logger.error(f"Failed to copy APK to output: {e}")
                return signed_apk

        zipaligned = self._zipalign(self.output_apk)
        if zipaligned:
            self.logger.info(f"[+] Final output: {self.output_apk}")
            size_mb = os.path.getsize(self.output_apk) / (1024 * 1024)
            self.logger.info(f"    Size: {size_mb:.1f} MB")

            self._make_installer_script()
            return self.output_apk

        self.logger.info(f"[+] Output (not zipaligned): {self.output_apk}")
        return self.output_apk

    def _build_apk(self) -> Optional[str]:
        if self.use_apktool:
            return self._build_apk_apktool()

        editor = ensure_jar('APKEditor.jar')
        if editor:
            return self._build_apk_apkeditor(editor)
        return self._build_apk_apktool()

    def _build_apk_apkeditor(self, editor_jar: str) -> Optional[str]:
        tmp_out = os.path.join(self.analyzer.output_dir, f"{self.analyzer.apk_name}_unsigned.apk")
        self.logger.info(f"[*] Rebuilding with APKEditor...")
        ret, out, err = run_command_stream(
            ['java', '-jar', editor_jar, 'b', '-i', self.analyzer.decompile_dir, '-o', tmp_out, '-f'],
            timeout=300, prefix=f"  {Color.DIM}",
            show_lines=[r'Smali<', r'Cached:', r'Saved to']
        )
        if ret == 0 and os.path.isfile(tmp_out):
            self.logger.info(f"    Rebuilt APK: {tmp_out} ({os.path.getsize(tmp_out) / 1024 / 1024:.1f} MB)")
            self.logger.info(f"[*] Stripping old signatures from rebuilt APK...")
            self._strip_old_signatures(tmp_out)
            self.logger.info(f"[*] Fixing DEX CRCs in rebuilt APK...")
            self.crc_fixer.fix_all_dex_in_apk(tmp_out)
            return tmp_out

        self.logger.warning("    APKEditor build failed, falling back to apktool")
        return self._build_apk_apktool()

    def _build_apk_apktool(self) -> Optional[str]:
        tmp_out = os.path.join(self.analyzer.output_dir, f"{self.analyzer.apk_name}_unsigned.apk")
        apktool = find_tool_path('apktool')
        if apktool:
            cmd = [apktool, 'b', '-o', tmp_out, self.analyzer.decompile_dir]
        else:
            jar = ensure_jar('APKTool.jar')
            if not jar:
                self.logger.error("apktool not found for rebuilding!")
                return self._build_apk_zip()
            cmd = ['java', '-jar', jar, 'b', '-o', tmp_out, self.analyzer.decompile_dir]

        self.logger.info(f"[*] Rebuilding with apktool...")
        ret, out, err = run_command_stream(cmd, timeout=300, prefix=f"  {Color.DIM}",
                                           show_lines=[r'Building', r'ERROR', r'Finished'])  

        if ret != 0:
            self.logger.warning(f"    apktool build failed: {err[:200]}")
            self.logger.info("[*] Trying manual ZIP build as fallback...")
            return self._build_apk_zip()

        if os.path.isfile(tmp_out):
            self.logger.info(f"    Rebuilt APK: {tmp_out} ({os.path.getsize(tmp_out) / 1024 / 1024:.1f} MB)")
            self.logger.info(f"[*] Stripping old signatures from rebuilt APK...")
            self._strip_old_signatures(tmp_out)
            self.logger.info(f"[*] Fixing DEX CRCs in rebuilt APK...")
            self.crc_fixer.fix_all_dex_in_apk(tmp_out)
            return tmp_out
        return None

    def _build_apk_zip(self) -> Optional[str]:
        self.logger.info("[*] Building APK via ZIP (manual)...")
        try:
            tmp_out = os.path.join(self.analyzer.output_dir, f"{self.analyzer.apk_name}_unsigned.apk")
            ensure_dir(os.path.dirname(tmp_out))

            with zipfile.ZipFile(tmp_out, 'w', zipfile.ZIP_DEFLATED) as zf:
                decompile_dir = self.analyzer.decompile_dir
                for root, dirs, files in os.walk(decompile_dir):
                    for f in files:
                        file_path = os.path.join(root, f)
                        arcname = os.path.relpath(file_path, decompile_dir)
                        zf.write(file_path, arcname)

            self.logger.info(f"    Manual ZIP APK: {tmp_out}")
            return tmp_out
        except Exception as e:
            self.logger.error(f"    Manual ZIP build failed: {e}")
            return None

    def _strip_old_signatures(self, apk_path: str) -> bool:
        try:
            tmp = apk_path + '.tmp'
            kept = 0
            removed = 0
            with zipfile.ZipFile(apk_path, 'r') as zin:
                with zipfile.ZipFile(tmp, 'w', zipfile.ZIP_DEFLATED) as zout:
                    for item in zin.infolist():
                        name = item.filename
                        if name.startswith('META-INF/'):
                            base = os.path.basename(name)
                            if (base == 'MANIFEST.MF' or base.endswith('.SF') or
                                base.endswith('.RSA') or base.endswith('.DSA') or
                                base.endswith('.EC') or base == 'SIGNATURE'):
                                removed += 1
                                continue
                        kept += 1
                        zout.writestr(item, zin.read(name))
            os.replace(tmp, apk_path)
            if removed > 0:
                self.logger.debug(f"    Removed {removed} old signature files from META-INF")
            return True
        except Exception as e:
            self.logger.warning(f"    Failed to strip old signatures: {e}")
            return False

    def _sign_apk(self, apk_path: str) -> Optional[str]:
        apksigner = find_tool_path('apksigner')
        if apksigner:
            return self._sign_apk_apksigner(apk_path)

        uber = find_tool_path('uber-apk-signer.jar')
        if not uber:
            uber_paths = [
                '/usr/local/bin/uber-apk-signer.jar',
                '/usr/share/java/uber-apk-signer.jar',
                os.path.expanduser('~/.local/share/uber-apk-signer.jar'),
            ]
            for up in uber_paths:
                if os.path.isfile(up):
                    uber = up
                    break

        if uber:
            return self._sign_apk_uber(apk_path, uber)

        self.logger.info("    apksigner/uber-apk-signer not found, using jarsigner...")
        return self._sign_apk_jarsigner(apk_path)

    def _sign_apk_apksigner(self, apk_path: str) -> Optional[str]:
        keystore = self._get_keystore()
        if not keystore:
            return None

        signed_path = apk_path.replace('_unsigned.apk', '_signed.apk')
        cmd = [
            find_tool_path('apksigner'), 'sign',
            '--ks', keystore,
            '--ks-pass', 'pass:android',
            '--ks-key-alias', 'androiddebugkey',
            '--out', signed_path,
            apk_path
        ]
        self.logger.info(f"[*] Signing with apksigner...")
        ret, out, err = run_command(cmd, timeout=60)
        if ret == 0:
            self.logger.info(f"    Signed APK: {signed_path}")
            return signed_path
        self.logger.warning(f"    apksigner signing failed: {err[:100]}")
        return None

    def _sign_apk_uber(self, apk_path: str, uber_path: str) -> Optional[str]:
        signed_path = apk_path.replace('_unsigned.apk', '_signed.apk')
        cmd = ['java', '-jar', uber_path, '--sign', '--out', signed_path, apk_path]
        self.logger.info(f"[*] Signing with uber-apk-signer...")
        ret, out, err = run_command(cmd, timeout=60)
        if ret == 0:
            self.logger.info(f"    Signed: {signed_path}")
            return signed_path
        return None

    def _sign_apk_jarsigner(self, apk_path: str) -> Optional[str]:
        keystore = self._get_keystore()
        if not keystore:
            return None

        signed_path = apk_path.replace('_unsigned.apk', '_jarsigned.apk')
        try:
            shutil.copy2(apk_path, signed_path)
        except Exception:
            return None

        jarsigner = find_tool_path('jarsigner')
        if not jarsigner:
            self.logger.error("jarsigner not found!")
            return None

        cmd = [
            jarsigner, '-sigalg', 'SHA256withRSA',
            '-digestalg', 'SHA-256',
            '-keystore', keystore,
            '-storepass', 'android',
            '-keypass', 'android',
            signed_path, 'androiddebugkey'
        ]
        self.logger.info(f"[*] Signing with jarsigner...")
        ret, out, err = run_command(cmd, timeout=60)
        if ret == 0:
            self.logger.info(f"    Signed APK: {signed_path}")
            return signed_path
        self.logger.warning(f"    jarsigner signing failed: {err[:200]}")
        return None

    def _get_keystore(self) -> Optional[str]:
        if self.keystore and os.path.isfile(self.keystore):
            return self.keystore

        default_keystore = os.path.expanduser('~/.android/debug.keystore')
        if os.path.isfile(default_keystore):
            return default_keystore

        self.logger.info("[*] Generating debug keystore...")
        if generate_debug_keystore(default_keystore):
            return default_keystore

        tmp_keystore = os.path.join(self.analyzer.output_dir, 'debug.keystore')
        if generate_debug_keystore(tmp_keystore):
            self.keystore = tmp_keystore
            return tmp_keystore

        self.logger.error("Failed to create debug keystore!")
        return None

    def _zipalign(self, apk_path: str) -> bool:
        zipalign = find_tool_path('zipalign')
        if not zipalign:
            self.logger.info("    zipalign not found, trying Python alignment...")
            return self._zipalign_python(apk_path)

        aligned_path = apk_path + '.aligned'
        cmd = [zipalign, '-f', '-p', '4', apk_path, aligned_path]
        self.logger.info(f"[*] Zip-aligning APK...")
        ret, out, err = run_command(cmd, timeout=60)
        if ret == 0 and os.path.isfile(aligned_path):
            shutil.move(aligned_path, apk_path)
            self.logger.info(f"    Aligned: {apk_path}")
            return True
        self.logger.warning("    zipalign failed, trying Python alignment...")
        return self._zipalign_python(apk_path)

    def _zipalign_python(self, apk_path: str) -> bool:
        try:
            tmp_path = apk_path + '.tmp'
            with zipfile.ZipFile(apk_path, 'r') as zin:
                with zipfile.ZipFile(tmp_path, 'w', zipfile.ZIP_STORED) as zout:
                    for item in zin.infolist():
                        data = zin.read(item.filename)
                        if not item.filename.endswith('/'):
                            extra_padding = (4 - (len(data) % 4)) % 4
                            if extra_padding > 0:
                                data += b'\x00' * extra_padding
                        zout.writestr(item, data)

            os.replace(tmp_path, apk_path)
            self.logger.info(f"    Python zip-aligned: {apk_path}")
            return True
        except Exception as e:
            self.logger.warning(f"    Python zipalign failed: {e}")
            return True

    def _make_installer_script(self):
        script_path = os.path.join(self.analyzer.output_dir, 'install.sh')
        try:
            with open(script_path, 'w') as f:
                f.write(f'''#!/bin/bash
# Install patched APK
# Generated by PairIPAutoPatcher
APK="{self.output_apk}"
PACKAGE="{self.analyzer.apk_info.get('package_name', 'unknown')}"

echo "[*] Installing patched APK..."
if command -v adb &> /dev/null; then
    adb install -r "$APK" 2>/dev/null || adb install "$APK"
    echo "[*] Uninstalling original (if needed): adb uninstall $PACKAGE"
    echo "[*] Done"
else
    echo "adb not found. Install manually:"
    echo "  {self.output_apk}"
fi
''')
            os.chmod(script_path, 0o755)
            self.logger.info(f"    Install script: {script_path}")
        except Exception:
            pass
