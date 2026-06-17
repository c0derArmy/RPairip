import os
import re
import shutil
import zipfile
import tempfile
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import List, Optional, Tuple, Dict, Set
from .utils import (
    setup_logger, run_command, run_command_stream, find_tool_path, ensure_dir,
    safe_delete, Color, CRC32Fixer, ensure_jar
)


class APKAnalyzer:
    def __init__(self, apk_path: str, output_dir: str, logger=None, use_apktool=False):
        self.apk_path = os.path.abspath(apk_path)
        self.apk_name = os.path.splitext(os.path.basename(apk_path))[0]
        self.output_dir = os.path.abspath(output_dir)
        self.logger = logger or setup_logger()
        self.decompile_dir = os.path.join(self.output_dir, 'decompiled')
        self.use_apktool = use_apktool
        self.smali_dirs = []
        self.lib_dir = None
        self.assets_dir = None
        self.res_dir = None
        self.manifest_path = None
        self.manifest_tree = None
        self.manifest_root = None
        self.package_name = None
        self.dex_files = []
        self.native_libs = {}
        self.certificate_pins = []
        self.api_endpoints = []
        self.all_smali_files = []
        self.billing_imports = []
        self.third_party_payment = []

        self.apk_info = {
            'size_bytes': 0,
            'package_name': '',
            'version_name': '',
            'version_code': 0,
            'min_sdk': 0,
            'target_sdk': 0,
            'permissions': [],
            'activities': [],
            'services': [],
            'receivers': [],
            'providers': [],
            'has_pairip': False,
            'has_billing': False,
            'native_libs': [],
            'dex_count': 0,
        }

    def analyze(self) -> bool:
        self.logger.info(f"[*] Analyzing APK: {self.apk_path}")
        if not os.path.isfile(self.apk_path):
            self.logger.error(f"APK not found: {self.apk_path}")
            return False

        self.apk_info['size_bytes'] = os.path.getsize(self.apk_path)
        self.logger.info(f"    Size: {self.apk_info['size_bytes'] / 1024 / 1024:.1f} MB")

        if not self._decompile():
            self.logger.warning("    Decompilation may be partial; continuing...")

        self._parse_manifest()
        self._walk_all()

        self.logger.info(f"    Package: {self.apk_info['package_name']}")
        self.logger.info(f"    Version: {self.apk_info['version_name']} ({self.apk_info['version_code']})")
        self.logger.info(f"    SDK: {self.apk_info['min_sdk']} -> {self.apk_info['target_sdk']}")
        if self.apk_info['native_libs']:
            self.logger.info(f"    Native libs: {len(self.apk_info['native_libs'])} found")
        self.logger.info(f"    Smali files: {len(self.all_smali_files)}")
        self.logger.info(f"    DEX files: {len(self.dex_files)}")

        return True

    def _decompile(self) -> bool:
        ensure_dir(self.output_dir)
        safe_delete(self.decompile_dir)

        if self.use_apktool:
            return self._decompile_apktool()
        return self._decompile_apkeditor()

    def _decompile_apkeditor(self) -> bool:
        editor = ensure_jar('APKEditor.jar')
        if not editor:
            self.logger.warning("APKEditor.jar not available, falling back to apktool")
            return self._decompile_apktool()

        self.logger.info("[*] Decompiling with APKEditor...")
        ret, out, err = run_command_stream(
            ['java', '-jar', editor, 'd', '-i', self.apk_path, '-o', self.decompile_dir, '-f'],
            timeout=300, prefix=f"  {Color.CYAN}",
            show_lines=[r'Baksmali:', r'Saved to']
        )
        if ret == 0 and os.path.isdir(self.decompile_dir):
            self.logger.info(f"    Decompiled to: {self.decompile_dir}")
            return True

        self.logger.warning("    APKEditor decompile failed, falling back to apktool")
        return self._decompile_apktool()

    def _decompile_apktool(self) -> bool:
        apktool_raw = find_tool_path('apktool')
        if not apktool_raw:
            jar = ensure_jar('APKTool.jar')
            if not jar:
                self.logger.error("apktool not found and APKTool.jar unavailable. Cannot decompile.")
                return self._manual_extract()
            apktool_raw = f"java -jar {jar}"

        apktool = shutil.which('apktool') or (f"java -jar {ensure_jar('APKTool.jar')}" if ensure_jar('APKTool.jar') else None)
        if not apktool or apktool.startswith('java'):
            jar = ensure_jar('APKTool.jar')
            if not jar:
                return self._manual_extract()
            self.logger.info(f"[*] Decompiling with APKTool.jar...")
            ret, out, err = run_command(
                ['java', '-jar', jar, 'd', '-f', '-o', self.decompile_dir, self.apk_path],
                timeout=300
            )
            if ret == 0:
                self.logger.info(f"    Decompiled to: {self.decompile_dir}")
                return True
            self.logger.warning(f"    APKTool.jar decompile failed: {err[:200]}")
            return self._manual_extract()

        self.logger.info(f"[*] Decompiling with apktool...")
        ret, out, err = run_command(
            [apktool, 'd', '-f', '-o', self.decompile_dir, self.apk_path],
            timeout=300
        )
        if ret == 0:
            self.logger.info(f"    Decompiled to: {self.decompile_dir}")
            return True

        self.logger.warning(f"    apktool decompile failed, trying --no-src...")
        safe_delete(self.decompile_dir)
        ret, out, err = run_command(
            [apktool, 'd', '-f', '--no-src', '-o', self.decompile_dir, self.apk_path],
            timeout=300
        )
        if ret == 0:
            self.logger.info(f"    Decompiled to: {self.decompile_dir}")
            return True

        self.logger.error(f"    apktool decompile failed: {err[:200]}")
        return self._manual_extract()

    def _manual_extract(self) -> bool:
        try:
            ensure_dir(self.decompile_dir)
            with zipfile.ZipFile(self.apk_path, 'r') as zf:
                zf.extractall(self.decompile_dir)
            self.logger.info(f"    Manually extracted to: {self.decompile_dir}")
            return True
        except Exception as e:
            self.logger.error(f"    Manual extraction failed: {e}")
            return False

    def _parse_manifest(self):
        manifest_candidates = [
            os.path.join(self.decompile_dir, 'AndroidManifest.xml'),
            os.path.join(self.decompile_dir, 'AndroidManifest.xml.arsc'),
        ]
        for mf in manifest_candidates:
            if os.path.isfile(mf):
                self.manifest_path = mf
                break

        if not self.manifest_path:
            self.logger.warning("    AndroidManifest.xml not found in decompiled output")
            return

        try:
            with zipfile.ZipFile(self.apk_path, 'r') as zf:
                if 'AndroidManifest.xml' in zf.namelist():
                    raw = zf.read('AndroidManifest.xml')
        except Exception:
            raw = None

        try:
            if self.manifest_path and os.path.isfile(self.manifest_path):
                with open(self.manifest_path, 'rb') as f:
                    data = f.read()
                if data.startswith(b'<?xml'):
                    self.manifest_tree = ET.fromstring(data)
                else:
                    try:
                        from pyaxmlparser import APK as PyAXMLAPK
                        apk = PyAXMLAPK(self.apk_path)
                        self.manifest_tree = ET.fromstring(apk.get_android_manifest_xml().encode('utf-8'))
                        self.package_name = apk.package
                        self.apk_info['package_name'] = apk.package
                        self.apk_info['version_name'] = apk.version_name
                        self.apk_info['version_code'] = apk.version_code
                        self.apk_info['min_sdk'] = apk.min_sdk_version or 0
                        self.apk_info['target_sdk'] = apk.target_sdk_version or 0
                    except ImportError:
                        self.logger.warning("    pyaxmlparser not available, using regex fallback")
                        self._parse_manifest_regex(data)
            self._extract_manifest_info()
        except Exception as e:
            self.logger.debug(f"    Manifest parse error: {e}")
            self._parse_manifest_raw()

    def _parse_manifest_regex(self, data: bytes):
        text = data.decode('utf-8', errors='replace')
        m = re.search(r'package="([^"]+)"', text)
        if m:
            self.package_name = m.group(1)
            self.apk_info['package_name'] = m.group(1)
        m = re.search(r'android:versionName="([^"]*)"', text)
        if m:
            self.apk_info['version_name'] = m.group(1)
        m = re.search(r'android:versionCode="(\d+)"', text)
        if m:
            self.apk_info['version_code'] = int(m.group(1))
        m = re.search(r'android:minSdkVersion="?\'?(\d+)"?\'?', text)
        if m:
            self.apk_info['min_sdk'] = int(m.group(1))
        m = re.search(r'android:targetSdkVersion="?\'?(\d+)"?\'?', text)
        if m:
            self.apk_info['target_sdk'] = int(m.group(1))

    def _extract_manifest_info(self):
        if not self.manifest_tree:
            return
        ns = {'android': 'http://schemas.android.com/apk/res/android'}
        root = self.manifest_tree
        if not self.apk_info['package_name']:
            self.apk_info['package_name'] = root.get('package', '')
            self.package_name = root.get('package', '')
        self.apk_info['version_name'] = root.get('{http://schemas.android.com/apk/res/android}versionName', '')
        vc = root.get('{http://schemas.android.com/apk/res/android}versionCode', '0')
        try:
            self.apk_info['version_code'] = int(vc)
        except ValueError:
            self.apk_info['version_code'] = 0

        for perm in root.findall('.//uses-permission', ns) or root.findall('.//uses-permission'):
            name = perm.get('{http://schemas.android.com/apk/res/android}name', '') or perm.get('android:name', '')
            if name:
                self.apk_info['permissions'].append(name)

        for activity in root.findall('.//activity', ns) or root.findall('.//activity'):
            name = activity.get('{http://schemas.android.com/apk/res/android}name', '') or activity.get('android:name', '')
            if name:
                self.apk_info['activities'].append(name)

        for svc in root.findall('.//service', ns) or root.findall('.//service'):
            name = svc.get('{http://schemas.android.com/apk/res/android}name', '') or svc.get('android:name', '')
            if name:
                self.apk_info['services'].append(name)

        for rcvr in root.findall('.//receiver', ns) or root.findall('.//receiver'):
            name = rcvr.get('{http://schemas.android.com/apk/res/android}name', '') or rcvr.get('android:name', '')
            if name:
                self.apk_info['receivers'].append(name)

        for prov in root.findall('.//provider', ns) or root.findall('.//provider'):
            name = prov.get('{http://schemas.android.com/apk/res/android}name', '') or prov.get('android:name', '')
            if name:
                self.apk_info['providers'].append(name)

        uses_sdk = root.find('.//uses-sdk')
        if uses_sdk is not None:
            if not self.apk_info['min_sdk']:
                ms = uses_sdk.get('{http://schemas.android.com/apk/res/android}minSdkVersion', '0')
                try:
                    self.apk_info['min_sdk'] = int(ms)
                except ValueError:
                    pass
            if not self.apk_info['target_sdk']:
                ts = uses_sdk.get('{http://schemas.android.com/apk/res/android}targetSdkVersion', '0')
                try:
                    self.apk_info['target_sdk'] = int(ts)
                except ValueError:
                    pass

    def _parse_manifest_raw(self):
        try:
            with open(self.manifest_path, 'rb') as f:
                data = f.read()
        except Exception:
            return
        m = re.search(rb'package="([^"]+)"', data)
        if m:
            self.package_name = m.group(1).decode('utf-8', errors='replace')
            self.apk_info['package_name'] = self.package_name
        m = re.search(rb'android:versionName="([^"]*)"', data)
        if m:
            self.apk_info['version_name'] = m.group(1).decode('utf-8', errors='replace')
        m = re.search(rb'android:versionCode="(\d+)"', data)
        if m:
            self.apk_info['version_code'] = int(m.group(1))

    def _walk_all(self):
        for root, dirs, files in os.walk(self.decompile_dir):
            bn = os.path.basename(root)
            if bn.startswith('smali') and root not in self.smali_dirs:
                self.smali_dirs.append(root)
            if bn == 'lib' and not self.lib_dir:
                self.lib_dir = root
            if bn == 'assets' and not self.assets_dir:
                self.assets_dir = root
            if bn == 'res' and not self.res_dir:
                self.res_dir = root
            for f in files:
                if f.endswith('.smali'):
                    self.all_smali_files.append(os.path.join(root, f))
                elif f.endswith('.so') and self.lib_dir and root.startswith(self.lib_dir):
                    arch = os.path.basename(os.path.dirname(root)) if root != self.lib_dir else 'unknown'
                    if f not in self.native_libs:
                        self.native_libs[f] = {
                            'path': os.path.join(root, f),
                            'arch': arch,
                            'size': os.path.getsize(os.path.join(root, f)),
                        }
                        self.apk_info['native_libs'].append(f)
                elif f.endswith('.dex'):
                    self.dex_files.append(os.path.join(root, f))
        if not self.dex_files:
            dex_path = os.path.join(self.decompile_dir, 'classes.dex')
            if os.path.isfile(dex_path):
                self.dex_files.append(dex_path)
            i = 2
            while True:
                dex_path = os.path.join(self.decompile_dir, f'classes{i}.dex')
                if os.path.isfile(dex_path):
                    self.dex_files.append(dex_path)
                    i += 1
                else:
                    break
            dex_path = os.path.join(self.decompile_dir, 'classes.dex')
            if os.path.isfile(dex_path):
                self.dex_files.append(dex_path)
            i = 2
            while True:
                dex_path = os.path.join(self.decompile_dir, f'classes{i}.dex')
                if os.path.isfile(dex_path):
                    self.dex_files.append(dex_path)
                    i += 1
                else:
                    break
        self.apk_info['dex_count'] = len(self.dex_files)

    def get_smali_content(self, smali_path: str) -> Optional[str]:
        path = os.path.join(self.decompile_dir, smali_path) if not os.path.isabs(smali_path) else smali_path
        if os.path.isfile(path):
            try:
                with open(path, 'r', encoding='utf-8', errors='replace') as f:
                    return f.read()
            except Exception:
                return None
        return None

    def write_smali_file(self, smali_path: str, content: str) -> bool:
        path = os.path.join(self.decompile_dir, smali_path) if not os.path.isabs(smali_path) else smali_path
        try:
            ensure_dir(os.path.dirname(path))
            with open(path, 'w', encoding='utf-8') as f:
                f.write(content)
            return True
        except Exception as e:
            self.logger.error(f"Failed to write {path}: {e}")
            return False

    def delete_file(self, rel_path: str) -> bool:
        path = os.path.join(self.decompile_dir, rel_path)
        try:
            if os.path.isfile(path):
                os.remove(path)
                return True
            elif os.path.isdir(path):
                shutil.rmtree(path, ignore_errors=True)
                return True
        except Exception:
            pass
        return False

    def delete_directory(self, rel_path: str) -> bool:
        return self.delete_file(rel_path)

    def find_smali_class(self, class_name: str) -> Optional[str]:
        smali_path = class_name.replace('.', '/') + '.smali'
        for sd in self.smali_dirs:
            path = os.path.join(sd, smali_path)
            if os.path.isfile(path):
                return path
        for root, dirs, files in os.walk(self.decompile_dir):
            for f in files:
                if f.endswith('.smali'):
                    path = os.path.join(root, f)
                    try:
                        with open(path, 'rb') as fh:
                            header = fh.read(4096)
                            if class_name.encode() in header:
                                return path
                    except Exception:
                        pass
        return None

    def find_method_in_smali(self, smali_content: str, method_name: str) -> Optional[Tuple[int, str]]:
        pattern = re.compile(
            rf'\.method\s+.*\s+{re.escape(method_name)}\s*\(',
            re.MULTILINE
        )
        match = pattern.search(smali_content)
        if match:
            start = match.start()
            end_method = smali_content.find('.end method', start)
            if end_method != -1:
                return (start, smali_content[start:end_method + len('.end method')])
        return None

    def get_resources(self):
        resources = {}
        if self.res_dir:
            for root, dirs, files in os.walk(self.res_dir):
                for f in files:
                    path = os.path.join(root, f)
                    rel = os.path.relpath(path, self.res_dir)
                    resources[rel] = path
        return resources

    def cleanup(self):
        safe_delete(self.decompile_dir)
