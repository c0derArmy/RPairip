import os
import re
import shutil
from typing import List, Dict, Optional, Tuple
from .utils import setup_logger, run_command, ensure_dir, Color


class PairIPDetector:
    def __init__(self, analyzer, logger=None):
        self.analyzer = analyzer
        self.logger = logger or setup_logger()
        self.findings = {
            'libpairipcore': [],
            'pairip_manifest': False,
            'pairip_class_references': [],
            'pairip_smali_dirs': [],
            'executeVM_references': [],
            'pairip_assets': [],
            'signature_checks': [],
            'frida_detection': [],
            'gdb_detection': [],
            'anti_tamper': [],
            'pairip_dex': [],
            'pairip_xml': [],
            'other_pairip': [],
        }

    def detect(self) -> Dict:
        self.logger.info(f"[*] Scanning for PairIP protection...")
        self._scan_native_libs()
        self._scan_manifest()
        self._scan_xml()
        self._scan_smali_code()
        self._scan_assets()
        self._scan_dex_entries()
        self._scan_anti_tamper()
        self._scan_anti_debug()
        self._summarize()
        self.logger.info(f"    PairIP findings: {self.findings['libpairipcore'] and 'YES'} | smali files: {len(self.findings['pairip_smali_dirs'])} | assets: {len(self.findings['pairip_assets'])}")
        return self.findings

    def _scan_native_libs(self):
        # Name-based patterns (high confidence)
        name_patterns = ['libpairip', 'libexecutor', 'lib_pairip', 'pairipcore']
        # Content-based patterns only use Java class paths (very unlikely false positives)
        content_patterns = ['com/pairip/', 'Lcom/pairip/', 'VMRunner', 'VmDecryptor']

        for lib_name, info in self.analyzer.native_libs.items():
            lib_lower = lib_name.lower()
            so_path = info['path']

            name_match = any(lib_lower.startswith(p.lower()) or p.lower() in lib_lower
                             for p in name_patterns)

            content_match = False
            if os.path.isfile(so_path):
                try:
                    ret, out, err = run_command(
                        ['strings', so_path], timeout=10
                    )
                    if ret == 0:
                        so_strings = out
                        for art in content_patterns:
                            if art in so_strings:
                                content_match = True
                                break
                except Exception:
                    pass

            if name_match or content_match:
                if info not in self.findings['libpairipcore']:
                    self.findings['libpairipcore'].append(info)
                    self.logger.debug(f"  [PAIRIP] Found PairIP native lib: {lib_name} ({info['arch']})")

    def _scan_manifest(self):
        manifest_path = self.analyzer.manifest_path
        if not manifest_path or not os.path.isfile(manifest_path):
            return
        try:
            with open(manifest_path, 'rb') as f:
                data = f.read()
            text = data.decode('utf-8', errors='replace')

            if 'com.pairip.application.Application' in text:
                self.findings['pairip_manifest'] = True
                self.logger.debug(f"  [PAIRIP] Found com.pairip.application.Application in manifest")

            for pattern in [
                r'com\.pairip\.\w+',
                r'pairip',
                r'PAIRIP',
            ]:
                for m in re.finditer(pattern, text, re.IGNORECASE):
                    ctx_start = max(0, m.start() - 60)
                    ctx_end = min(len(text), m.end() + 60)
                    context = text[ctx_start:ctx_end].replace('\n', ' ').strip()
                    if m.group().lower() not in context.lower():
                        continue
                    entry = {'match': m.group(), 'context': context}
                    if entry not in self.findings['other_pairip']:
                        self.findings['other_pairip'].append(entry)
                        if m.group().lower() != 'pairip':
                            self.logger.debug(f"  [PAIRIP] Manifest reference: {m.group()}")

            if 'pairip' in text.lower() and not self.findings['pairip_manifest']:
                matches = re.findall(r'android:name="([^"]*pairip[^"]*)"', text, re.IGNORECASE)
                for m in matches:
                    self.findings['pairip_manifest'] = True
                    self.logger.debug(f"  [PAIRIP] Found PairIP component: {m}")

        except Exception as e:
            self.logger.debug(f"    Error scanning manifest: {e}")

    def _scan_xml(self):
        xml_patterns = [
            (r'com\.pairip\.\S+', 'PairIP class reference'),
            (r'pairip', 'PairIP keyword'),
            (r'executeVM', 'executeVM reference'),
            (r'libpairipcore', 'libpairipcore reference'),
            (r'PairIP', 'PairIP keyword'),
        ]
        for root, dirs, files in os.walk(self.analyzer.decompile_dir):
            for f in files:
                if not f.endswith('.xml'):
                    continue
                path = os.path.join(root, f)
                rel = os.path.relpath(path, self.analyzer.decompile_dir)
                try:
                    with open(path, 'rb') as fh:
                        data = fh.read(262144)
                    text = data.decode('utf-8', errors='replace')
                    for pat, desc in xml_patterns:
                        if re.search(pat, text, re.IGNORECASE):
                            entry = {'file': rel, 'pattern': pat, 'description': desc}
                            if entry not in self.findings['pairip_xml']:
                                self.findings['pairip_xml'].append(entry)
                                self.logger.debug(f"  [PAIRIP] {desc} in XML: {rel}")
                except Exception:
                    pass

    def _scan_smali_code(self):
        pairip_patterns = [
            r'com/pairip/',
            r'Lcom/pairip/',
            r'pairip',
            r'executeVM',
            r'RegisterNatives',
            r'libpairipcore',
        ]
        for smali_file in self.analyzer.all_smali_files:
            try:
                with open(smali_file, 'rb') as f:
                    content = f.read()
                text = content.decode('utf-8', errors='replace')
                rel_path = os.path.relpath(smali_file, self.analyzer.decompile_dir)

                for pat in pairip_patterns:
                    if re.search(pat, text, re.IGNORECASE):
                        if pat == r'com/pairip/' or pat == r'Lcom/pairip/':
                            dir_part = os.path.dirname(rel_path)
                            if 'com/pairip' in dir_part.replace('\\', '/'):
                                if rel_path not in self.findings['pairip_smali_dirs'] and rel_path not in [
                                    x for sub in self.findings.values()
                                    if isinstance(sub, list) for x in sub if isinstance(x, str)
                                ]:
                                    self.findings['pairip_smali_dirs'].append(rel_path)
                                    self.logger.debug(f"  [PAIRIP] PairIP smali: {rel_path}")
                            else:
                                ref = {'file': rel_path, 'pattern': pat}
                                if ref not in self.findings['pairip_class_references']:
                                    self.findings['pairip_class_references'].append(ref)
                                    if pat not in (r'com/pairip/', r'Lcom/pairip/'):
                                        self.logger.debug(f"  [PAIRIP] Reference in {rel_path}: {pat}")

                        elif pat == 'executeVM':
                            lines = text.split('\n')
                            for i, line in enumerate(lines):
                                if 'executeVM' in line:
                                    ref = {'file': rel_path, 'line': i + 1, 'content': line.strip()}
                                    if ref not in self.findings['executeVM_references']:
                                        self.findings['executeVM_references'].append(ref)
                                        self.logger.debug(f"  [PAIRIP] executeVM in {rel_path}:{i + 1}")

                        elif pat == 'RegisterNatives':
                            if 'System.loadLibrary' in text or 'RegisterNatives' in text:
                                ref = {'file': rel_path, 'pattern': pat}
                                if ref not in self.findings['executeVM_references']:
                                    self.findings['executeVM_references'].append(ref)

                for line_no, line in enumerate(text.split('\n'), 1):
                    if 'frida' in line.lower() and ('detect' in line.lower() or 'check' in line.lower() or 'scan' in line.lower()):
                        ref = {'file': rel_path, 'line': line_no, 'content': line.strip()}
                        if ref not in self.findings['frida_detection']:
                            self.findings['frida_detection'].append(ref)
                            self.logger.debug(f"  [ANTI-FRIDA] Possible detection in {rel_path}:{line_no}")

                    if ('gdb' in line.lower() or 'ptrace' in line.lower() or 'TracerPid' in line) and (
                        'detect' in line.lower() or 'check' in line.lower() or 'read' in line.lower()
                    ):
                        ref = {'file': rel_path, 'line': line_no, 'content': line.strip()}
                        if ref not in self.findings['gdb_detection']:
                            self.findings['gdb_detection'].append(ref)
                            self.logger.debug(f"  [ANTI-GDB] Possible detection in {rel_path}:{line_no}")

            except Exception as e:
                self.logger.debug(f"    Error scanning {smali_file}: {e}")

    def _scan_assets(self):
        if not self.analyzer.assets_dir or not os.path.isdir(self.analyzer.assets_dir):
            return
        for root, dirs, files in os.walk(self.analyzer.assets_dir):
            for f in files:
                path = os.path.join(root, f)
                rel = os.path.relpath(path, self.analyzer.decompile_dir)
                if f.endswith('.dex') or f.endswith('.jar') or f.endswith('.apk'):
                    self.findings['pairip_assets'].append(rel)
                    self.logger.debug(f"  [PAIRIP] Executable in assets: {rel}")
                fname_lower = f.lower()
                if 'pairip' in fname_lower or 'vm' in fname_lower or 'bytecode' in fname_lower:
                    self.findings['pairip_assets'].append(rel)
                    self.logger.debug(f"  [PAIRIP] Possible VM bytecode: {rel}")

    def _scan_dex_entries(self):
        if not self.analyzer.decompile_dir:
            return
        for root, dirs, files in os.walk(self.analyzer.decompile_dir):
            for f in files:
                if f.endswith('.dex'):
                    path = os.path.join(root, f)
                    rel = os.path.relpath(path, self.analyzer.decompile_dir)
                    if 'pairip' in f.lower() or 'protected' in f.lower() or 'encrypted' in f.lower():
                        self.findings['pairip_dex'].append(rel)
                        self.logger.debug(f"  [PAIRIP] Protected DEX: {rel}")

    def _scan_anti_tamper(self):
        patterns = [
            (r'apkSignature', 'APK signature check'),
            (r'signature.*check', 'Signature verification'),
            (r'getPackageSignature', 'Package signature verification'),
            (r'signature.*verify', 'Signature verification'),
            (r'hash.*check', 'Hash integrity check'),
            (r'integrity.*check', 'Integrity check'),
            (r'checksum', 'Checksum verification'),
            (r'cr[3c].*check', 'CRC check'),
            (r'cert.*sniff', 'Certificate check'),
        ]
        for smali_file in self.analyzer.all_smali_files:
            try:
                with open(smali_file, 'rb') as f:
                    content = f.read()
                text = content.decode('utf-8', errors='replace')
                rel_path = os.path.relpath(smali_file, self.analyzer.decompile_dir)
                for pat, desc in patterns:
                    if re.search(pat, text, re.IGNORECASE):
                        ref = {'file': rel_path, 'description': desc}
                        if ref not in self.findings['signature_checks']:
                            self.findings['signature_checks'].append(ref)
                            self.logger.debug(f"  [SIGNATURE] {desc} in {rel_path}")
            except Exception:
                pass

    def _scan_anti_debug(self):
        debug_patterns = [
            (r'android\.os\.Debug', 'Debug class check'),
            (r'isDebuggerConnected', 'Debugger connected check'),
            (r'waitForDebugger', 'Wait for debugger'),
            (r'ptrace', 'Ptrace check'),
            (r'TracerPid', 'Tracer PID check'),
            (r'android:debuggable="true"', 'Debuggable flag'),
            (r'debuggable', 'Debuggable'),
            (r'ro\.debuggable', 'System property debug check'),
            (r'ro\.secure', 'Root secure check'),
        ]
        for smali_file in self.analyzer.all_smali_files:
            try:
                with open(smali_file, 'rb') as f:
                    content = f.read()
                text = content.decode('utf-8', errors='replace')
                rel_path = os.path.relpath(smali_file, self.analyzer.decompile_dir)
                line_no = 0
                for line in text.split('\n'):
                    line_no += 1
                    for pat, desc in debug_patterns:
                        if re.search(pat, line, re.IGNORECASE):
                            ref = {'file': rel_path, 'line': line_no, 'description': desc, 'content': line.strip()}
                            if ref not in self.findings['gdb_detection']:
                                self.findings['gdb_detection'].append(ref)
                                self.logger.debug(f"  [ANTI-DEBUG] {desc} in {rel_path}:{line_no}")
            except Exception:
                pass

    def has_pairip(self) -> bool:
        return bool(
            self.findings['libpairipcore'] or
            self.findings['pairip_manifest'] or
            self.findings['pairip_smali_dirs'] or
            self.findings['pairip_assets'] or
            self.findings['executeVM_references']
        )

    def _summarize(self):
        if self.has_pairip():
            self.logger.debug(f"  [*] PairIP DETECTED - Protection found!")
            if self.findings['libpairipcore']:
                self.logger.info(f"      libpairipcore.so: {len(self.findings['libpairipcore'])} instance(s)")
            if self.findings['pairip_manifest']:
                self.logger.info(f"      Manifest reference: YES")
            if self.findings['pairip_smali_dirs']:
                self.logger.info(f"      PairIP smali files: {len(self.findings['pairip_smali_dirs'])}")
            if self.findings['pairip_assets']:
                self.logger.info(f"      Protected assets: {len(self.findings['pairip_assets'])}")
            if self.findings['executeVM_references']:
                self.logger.info(f"      executeVM references: {len(self.findings['executeVM_references'])}")
        else:
            self.logger.debug(f"  [*] No PairIP protection detected")


class PairIPPatcher:
    def __init__(self, analyzer, findings: Dict, logger=None):
        self.analyzer = analyzer
        self.findings = findings
        self.logger = logger or setup_logger()
        self.patches_applied = []

    def patch_all(self) -> bool:
        self.logger.info(f"\n{'=' * 60}")
        self.logger.info(f"[*] Applying PairIP patches...")
        self.logger.info(f"{'=' * 60}")

        patched = False
        patched |= self._patch_manifest()
        patched |= self._patch_xml()
        patched |= self._remove_pairip_smali()
        patched |= self._remove_pairip_native_libs()
        patched |= self._remove_pairip_assets()
        patched |= self._patch_executeVM()
        patched |= self._patch_signature_checks()
        patched |= self._patch_anti_debug()
        patched |= self._patch_pairip_methods()
        patched |= self._strip_pairip_references()

        if patched:
            self.logger.info(f"[+] PairIP patching complete - {len(self.patches_applied)} patches applied")
        else:
            self.logger.info(f"[-] No PairIP patches needed or all were already applied")
        return patched

    def _patch_manifest(self) -> bool:
        manifest_path = self.analyzer.manifest_path
        if not manifest_path or not os.path.isfile(manifest_path):
            return False
        self.logger.debug(f"  [i] Manifest patching skipped - PairIP handled via stub classes")
        return False

    def _patch_xml(self) -> bool:
        self.logger.debug(f"  [i] XML patching skipped - PairIP handled via stub classes")
        return False

    def _get_base_class(self, smali_content: str) -> str:
        m = re.search(r'\.super\s+(\S+)', smali_content)
        return m.group(1) if m else 'Ljava/lang/Object;'

    def _make_stub_smali(self, class_path: str, super_class: str) -> str:
        short_name = class_path.split('/')[-1] if '/' in class_path else class_path
        return f'''.class public L{class_path};
.super {super_class}
.source "{short_name}.java"

.method public constructor <init>()V
    .locals 0
    invoke-direct {{p0}}, {super_class}-><init>()V
    return-void
.end method
'''

    def _remove_pairip_smali(self) -> bool:
        patched = False
        app_extending_pairip = []

        for root, dirs, files in os.walk(self.analyzer.decompile_dir):
            for f in files:
                if f.endswith('.smali'):
                    path = os.path.join(root, f)
                    try:
                        with open(path, 'r', encoding='utf-8', errors='replace') as fh:
                            content = fh.read()
                        if re.search(r'\.super\s+Lcom/pairip/application/Application;', content):
                            app_extending_pairip.append((path, content))
                    except Exception:
                        pass

        pairip_smali_files = []
        for root, dirs, files in os.walk(self.analyzer.decompile_dir):
            for f in files:
                if f.endswith('.smali') and '/com/pairip/' in root.replace('\\', '/') + '/':
                    pairip_smali_files.append(os.path.join(root, f))

        processed = set()
        for fpath in pairip_smali_files:
            if fpath in processed:
                continue
            processed.add(fpath)
            rel = os.path.relpath(fpath, self.analyzer.decompile_dir)
            try:
                with open(fpath, 'r', encoding='utf-8', errors='replace') as fh:
                    content = fh.read()
            except Exception:
                content = ''
            base = self._get_base_class(content) if content else 'Ljava/lang/Object;'

            if 'Application.smali' in rel and 'application' in rel:
                for app_path, app_content in app_extending_pairip:
                    new_content = app_content.replace('Lcom/pairip/application/Application;', 'Landroid/app/Application;')
                    try:
                        with open(app_path, 'w', encoding='utf-8') as fh:
                            fh.write(new_content)
                        ar = os.path.relpath(app_path, self.analyzer.decompile_dir)
                        self.logger.debug(f"  [+] Changed superclass to android/app/Application in {ar}")
                        patched = True
                    except Exception as e:
                        self.logger.warning(f"    Could not update superclass in {app_path}: {e}")
                base = 'Landroid/app/Application;'

            stub = self._make_stub_smali(rel.replace('.smali', ''), base)
            try:
                with open(fpath, 'w', encoding='utf-8') as fh:
                    fh.write(stub)
                self.logger.debug(f"  [+] Stubbed PairIP smali: {rel}")
                self.patches_applied.append({
                    'type': 'smali_stub',
                    'description': f'Replaced {rel} with no-op stub',
                    'target': rel
                })
                patched = True
            except Exception as e:
                self.logger.warning(f"    Could not stub {rel}: {e}")

        for smali_file in self.analyzer.all_smali_files:
            try:
                with open(smali_file, 'r', encoding='utf-8', errors='replace') as f:
                    content = f.read()
                rel_path = os.path.relpath(smali_file, self.analyzer.decompile_dir)
                if 'com/pairip/' in rel_path.replace('\\', '/'):
                    continue
                orig = content

                content = re.sub(r'Lcom/pairip/[a-zA-Z0-9_$]+;', 'Landroid/app/Application;', content)

                content = re.sub(
                    r'const-string\s+\w+,\s*"(?:lib)?pairip[^"]*"',
                    'const-string v0, "libc"',
                    content, flags=re.IGNORECASE
                )

                if 'loadLibrary' in content:
                    content = re.sub(
                        r'(const-string\s+\w+,\s*)"(?:lib)?pairip[^"]*"',
                        r'\1"libc"',
                        content, flags=re.IGNORECASE
                    )

                if content != orig:
                    with open(smali_file, 'w', encoding='utf-8') as f:
                        f.write(content)
                    self.logger.debug(f"  [+] Stripped PairIP references in {rel_path}")
                    patched = True
            except Exception:
                pass

        return patched

    def _remove_pairip_native_libs(self) -> bool:
        patched = False

        if self.analyzer.lib_dir and os.path.isdir(self.analyzer.lib_dir):
            detected_libs = {info['path'] for info in self.findings.get('libpairipcore', [])}
            for root, dirs, files in os.walk(self.analyzer.lib_dir):
                for f in files:
                    if not f.endswith('.so'):
                        continue
                    path = os.path.join(root, f)
                    if path not in detected_libs:
                        continue
                    arch = os.path.basename(os.path.dirname(root))
                    try:
                        bak_path = path + '.bak'
                        os.rename(path, bak_path)
                        self.logger.debug(f"  [+] Renamed PairIP lib: {f} -> {f}.bak ({arch})")
                        self.patches_applied.append({
                            'type': 'native_rename',
                            'description': f"Renamed {f} to {f}.bak ({arch})",
                            'target': os.path.relpath(path, self.analyzer.decompile_dir)
                        })
                        patched = True
                    except Exception as e:
                        self.logger.warning(f"    Could not rename {path}: {e}")

        for smali_file in self.analyzer.all_smali_files:
            try:
                with open(smali_file, 'r', encoding='utf-8', errors='replace') as f:
                    content = f.read()
                orig = content
                for prefix in pairip_so_prefixes:
                    content = re.sub(
                        rf'const-string\s+\w+,\s*"{re.escape(prefix)}[^"]*"',
                        'const-string v0, "libc"',
                        content
                    )
                if content != orig:
                    with open(smali_file, 'w', encoding='utf-8') as f:
                        f.write(content)
                    rel = os.path.relpath(smali_file, self.analyzer.decompile_dir)
                    self.logger.debug(f"  [+] Stripped PairIP lib reference in {rel}")
                    patched = True
            except Exception:
                pass

        return patched

    def _remove_pairip_assets(self) -> bool:
        patched = False
        for asset_rel in self.findings['pairip_assets']:
            asset_path = os.path.join(self.analyzer.decompile_dir, asset_rel)
            try:
                if os.path.isfile(asset_path):
                    os.remove(asset_path)
                    self.logger.debug(f"  [+] Removed PairIP asset: {asset_rel}")
                    self.patches_applied.append({
                        'type': 'asset_remove',
                        'description': f'Removed {asset_rel}',
                        'target': asset_rel
                    })
                    patched = True
                elif os.path.isdir(asset_path):
                    shutil.rmtree(asset_path, ignore_errors=True)
                    self.logger.debug(f"  [+] Removed PairIP asset directory: {asset_rel}")
                    patched = True
            except Exception as e:
                self.logger.warning(f"    Could not remove asset {asset_rel}: {e}")
        return patched

    def _patch_executeVM(self) -> bool:
        patched = False
        for ref in self.findings['executeVM_references']:
            if isinstance(ref, dict) and 'file' in ref:
                smali_path = os.path.join(self.analyzer.decompile_dir, ref['file'])
                if not os.path.isfile(smali_path):
                    continue
                try:
                    with open(smali_path, 'r', encoding='utf-8', errors='replace') as f:
                        content = f.read()

                    if 'executeVM' in content:
                        content = content.replace(
                            'Lcom/pairip/VMProtect;->executeVM()V',
                            'Landroid/app/Application;->onCreate()V'
                        )
                        content = re.sub(
                            r'invoke-.*?\{.*?\},\s*.*?->executeVM\(\)[VZ]',
                            'return-void',
                            content
                        )

                        method_match = re.search(
                            r'\.method\s+.*\bexecuteVM\b.*?\n.*?\.end\s+method',
                            content, re.DOTALL
                        )
                        if method_match:
                            indentation = '    '
                            new_method = method_match.group(0)
                            if 'V' in new_method.split('executeVM')[0].split('(')[-1] if '(' in new_method else '':
                                new_body = f'.method public static executeVM()V\n{indentation}.locals 0\n{indentation}return-void\n.end method'
                            else:
                                new_body = f'.method public static executeVM()Z\n{indentation}.locals 1\n{indentation}const/4 v0, 0x1\n{indentation}return v0\n.end method'
                            content = content.replace(method_match.group(0), new_body)
                            self.logger.debug(f"  [+] NOP'd executeVM() in {ref['file']}")

                        with open(smali_path, 'w', encoding='utf-8') as f:
                            f.write(content)
                        self.patches_applied.append({
                            'type': 'executeVM_patch',
                            'description': 'Patched executeVM() to no-op',
                            'target': ref['file']
                        })
                        patched = True
                except Exception as e:
                    self.logger.warning(f"    Error patching executeVM in {ref['file']}: {e}")

        for smali_file in self.analyzer.all_smali_files:
            try:
                with open(smali_file, 'r', encoding='utf-8', errors='replace') as f:
                    content = f.read()
                if 'RegisterNatives' in content and 'libpairipcore' in content:
                    content = re.sub(
                        r'invoke-.*?\{.*?\},\s*L.*?;->RegisterNatives.*',
                        '',
                        content
                    )
                    content = content.replace('libpairipcore', 'libutil')
                    with open(smali_file, 'w', encoding='utf-8') as f:
                        f.write(content)
                    rel = os.path.relpath(smali_file, self.analyzer.decompile_dir)
                    self.logger.debug(f"  [+] Patched RegisterNatives/libpairipcore in {rel}")
                    patched = True
            except Exception:
                pass

        return patched

    def _patch_signature_checks(self) -> bool:
        patched = False
        for ref in self.findings['signature_checks']:
            smali_path = os.path.join(self.analyzer.decompile_dir, ref['file'])
            if not os.path.isfile(smali_path):
                continue
            try:
                with open(smali_path, 'r', encoding='utf-8', errors='replace') as f:
                    content = f.read()

                sig_methods = re.findall(
                    r'\.method\s+.*\b(signature|checksum|hash|integrity|cert)\w*\b.*?\)Z\s*\n.*?\.end\s+method',
                    content, re.DOTALL | re.IGNORECASE
                )
                for sig_m in sig_methods:
                    sig_m_full = sig_m
                    if isinstance(sig_m, str) and sig_m.strip().startswith('.method'):
                        new_method = sig_m[:sig_m.index('\n')] + '\n    .locals 1\n    const/4 v0, 0x1\n    return v0\n.end method'
                        content = content.replace(sig_m, new_method)
                        self.logger.debug(f"  [+] Patched signature check in {ref['file']}")

                content = re.sub(
                    r'\.method\s+.*\b(verify|validate|check)\w*(Signature|Cert|Hash|Integrity)\w*\b.*?\)Z\s*\n.*?\.end\s+method',
                    lambda m: m.group(0).split('\n')[0] + '\n    .locals 1\n    const/4 v0, 0x1\n    return v0\n.end method',
                    content, flags=re.DOTALL | re.IGNORECASE
                )

                with open(smali_path, 'w', encoding='utf-8') as f:
                    f.write(content)
                self.patches_applied.append({
                    'type': 'signature_patch',
                    'description': 'Patched signature verification to return success',
                    'target': ref['file']
                })
                patched = True
            except Exception as e:
                self.logger.debug(f"    Error patching signature in {ref['file']}: {e}")
        return patched

    def _patch_anti_debug(self) -> bool:
        patched = False
        for ref in self.findings['gdb_detection']:
            if isinstance(ref, dict) and 'file' in ref and os.path.isfile(
                os.path.join(self.analyzer.decompile_dir, ref['file'])
            ):
                smali_path = os.path.join(self.analyzer.decompile_dir, ref['file'])
                try:
                    with open(smali_path, 'r', encoding='utf-8', errors='replace') as f:
                        content = f.read()
                    orig = content
                    content = re.sub(
                        r'invoke-static\s*\{.*?\},\s*Landroid/os/Debug;->isDebuggerConnected\(\)Z',
                        'const/4 v0, 0x0\ninvoke-static {v0}, Ljava/lang/Boolean;->valueOf(Z)Ljava/lang/Boolean;',
                        content
                    )
                    content = re.sub(
                        r'sget\s+\w+,\s*Landroid/os/Build;->TAG:Ljava/lang/String;',
        'const-string v0, "patched"',
                        content
                    )
                    if 'TracerPid' in content:
                        content = re.sub(
                            r'invoke-.*?\{.*?\},\s*L.*?;->readLine\(\)Ljava/lang/String;',
                            'const-string v0, "0"',
                            content
                        )
                    if 'ptrace' in content.lower():
                        content = re.sub(
                            r'const-string\s+\w+,\s*"ptrace"',
                            'const-string v0, "ptrace_patched"',
                            content
                        )
                    if content != orig:
                        with open(smali_path, 'w', encoding='utf-8') as f:
                            f.write(content)
                        self.logger.debug(f"  [+] Patched anti-debug in {ref['file']}")
                        patched = True
                except Exception:
                    pass

        for ref in self.findings['frida_detection']:
            if isinstance(ref, dict) and 'file' in ref:
                smali_path = os.path.join(self.analyzer.decompile_dir, ref['file'])
                if os.path.isfile(smali_path):
                    try:
                        with open(smali_path, 'r', encoding='utf-8', errors='replace') as f:
                            content = f.read()
                        orig = content
                        if 'frida' in content.lower():
                            content = re.sub(
                                r'(invoke-.*?\{.*?\},\s*L.*?;->\w*[Ff][Rr][Ii][Dd][Aa]\w*\().*?\).*',
                                r'\1)V\n    return-void',
                                content
                            )
                            content = re.sub(
                                r'const-string\s+\w+,\s*"[Ff][Rr][Ii][Dd][Aa]"',
                                'const-string v0, "disabled"',
                                content
                            )
                        if content != orig:
                            with open(smali_path, 'w', encoding='utf-8') as f:
                                f.write(content)
                            self.logger.debug(f"  [+] Patched Frida detection in {ref['file']}")
                            patched = True
                    except Exception:
                        pass

        if patched:
            self.patches_applied.append({
                'type': 'anti_debug_patch',
                'description': 'Patched anti-debug/frida/gdb detection',
                'target': 'multiple files'
            })
        return patched

    def _patch_pairip_methods(self) -> bool:
        patched = False
        pairip_target_methods = {
            'verifyIntegrity': 'Z',
            'verifySignatureMatches': 'Z',
            'connectToLicensingService': 'V',
            'initializeLicenseCheck': 'V',
            'processResponse': 'V',
            'executeVM': 'V',
        }
        for smali_file in self.analyzer.all_smali_files:
            try:
                with open(smali_file, 'r', encoding='utf-8', errors='replace') as f:
                    content = f.read()
                rel = os.path.relpath(smali_file, self.analyzer.decompile_dir)
                orig = content

                for method_name, ret_type in pairip_target_methods.items():
                    if method_name not in content:
                        continue
                    if ret_type == 'V':
                        content = re.sub(
                            rf'\.method\s+(?:public|private|protected|static|final)?\s*{re.escape(method_name)}\(.*?\)V\s*\n.*?\.end\s+method',
                            f'.method public static {method_name}()V\n    .locals 0\n    return-void\n.end method',
                            content, flags=re.DOTALL
                        )
                    else:
                        content = re.sub(
                            rf'\.method\s+(?:public|private|protected|static|final)?\s*{re.escape(method_name)}\(.*?\){re.escape(ret_type)}\s*\n.*?\.end\s+method',
                            f'.method public static {method_name}(){ret_type}\n    .locals 1\n    const/4 v0, 0x1\n    return v0\n.end method',
                            content, flags=re.DOTALL
                        )

                content = re.sub(
                    r'invoke-static\s*\{[^}]*\},\s*Lcom/pairip/SignatureCheck;->verifyIntegrity\(Landroid/content/Context;\)V',
                    '# verifyIntegrity stripped',
                    content
                )

                content = re.sub(
                    r'invoke-static\s*\{.*?\},\s*Lcom/pairip/[a-zA-Z0-9_$]+;->RegisterNatives\(\)V',
                    'return-void',
                    content
                )

                if content != orig:
                    with open(smali_file, 'w', encoding='utf-8') as f:
                        f.write(content)
                    self.logger.debug(f"  [+] Patched PairIP methods in {rel}")
                    self.patches_applied.append({
                        'type': 'pairip_methods',
                        'description': f'Patched PairIP method references in {rel}',
                        'target': rel
                    })
                    patched = True
            except Exception:
                pass
        return patched

    def _strip_pairip_references(self) -> bool:
        patched = False
        for smali_file in self.analyzer.all_smali_files:
            try:
                with open(smali_file, 'r', encoding='utf-8', errors='replace') as f:
                    content = f.read()
                rel = os.path.relpath(smali_file, self.analyzer.decompile_dir)
                orig = content

                content = re.sub(r'Lcom/pairip/[a-zA-Z0-9_$]+;', 'Landroid/app/Application;', content)
                content = re.sub(r'\"pairip\"', '"patched"', content, flags=re.IGNORECASE)
                content = re.sub(r'\"PAIRIP\"', '"PATCHED"', content)

                if content != orig:
                    with open(smali_file, 'w', encoding='utf-8') as f:
                        f.write(content)
                    self.logger.debug(f"  [+] Stripped PairIP references in {rel}")
                    patched = True
            except Exception:
                pass
        return patched
