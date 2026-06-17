import os
import re
import shutil
from typing import List, Dict, Optional, Tuple
from .utils import setup_logger, Color, SmaliHelper


class SecurityBypass:
    def __init__(self, analyzer, logger=None):
        self.analyzer = analyzer
        self.logger = logger or setup_logger()
        self.patches_applied = []
        self.findings = {
            'root_detection': [],
            'debugger_detection': [],
            'cert_pinning': [],
            'emulator_detection': [],
            'ssl_pinning': [],
        }

    def analyze_and_patch_all(self) -> Dict:
        self.logger.info(f"\n{'=' * 60}")
        self.logger.info(f"[*] Security bypass: scanning and patching...")
        self.logger.info(f"{'=' * 60}")

        results = {}
        results['root_bypass'] = self._bypass_root_detection()
        results['debugger_bypass'] = self._bypass_debugger_detection()
        results['cert_pinning_bypass'] = self._bypass_cert_pinning()
        results['emulator_bypass'] = self._bypass_emulator_detection()
        results['ssl_bypass'] = self._bypass_ssl_pinning()

        total = sum(1 for v in results.values() if v)
        if total:
            self.logger.info(f"[+] Security bypass complete - {total} categories patched, {len(self.patches_applied)} total patches")
        else:
            self.logger.info("[-] No security detections found to patch")

        return results

    def _detect_root_patterns(self) -> List[Dict]:
        findings = []
        root_patterns = [
            (r'isRooted|isDeviceRooted|checkRoot|detectRoot', 'Root check method'),
            (r'findBinary.*su', 'Su binary search'),
            (r'Magisk|magisk', 'Magisk detection'),
            (r'Superuser\.apk', 'Superuser detection'),
            (r'com\.*supersu', 'SuperSU reference'),
            (r'ro\.debuggable', 'System ro.debuggable'),
            (r'ro\.secure', 'System ro.secure'),
            (r'build\.TAGS.*test-keys', 'Test keys check'),
            (r'which.*su', 'Which su search'),
            (r'System\.getenv.*PATH\b', 'PATH environment check'),
            (r'access.*su', 'Access su binary'),
            (r'Runtime\.exec.*su', 'Runtime exec su'),
            (r'ProcessBuilder.*su', 'ProcessBuilder su'),
            (r'/system/app/Superuser', 'System app Superuser'),
            (r'/sbin/su', 'sbin su path'),
            (r'/system/bin/su', 'system bin su'),
            (r'/system/xbin/su', 'system xbin su'),
            (r'/data/local/xbin/su', 'data local su'),
            (r'/data/local/bin/su', 'data local bin su'),
            (r'/system/sd/xbin/su', 'system sd su'),
            (r'/system/bin/failsafe/su', 'failsafe su'),
            (r'/data/local/su', 'data local su'),
            (r'build\.TAGS', 'Build tags check'),
            (r'getprop.*ro\.build\.tags', 'getprop build tags'),
            (r'getprop.*ro\.debuggable', 'getprop debuggable'),
        ]
        for smali_file in self.analyzer.all_smali_files:
            try:
                with open(smali_file, 'rb') as f:
                    content = f.read()
                text = content.decode('utf-8', errors='replace')
                rel_path = os.path.relpath(smali_file, self.analyzer.decompile_dir)
                for pat, desc in root_patterns:
                    if re.search(pat, text, re.IGNORECASE):
                        entry = {'pattern': pat, 'description': desc, 'file': rel_path}
                        if entry not in findings:
                            findings.append(entry)
            except Exception:
                pass
        return findings

    def _bypass_root_detection(self) -> bool:
        patched = False
        findings = self._detect_root_patterns()
        self.findings['root_detection'] = findings

        if findings:
            self.logger.info(f"    Root detection: {len(findings)} patterns found")

        for finding in findings:
            smali_path = os.path.join(self.analyzer.decompile_dir, finding['file'])
            if not os.path.isfile(smali_path):
                continue
            try:
                with open(smali_path, 'r', encoding='utf-8', errors='replace') as f:
                    content = f.read()
                orig = content

                root_methods = re.findall(
                    r'\.method\s+.*\b(?:isRooted|isDeviceRooted|checkRoot|detectRoot|hasRoot|isRoot)\b.*?\)Z\s*\n.*?\.end\s+method',
                    content, re.DOTALL | re.IGNORECASE
                )
                for m in root_methods:
                    new_body = m.split('\n')[0] + '\n    .locals 1\n    const/4 v0, 0x0\n    return v0\n.end method'
                    content = content.replace(m, new_body)
                    self.logger.info(f"    [+] Patched root check: isRooted() -> false in {finding['file']}")
                    patched = True

                content = re.sub(
                    r'const-string\s+\w+,\s*"/system/[^"]*su[^"]*"',
                    'const-string v0, "/system/xbin/patched"',
                    content
                )
                content = re.sub(
                    r'const-string\s+\w+,\s*"/sbin/su"',
                    'const-string v0, "/sbin/patched"',
                    content
                )
                content = re.sub(
                    r'const-string\s+\w+,\s*"(?:/data/local/[^"]*su|/data/local/xbin/su|/data/local/bin/su)"',
                    'const-string v0, "/data/local/patched"',
                    content
                )
                content = re.sub(
                    r'invoke-virtual\s+\{.*?\},\s*Ljava/io/File;->exists\(\)Z',
                    'const/4 v0, 0x0',
                    content
                )

                if 'su' in finding['pattern']:
                    content = re.sub(
                        r'const-string\s+\w+,\s*"(?:su|Su|SU)"\s*',
                        'const-string v0, "patched_binary"',
                        content
                    )

                if content != orig:
                    with open(smali_path, 'w', encoding='utf-8') as f:
                        f.write(content)
                    self.patches_applied.append({
                        'type': 'root_bypass',
                        'description': finding['description'],
                        'target': finding['file']
                    })
                    if not patched:
                        self.logger.info(f"    [+] Patched root detection: {finding['description']} in {finding['file']}")
                        patched = True
            except Exception:
                pass
        return patched

    def _detect_debugger_patterns(self) -> List[Dict]:
        findings = []
        debug_patterns = [
            (r'isDebuggerConnected', 'Debugger connected check'),
            (r'waitForDebugger', 'Wait for debugger'),
            (r'android\.os\.Debug', 'Debug class reference'),
            (r'Debug\.isDebuggerConnected', 'Debug.isDebuggerConnected'),
            (r'ptrace', 'Ptrace anti-debug'),
            (r'TracerPid', 'Tracer PID check'),
            (r'android:debuggable=', 'Debuggable flag'),
            (r'getprop.*debug', 'Property debug check'),
            (r'ro\.kernel\.qemu', 'QEMU detection'),
            (r'ro\.product\.cpu\.abi', 'ABI detection'),
        ]
        for smali_file in self.analyzer.all_smali_files:
            try:
                with open(smali_file, 'rb') as f:
                    content = f.read()
                text = content.decode('utf-8', errors='replace')
                rel_path = os.path.relpath(smali_file, self.analyzer.decompile_dir)
                for pat, desc in debug_patterns:
                    if re.search(pat, text, re.IGNORECASE):
                        entry = {'pattern': pat, 'description': desc, 'file': rel_path}
                        if entry not in findings:
                            findings.append(entry)
            except Exception:
                pass
        return findings

    def _bypass_debugger_detection(self) -> bool:
        patched = False
        findings = self._detect_debugger_patterns()
        self.findings['debugger_detection'] = findings

        if findings:
            self.logger.info(f"    Debugger detection: {len(findings)} patterns found")

        for finding in findings:
            smali_path = os.path.join(self.analyzer.decompile_dir, finding['file'])
            if not os.path.isfile(smali_path):
                continue
            try:
                with open(smali_path, 'r', encoding='utf-8', errors='replace') as f:
                    content = f.read()
                orig = content

                if 'waitForDebugger' in finding['pattern']:
                    content = re.sub(
                        r'\.method\s+.*\bwaitForDebugger\b.*?\)V\s*\n.*?\.end\s+method',
                        lambda m: m.group(0).split('\n')[0] + '\n    .locals 1\n    return-void\n.end method',
                        content, flags=re.DOTALL
                    )

                if 'Debug.isDebuggerConnected' in finding['pattern']:
                    content = re.sub(
                        r'invoke-static\s*\{.*?\},\s*Landroid/os/Debug;->isDebuggerConnected\(\)Z',
                        'const/4 v0, 0x0',
                        content
                    )

                if 'TracerPid' in finding['pattern']:
                    content = re.sub(
                        r'const-string\s+\w+,\s*"TracerPid"',
                        'const-string v0, "PatchedPid"',
                        content
                    )
                    content = re.sub(
                        r'if-nez\s+\w+,\s*:cond_\w+',
                        'if-eqz v0, :cond_\n',
                        content
                    )

                if 'ptrace' in finding['pattern'].lower():
                    content = re.sub(
                        r'const/4\s+\w+,\s*(?:0x[0]*10|16)\s*#\s*PTRACE_TRACEME\b',
                        'const/4 v0, 0x0',
                        content
                    )
                    content = re.sub(
                        r'const-string\s+\w+,\s*"ptrace"',
                        'const-string v0, "disabled"',
                        content
                    )

                if 'android:debuggable=' in finding['pattern']:
                    if self.analyzer.manifest_path and os.path.isfile(self.analyzer.manifest_path):
                        try:
                            with open(self.analyzer.manifest_path, 'rb') as fm:
                                mdata = fm.read()
                            mtext = mdata.decode('utf-8', errors='replace')
                            mtext = re.sub(
                                r'android:debuggable="?\'?false"?\'?',
                                'android:debuggable="true"',
                                mtext
                            )
                            with open(self.analyzer.manifest_path, 'wb') as fm:
                                fm.write(mtext.encode('utf-8'))
                            self.logger.info(f"    [+] Set android:debuggable=true in manifest")
                        except Exception:
                            pass

                if content != orig:
                    with open(smali_path, 'w', encoding='utf-8') as f:
                        f.write(content)
                    self.patches_applied.append({
                        'type': 'debugger_bypass',
                        'description': finding['description'],
                        'target': finding['file']
                    })
                    if not patched:
                        self.logger.info(f"    [+] Patched debugger detection: {finding['description']} in {finding['file']}")
                        patched = True
            except Exception:
                pass
        return patched

    def _detect_cert_pinning(self) -> List[Dict]:
        findings = []
        cert_patterns = [
            (r'CertificatePinner', 'OkHttp CertificatePinner'),
            (r'certificatePinner', 'Certificate pinner builder'),
            (r'checkServerTrusted', 'TrustManager checkServerTrusted'),
            (r'TrustManager', 'TrustManager reference'),
            (r'SSLSocketFactory', 'Custom SSLSocketFactory'),
            (r'HostnameVerifier', 'Custom HostnameVerifier'),
            (r'X509TrustManager', 'X509 TrustManager'),
            (r'KeyStore', 'KeyStore reference'),
            (r'SSLContext', 'SSLContext reference'),
            (r'sha256/', 'SHA-256 pin hash'),
            (r'sha1/', 'SHA-1 pin hash'),
            (r'\.cer', 'Certificate file'),
            (r'\.crt', 'Certificate file'),
            (r'\.pem', 'PEM certificate'),
            (r'publicKey', 'Public key pinning'),
            (r'CertificateChain', 'Certificate chain'),
            (r'pinning', 'Pinning reference'),
            (r'ALLOW_ALL_HOSTNAME_VERIFIER', 'Allow all verifier'),
            (r'StrictHostnameVerifier', 'Strict verifier'),
            (r'OkHttpClient.*Builder', 'OkHttp builder'),
        ]
        for smali_file in self.analyzer.all_smali_files:
            try:
                with open(smali_file, 'rb') as f:
                    content = f.read()
                text = content.decode('utf-8', errors='replace')
                rel_path = os.path.relpath(smali_file, self.analyzer.decompile_dir)
                for pat, desc in cert_patterns:
                    if re.search(pat, text, re.IGNORECASE):
                        entry = {'pattern': pat, 'description': desc, 'file': rel_path}
                        if entry not in findings:
                            findings.append(entry)
            except Exception:
                pass
        return findings

    def _bypass_cert_pinning(self) -> bool:
        patched = False
        findings = self._detect_cert_pinning()
        self.findings['cert_pinning'] = findings

        if findings:
            self.logger.info(f"    Certificate pinning: {len(findings)} patterns found")

        for finding in findings:
            smali_path = os.path.join(self.analyzer.decompile_dir, finding['file'])
            if not os.path.isfile(smali_path):
                continue
            try:
                with open(smali_path, 'r', encoding='utf-8', errors='replace') as f:
                    content = f.read()
                orig = content

                if 'CertificatePinner' in finding['pattern'].lower().replace(' ', ''):
                    content = re.sub(
                        r'\.method\s+.*\bcertificatePinner\b.*?\)Lokhttp3/CertificatePinner;',
                        lambda m: m.group(0).split('\n')[0] + '\n    .locals 1\n    const/4 v0, 0x0\n    return-object v0\n.end method',
                        content, flags=re.DOTALL | re.IGNORECASE
                    )
                    content = re.sub(
                        r'new-instance\s+\w+,\s*Lokhttp3/CertificatePinner\$Builder',
                        'const/4 v0, 0x0',
                        content
                    )
                    content = re.sub(
                        r'invoke-virtual\s\{.*?\},\s*Lokhttp3/CertificatePinner\$Builder;->build\(\)Lokhttp3/CertificatePinner;',
                        'const/4 v0, 0x0',
                        content
                    )

                if 'checkServerTrusted' in finding['pattern']:
                    content = re.sub(
                        r'\.method\s+.*\bcheckServerTrusted\b.*?\)V\s*\n.*?\.end\s+method',
                        lambda m: m.group(0).split('\n')[0] + '\n    .locals 2\n    return-void\n.end method',
                        content, flags=re.DOTALL
                    )

                if 'TrustManager' in finding['pattern']:
                    trust_manager_methods = re.findall(
                        r'\.method\s+.*(?:checkServerTrusted|checkClientTrusted|getAcceptedIssuers)\b.*?\n.*?\.end\s+method',
                        content, re.DOTALL
                    )
                    for tm in trust_manager_methods:
                        sig = tm.split('\n')[0]
                        ret_type = sig.split(')')[-1] if ')' in sig else ''
                        if 'V' in ret_type:
                            new_body = sig + '\n    .locals 2\n    return-void\n.end method'
                        elif 'Z' in ret_type:
                            new_body = sig + '\n    .locals 1\n    const/4 v0, 0x1\n    return v0\n.end method'
                        elif 'L' in ret_type:
                            new_body = sig + '\n    .locals 1\n    const/4 v0, 0x0\n    return-object v0\n.end method'
                        else:
                            new_body = sig + '\n    .locals 1\n    return-void\n.end method'
                        content = content.replace(tm, new_body)

                if 'HostnameVerifier' in finding['pattern']:
                    hv_methods = re.findall(
                        r'\.method\s+.*\bverify\b.*?\)Z\s*\n.*?\.end\s+method',
                        content, re.DOTALL
                    )
                    for hv in hv_methods:
                        sig = hv.split('\n')[0]
                        new_body = sig + '\n    .locals 1\n    const/4 v0, 0x1\n    return v0\n.end method'
                        content = content.replace(hv, new_body)

                if content != orig:
                    with open(smali_path, 'w', encoding='utf-8') as f:
                        f.write(content)
                    self.patches_applied.append({
                        'type': 'cert_pinning_bypass',
                        'description': finding['description'],
                        'target': finding['file']
                    })
                    if not patched:
                        self.logger.info(f"    [+] Patched cert pinning: {finding['description']} in {finding['file']}")
                        patched = True
            except Exception:
                pass
        return patched

    def _detect_emulator_patterns(self) -> List[Dict]:
        findings = []
        emu_patterns = [
            (r'ro\.kernel\.qemu', 'QEMU kernel property'),
            (r'ro\.product\.model', 'Product model'),
            (r'ro\.product\.manufacturer', 'Manufacturer'),
            (r'ro\.product\.device', 'Device name'),
            (r'ro\.build\.fingerprint', 'Build fingerprint'),
            (r'isEmulator|isEmulated|checkEmulator', 'Emulator check'),
            (r'Build\.FINGERPRINT', 'Build fingerprint'),
            (r'Build\.MODEL', 'Build model'),
            (r'Build\.DEVICE', 'Build device'),
            (r'Build\.PRODUCT', 'Build product'),
            (r'Build\.MANUFACTURER', 'Build manufacturer'),
            (r'google_sdk', 'Google SDK emulator'),
            (r'sdk_gphone', 'SDK Gphone emulator'),
            (r'generic_', 'Generic emulator'),
            (r'vbox86', 'VirtualBox x86'),
            (r'ranchu', 'Ranchu emulator'),
            (r'goldfish', 'Goldfish emulator'),
        ]
        for smali_file in self.analyzer.all_smali_files:
            try:
                with open(smali_file, 'rb') as f:
                    content = f.read()
                text = content.decode('utf-8', errors='replace')
                rel_path = os.path.relpath(smali_file, self.analyzer.decompile_dir)
                for pat, desc in emu_patterns:
                    if re.search(pat, text, re.IGNORECASE):
                        entry = {'pattern': pat, 'description': desc, 'file': rel_path}
                        if entry not in findings:
                            findings.append(entry)
            except Exception:
                pass
        return findings

    def _bypass_emulator_detection(self) -> bool:
        patched = False
        findings = self._detect_emulator_patterns()
        self.findings['emulator_detection'] = findings
        if findings:
            self.logger.info(f"    Emulator detection: {len(findings)} patterns found")
        for finding in findings:
            smali_path = os.path.join(self.analyzer.decompile_dir, finding['file'])
            if not os.path.isfile(smali_path):
                continue
            try:
                with open(smali_path, 'r', encoding='utf-8', errors='replace') as f:
                    content = f.read()
                orig = content

                emu_methods = re.findall(
                    r'\.method\s+.*\b(?:isEmulator|isEmulated|checkEmulator|isGenymotion|isBluestacks)\b.*?\)Z\s*\n.*?\.end\s+method',
                    content, re.DOTALL | re.IGNORECASE
                )
                for m in emu_methods:
                    new_body = m.split('\n')[0] + '\n    .locals 1\n    const/4 v0, 0x0\n    return v0\n.end method'
                    content = content.replace(m, new_body)
                    self.logger.info(f"    [+] Patched emulator check: {finding['description']} in {finding['file']}")
                    patched = True

                content = re.sub(
                    r'const-string\s+\w+,\s*"generic"',
                    'const-string v0, "real_device"',
                    content
                )

                if content != orig:
                    with open(smali_path, 'w', encoding='utf-8') as f:
                        f.write(content)
                    self.patches_applied.append({
                        'type': 'emulator_bypass',
                        'description': finding['description'],
                        'target': finding['file']
                    })
                    patched = True
            except Exception:
                pass
        return patched

    def _bypass_ssl_pinning(self) -> bool:
        patched = False
        ssl_findings = [f for f in self.findings.get('cert_pinning', [])
                        if 'SSL' in f.get('pattern', '') or 'ssl' in f.get('pattern', '').lower()]
        for finding in ssl_findings:
            smali_path = os.path.join(self.analyzer.decompile_dir, finding['file'])
            if not os.path.isfile(smali_path):
                continue
            try:
                with open(smali_path, 'r', encoding='utf-8', errors='replace') as f:
                    content = f.read()
                orig = content

                content = re.sub(
                    r'SSLContext\.getInstance\s*\([^)]*\)',
                    'SSLContext.getInstance("TLS")',
                    content
                )

                if content != orig:
                    with open(smali_path, 'w', encoding='utf-8') as f:
                        f.write(content)
                    self.patches_applied.append({
                        'type': 'ssl_bypass',
                        'description': finding['description'],
                        'target': finding['file']
                    })
                    patched = True
            except Exception:
                pass
        return patched
