import os
import json
from datetime import datetime
from typing import Dict, List, Optional
from .utils import setup_logger, Color


class ReportGenerator:
    def __init__(self, analyzer, all_findings: Dict, patches: List[Dict],
                 output_dir: str, logger=None):
        self.analyzer = analyzer
        self.all_findings = all_findings
        self.patches = patches
        self.output_dir = output_dir
        self.logger = logger or setup_logger()

    def generate(self) -> Dict[str, str]:
        self.logger.info(f"\n{'=' * 60}")
        self.logger.info(f"[*] Generating reports...")
        self.logger.info(f"{'=' * 60}")

        reports = {}
        reports['json'] = self._generate_json()
        reports['text'] = self._generate_text()
        reports['html'] = self._generate_html()

        if reports['json']:
            self.logger.info(f"    JSON report: {reports['json']}")
        if reports['text']:
            self.logger.info(f"    Text report: {reports['text']}")
        if reports['html']:
            self.logger.info(f"    HTML report: {reports['html']}")

        return reports

    def _build_report_data(self) -> Dict:
        apk_info = self.analyzer.apk_info
        pairip_findings = self.all_findings.get('pairip_detector', {}) or {}
        pairip_patches = self.all_findings.get('pairip_patches', []) or []
        premium_findings = self.all_findings.get('premium_findings', {}) or {}
        premium_patches = self.all_findings.get('premium_patches', []) or []
        security_findings = self.all_findings.get('security_findings', {}) or {}
        security_patches = self.all_findings.get('security_patches', []) or []

        return {
            'report_metadata': {
                'tool': 'PairIPAutoPatcher',
                'version': '1.0.0',
                'generated': datetime.now().isoformat(),
                'apk_file': self.analyzer.apk_path,
            },
            'apk_info': {
                'file_name': os.path.basename(self.analyzer.apk_path),
                'size_bytes': apk_info.get('size_bytes', 0),
                'size_mb': f"{apk_info.get('size_bytes', 0) / 1024 / 1024:.1f}",
                'package_name': apk_info.get('package_name', ''),
                'version_name': apk_info.get('version_name', ''),
                'version_code': apk_info.get('version_code', 0),
                'min_sdk': apk_info.get('min_sdk', 0),
                'target_sdk': apk_info.get('target_sdk', 0),
                'permissions': apk_info.get('permissions', []),
                'activities': apk_info.get('activities', []),
                'services': apk_info.get('services', []),
                'receivers': apk_info.get('receivers', []),
                'providers': apk_info.get('providers', []),
                'native_libs': apk_info.get('native_libs', []),
                'dex_count': apk_info.get('dex_count', 0),
                'has_pairip': apk_info.get('has_pairip', False),
                'has_billing': apk_info.get('has_billing', False),
            },
            'pairip_analysis': {
                'detected': (
                    len(pairip_findings.get('libpairipcore', [])) > 0 or
                    pairip_findings.get('pairip_manifest', False) or
                    len(pairip_findings.get('pairip_smali_dirs', [])) > 0
                ),
                'libpairipcore': [
                    {'name': os.path.basename(l.get('path', '')), 'arch': l.get('arch', '')}
                    for l in pairip_findings.get('libpairipcore', [])
                ],
                'manifest_reference': pairip_findings.get('pairip_manifest', False),
                'smali_files': pairip_findings.get('pairip_smali_dirs', []),
                'executeVM_references': [
                    {'file': r.get('file', ''), 'line': r.get('line', 0)}
                    for r in pairip_findings.get('executeVM_references', [])
                    if isinstance(r, dict)
                ],
                'pairip_assets': pairip_findings.get('pairip_assets', []),
                'signature_checks': [
                    {'file': s.get('file', ''), 'description': s.get('description', '')}
                    for s in pairip_findings.get('signature_checks', [])
                ],
                'anti_debug_detections': [
                    {'file': d.get('file', ''), 'description': d.get('description', '')}
                    for d in pairip_findings.get('gdb_detection', [])
                    if isinstance(d, dict)
                ],
                'frida_detections': [
                    {'file': f.get('file', ''), 'line': f.get('line', 0)}
                    for f in pairip_findings.get('frida_detection', [])
                    if isinstance(f, dict)
                ],
                'other_pairip': pairip_findings.get('other_pairip', []),
            },
            'premium_analysis': {
                'detected': (
                    len(premium_findings.get('premium_booleans', [])) > 0 or
                    len(premium_findings.get('billing_integrations', [])) > 0
                ),
                'subscription_methods': premium_findings.get('subscription_methods', []),
                'billing_integrations': premium_findings.get('billing_integrations', []),
                'third_party_payment': premium_findings.get('third_party_payment', []),
                'premium_booleans': premium_findings.get('premium_booleans', []),
                'premium_checks': premium_findings.get('premium_checks', []),
                'server_validation': premium_findings.get('server_validation', []),
                'paywall_classes': premium_findings.get('paywall_classes', []),
                'feature_flags': premium_findings.get('feature_flags', []),
                'license_checks': premium_findings.get('license_checks', []),
                'obfuscated_billing': premium_findings.get('obfuscated_billing', []),
            },
            'security_analysis': {
                'root_detection': security_findings.get('root_detection', []),
                'debugger_detection': security_findings.get('debugger_detection', []),
                'cert_pinning': security_findings.get('cert_pinning', []),
                'emulator_detection': security_findings.get('emulator_detection', []),
            },
            'api_endpoints': self.analyzer.api_endpoints,
            'patches_applied': self.patches,
            'summary': {
                'total_findings': sum(
                    len(v) if isinstance(v, list) else (1 if v else 0)
                    for d in [pairip_findings, premium_findings, security_findings]
                    for v in d.values()
                ),
                'total_patches': len(self.patches),
            }
        }

    def _generate_json(self) -> str:
        try:
            data = self._build_report_data()
            path = os.path.join(self.output_dir, f'{self.analyzer.apk_name}_report.json')
            os.makedirs(os.path.dirname(path), exist_ok=True)
            with open(path, 'w', encoding='utf-8') as f:
                json.dump(data, f, indent=2, default=str)
            return path
        except Exception as e:
            self.logger.error(f"    JSON report failed: {e}")
            return ''

    def _generate_text(self) -> str:
        try:
            data = self._build_report_data()
            path = os.path.join(self.output_dir, f'{self.analyzer.apk_name}_report.txt')
            os.makedirs(os.path.dirname(path), exist_ok=True)
            with open(path, 'w', encoding='utf-8') as f:
                f.write(self._format_text_report(data))
            return path
        except Exception as e:
            self.logger.error(f"    Text report failed: {e}")
            return ''

    def _format_text_report(self, data: Dict) -> str:
        lines = []
        lines.append('=' * 70)
        lines.append('  PairIPAutoPatcher - REVERSE ENGINEERING REPORT')
        lines.append('=' * 70)
        lines.append(f"  Generated: {data['report_metadata']['generated']}")
        lines.append(f"  Target APK: {data['report_metadata']['apk_file']}")
        lines.append('')

        apk = data['apk_info']
        lines.append('--- APK INFORMATION ---')
        lines.append(f"  Package:      {apk['package_name']}")
        lines.append(f"  Version:      {apk['version_name']} ({apk['version_code']})")
        lines.append(f"  Size:         {apk['size_mb']} MB")
        lines.append(f"  SDK:          {apk['min_sdk']} -> {apk['target_sdk']}")
        lines.append(f"  DEX files:    {apk['dex_count']}")
        lines.append(f"  Native libs:  {len(apk['native_libs'])}")
        if apk['permissions']:
            lines.append(f"  Permissions:  {len(apk['permissions'])}")
            for p in apk['permissions'][:15]:
                lines.append(f"    - {p.split('.')[-1]}")
            if len(apk['permissions']) > 15:
                lines.append(f"    ... and {len(apk['permissions']) - 15} more")
        lines.append('')

        pairip = data['pairip_analysis']
        lines.append('--- PAIRIP ANALYSIS ---')
        if pairip['detected']:
            lines.append(f"  STATUS: DETECTED AND PATCHED")
        else:
            lines.append(f"  STATUS: Not detected")
        if pairip['libpairipcore']:
            lines.append(f"  libpairipcore.so: {len(pairip['libpairipcore'])} instance(s)")
            for l in pairip['libpairipcore']:
                lines.append(f"    - {l['name']} ({l['arch']})")
        lines.append(f"  Manifest reference: {'YES' if pairip['manifest_reference'] else 'No'}")
        lines.append(f"  PairIP smali files: {len(pairip['smali_files'])}")
        lines.append(f"  executeVM refs: {len(pairip['executeVM_references'])}")
        lines.append(f"  Signature checks: {len(pairip['signature_checks'])}")
        lines.append(f"  Anti-debug checks: {len(pairip['anti_debug_detections'])}")
        lines.append(f"  Frida detection: {len(pairip['frida_detections'])}")
        lines.append('')

        premium = data['premium_analysis']
        lines.append('--- PREMIUM/SUBSCRIPTION ANALYSIS ---')
        if premium['detected']:
            lines.append(f"  STATUS: Premium logic detected and bypassed")
        else:
            lines.append(f"  STATUS: No premium logic detected")
        lines.append(f"  Subscription keywords found: {len(premium['premium_checks'])}")
        lines.append(f"  Premium boolean methods: {len(premium['premium_booleans'])}")
        lines.append(f"  Billing integrations: {len(premium['billing_integrations'])}")
        lines.append(f"  Third-party payment SDKs: {len(premium['third_party_payment'])}")
        if premium['third_party_payment']:
            for tp in premium['third_party_payment']:
                lines.append(f"    - {tp.get('service', 'Unknown')}")
        lines.append(f"  Server validation points: {len(premium['server_validation'])}")
        lines.append(f"  Paywall classes: {len(premium['paywall_classes'])}")
        lines.append(f"  Feature flags: {len(premium['feature_flags'])}")
        lines.append(f"  License checks: {len(premium['license_checks'])}")
        if premium['subscription_methods']:
            lines.append(f"  Subscription method details:")
            for sm in premium['subscription_methods'][:20]:
                lines.append(f"    - {sm.get('keyword', '')} in {sm.get('file', '')}")
        lines.append('')

        sec = data['security_analysis']
        lines.append('--- SECURITY ANALYSIS ---')
        lines.append(f"  Root detection checks: {len(sec['root_detection'])}")
        lines.append(f"  Debugger detection: {len(sec['debugger_detection'])}")
        lines.append(f"  Certificate pinning: {len(sec['cert_pinning'])}")
        lines.append(f"  Emulator detection: {len(sec['emulator_detection'])}")
        lines.append('')

        if data['api_endpoints']:
            lines.append('--- API ENDPOINTS EXTRACTED ---')
            for ep in sorted(set(data['api_endpoints']))[:50]:
                lines.append(f"  {ep}")
            if len(set(data['api_endpoints'])) > 50:
                lines.append(f"  ... and {len(set(data['api_endpoints'])) - 50} more")
            lines.append('')

        patches = data['patches_applied']
        if patches:
            lines.append('--- PATCHES APPLIED ---')
            for i, p in enumerate(patches, 1):
                lines.append(f"  {i:3d}. [{p.get('type', 'unknown')}] {p.get('description', '')}")
                if p.get('target'):
                    lines.append(f"       Target: {p['target']}")
            lines.append('')

        lines.append('=' * 70)
        lines.append('  Report generated by PairIPAutoPatcher v1.0.0')
        lines.append('=' * 70)
        return '\n'.join(lines)

    def _generate_html(self) -> str:
        try:
            data = self._build_report_data()
            path = os.path.join(self.output_dir, f'{self.analyzer.apk_name}_report.html')
            os.makedirs(os.path.dirname(path), exist_ok=True)
            with open(path, 'w', encoding='utf-8') as f:
                f.write(self._format_html_report(data))
            return path
        except Exception as e:
            self.logger.error(f"    HTML report failed: {e}")
            return ''

    def _format_html_report(self, data: Dict) -> str:
        apk = data['apk_info']
        pairip = data['pairip_analysis']
        premium = data['premium_analysis']
        sec = data['security_analysis']
        patches = data['patches_applied']
        endpoints = data['api_endpoints']

        pairip_status = 'Detected & Patched' if pairip['detected'] else 'Not Detected'
        pairip_color = '#dc3545' if pairip['detected'] else '#28a745'
        premium_status = 'Detected & Patched' if premium['detected'] else 'Not Detected'
        premium_color = '#dc3545' if premium['detected'] else '#28a745'

        patch_rows = ''
        for i, p in enumerate(patches, 1):
            patch_rows += f'''
            <tr>
                <td>{i}</td>
                <td>{p.get('type', '')}</td>
                <td>{p.get('description', '')}</td>
                <td><code>{p.get('target', '')}</code></td>
            </tr>'''

        endpoint_items = ''
        for ep in sorted(set(endpoints))[:100]:
            endpoint_items += f'<li><code>{ep}</code></li>\n'

        return f'''<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>PairIPAutoPatcher Report - {apk['package_name']}</title>
<style>
* {{ margin: 0; padding: 0; box-sizing: border-box; }}
body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; background: #0f0f1a; color: #e0e0e0; line-height: 1.6; padding: 20px; }}
.container {{ max-width: 1200px; margin: 0 auto; }}
h1 {{ color: #00d4aa; border-bottom: 2px solid #00d4aa; padding-bottom: 10px; margin-bottom: 20px; }}
h2 {{ color: #00d4aa; margin: 25px 0 15px; }}
h3 {{ color: #aaa; margin: 15px 0 10px; }}
.section {{ background: #1a1a2e; border-radius: 8px; padding: 20px; margin-bottom: 20px; border: 1px solid #2a2a4e; }}
table {{ width: 100%; border-collapse: collapse; margin: 10px 0; }}
th, td {{ padding: 8px 12px; text-align: left; border-bottom: 1px solid #2a2a4e; }}
th {{ color: #00d4aa; font-weight: 600; }}
.status {{ display: inline-block; padding: 4px 12px; border-radius: 4px; font-weight: bold; font-size: 0.9em; }}
ul {{ list-style: none; padding: 0; }}
li {{ padding: 4px 0; }}
code {{ background: #2a2a4e; padding: 2px 6px; border-radius: 3px; font-size: 0.9em; color: #ffd700; }}
.meta {{ color: #888; font-size: 0.9em; }}
.footer {{ text-align: center; color: #666; margin-top: 40px; padding-top: 20px; border-top: 1px solid #2a2a4e; }}
</style>
</head>
<body>
<div class="container">
<h1>PairIPAutoPatcher Report</h1>
<p class="meta">Generated: {data['report_metadata']['generated']}<br>
Target: {data['report_metadata']['apk_file']}</p>

<div class="section">
<h2>APK Information</h2>
<table>
<tr><th>Property</th><th>Value</th></tr>
<tr><td>Package</td><td><code>{apk['package_name']}</code></td></tr>
<tr><td>Version</td><td>{apk['version_name']} ({apk['version_code']})</td></tr>
<tr><td>Size</td><td>{apk['size_mb']} MB ({apk['size_bytes']} bytes)</td></tr>
<tr><td>SDK</td><td>min {apk['min_sdk']} -> target {apk['target_sdk']}</td></tr>
<tr><td>DEX Files</td><td>{apk['dex_count']}</td></tr>
<tr><td>Native Libraries</td><td>{len(apk['native_libs'])}</td></tr>
</table>
</div>

<div class="section">
<h2>PairIP Protection Analysis <span class="status" style="background:{pairip_color}20;color:{pairip_color}">{pairip_status}</span></h2>
<table>
<tr><th>Component</th><th>Count</th></tr>
<tr><td>libpairipcore.so</td><td>{len(pairip['libpairipcore'])}</td></tr>
<tr><td>Manifest Reference</td><td>{'Yes' if pairip['manifest_reference'] else 'No'}</td></tr>
<tr><td>PairIP Smali Files</td><td>{len(pairip['smali_files'])}</td></tr>
<tr><td>executeVM References</td><td>{len(pairip['executeVM_references'])}</td></tr>
<tr><td>Protected Assets</td><td>{len(pairip['pairip_assets'])}</td></tr>
<tr><td>Signature Checks</td><td>{len(pairip['signature_checks'])}</td></tr>
<tr><td>Anti-Debug Checks</td><td>{len(pairip['anti_debug_detections'])}</td></tr>
<tr><td>Frida Detection</td><td>{len(pairip['frida_detections'])}</td></tr>
</table>
</div>

<div class="section">
<h2>Premium/Subscription Analysis <span class="status" style="background:{premium_color}20;color:{premium_color}">{premium_status}</span></h2>
<table>
<tr><th>Component</th><th>Count</th></tr>
<tr><td>Subscription Keywords</td><td>{len(premium['premium_checks'])}</td></tr>
<tr><td>Premium Boolean Methods</td><td>{len(premium['premium_booleans'])}</td></tr>
<tr><td>Billing Integrations</td><td>{len(premium['billing_integrations'])}</td></tr>
<tr><td>Third-Party Payment SDKs</td><td>{len(premium['third_party_payment'])}</td></tr>
<tr><td>Server Validation Points</td><td>{len(premium['server_validation'])}</td></tr>
<tr><td>Paywall Classes</td><td>{len(premium['paywall_classes'])}</td></tr>
<tr><td>Feature Flags</td><td>{len(premium['feature_flags'])}</td></tr>
<tr><td>License Checks</td><td>{len(premium['license_checks'])}</td></tr>
</table>
</div>

<div class="section">
<h2>Security Bypass Analysis</h2>
<table>
<tr><th>Category</th><th>Count</th></tr>
<tr><td>Root Detection</td><td>{len(sec['root_detection'])}</td></tr>
<tr><td>Debugger Detection</td><td>{len(sec['debugger_detection'])}</td></tr>
<tr><td>Certificate Pinning</td><td>{len(sec['cert_pinning'])}</td></tr>
<tr><td>Emulator Detection</td><td>{len(sec['emulator_detection'])}</td></tr>
</table>
</div>

<div class="section">
<h2>API Endpoints Extracted</h2>
<ul>{endpoint_items}</ul>
</div>

<div class="section">
<h2>Patches Applied ({len(patches)})</h2>
<table>
<tr><th>#</th><th>Type</th><th>Description</th><th>Target</th></tr>
{patch_rows}
</table>
</div>

<div class="footer">
PairIPAutoPatcher v1.0.0
</div>
</div>
</body>
</html>'''
