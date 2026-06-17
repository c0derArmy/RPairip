#!/usr/bin/env python3
"""
PairIPAutoPatcher - Automated PairIP protection patcher
Strips PairIP protection from Android APK/APKS/XAPK files.

Usage:
  python3 pairip_autopatcher.py target.apk
  python3 pairip_autopatcher.py target.apk --output-dir ./patched
  python3 pairip_autopatcher.py --batch ./apk_directory/
"""

import os
import sys
import re
import shutil
import argparse
import logging
import time
import glob
from datetime import datetime
from typing import Dict, List, Optional

from core.utils import (
    setup_logger, run_command, run_command_stream, find_tool_path, ensure_dir,
    safe_delete, Color, CRC32Fixer, CONSOLE, RICH_AVAILABLE,
    ensure_jar, get_jar_path, JARS_DIR
)
import shutil
from core.analyzer import APKAnalyzer
from core.pairip import PairIPDetector, PairIPPatcher
from core.builder import APKBuilder


class PairIPAutoPatcher:
    def __init__(self, args):
        self.args = args
        self.logger = None
        self.analyzer = None
        self.all_findings = {}
        self.all_patches = []
        self.start_time = time.time()

        self.apk_path = args.input if hasattr(args, 'input') and args.input else None
        self.input_dir = args.dir if hasattr(args, 'dir') and args.dir else None
        self.batch_mode = args.batch if hasattr(args, 'batch') else False
        self.output_dir = args.output_dir if hasattr(args, 'output_dir') else None
        self.skip_pairip = args.skip_pairip if hasattr(args, 'skip_pairip') else False
        self.keep_decompile = args.keep_decompile if hasattr(args, 'keep_decompile') else False
        self.verbose = args.verbose if hasattr(args, 'verbose') else False
        self.keystore = args.keystore if hasattr(args, 'keystore') else None
        self.android_mode = (hasattr(args, 'android') and args.android) or detect_android()
        self.use_apktool = args.apktool if hasattr(args, 'apktool') else False

    def _merge_splits(self, path: str) -> str:
        ext = os.path.splitext(path)[1].lower()
        if ext not in ('.apks', '.xapk', '.apkm'):
            return path
        editor = ensure_jar('APKEditor.jar')
        if not editor:
            print(f"{Color.FAIL}[!] APKEditor.jar required to merge {ext} files{Color.RESET}")
            print(f"{Color.WARNING}[i] Download APKEditor.jar manually or use --apktool to bypass{Color.RESET}")
            sys.exit(1)
        output = os.path.abspath(os.path.join(os.path.dirname(path), f"{os.path.splitext(os.path.basename(path))[0]}_merged.apk"))
        if os.path.isfile(output):
            os.remove(output)
        print(f"{Color.GREEN}[i] Merging {os.path.basename(path)} with APKEditor...{Color.RESET}")
        ret, out, err = run_command_stream(
            ['java', '-jar', editor, 'm', '-i', path, '-o', output, '-f'],
            timeout=300, prefix=f"  {Color.GREEN}",
            show_lines=[r'Merging:', r'Added \[', r'Saved to']
        )
        if ret == 0 and os.path.isfile(output):
            print(f"{Color.GREEN}[+] Merged to: {output}{Color.RESET}")
            return output
        print(f"{Color.FAIL}[!] APKEditor merge failed, trying manual extract{Color.RESET}")
        return path

    def _check_environment(self):
        missing = []
        if not shutil.which('java'):
            missing.append('java (openjdk)')

        if missing:
            print(f"{Color.YELLOW}[i] Missing tools: {', '.join(missing)}{Color.RESET}")
            if self.android_mode:
                print(f"{Color.CYAN}[i] Installing via pkg (Termux)...{Color.RESET}")
                for tool in missing:
                    if 'java' in tool:
                        os.system('pkg update -y && pkg install -y openjdk-17 2>/dev/null')
            else:
                print(f"{Color.CYAN}[i] Installing via apt (Linux)...{Color.RESET}")
                for tool in missing:
                    if 'java' in tool:
                        os.system('apt update -y 2>/dev/null && apt install -y default-jdk 2>/dev/null')

            # re-check
            still_missing = []
            if not shutil.which('java'):
                still_missing.append('java')
            if still_missing:
                print(f"{Color.WARNING}[!] Could not auto-install: {', '.join(still_missing)}{Color.RESET}")
                print(f"{Color.WARNING}[i] Install manually and re-run.{Color.RESET}")

        # warn about optional tools
        if not shutil.which('zipalign'):
            print(f"{Color.DIM}[i] zipalign not found — will use Python fallback{Color.RESET}")
        if not shutil.which('apksigner') and not shutil.which('jarsigner'):
            print(f"{Color.DIM}[i] No APK signer found — will try jarsigner from JDK{Color.RESET}")

    def run(self) -> bool:
        self._check_environment()
        if self.apk_path:
            self.apk_path = os.path.abspath(self.apk_path)
        if self.input_dir:
            self.input_dir = os.path.abspath(self.input_dir)
        if self.batch_mode and self.input_dir:
            return self._run_batch()
        elif self.apk_path:
            apk_path = self._merge_splits(self.apk_path)
            return self._run_single(apk_path)
        else:
            print(f"{Color.FAIL}[!] Use -i <file> or --batch --dir <folder>{Color.RESET}")
            return False

    def _run_batch(self) -> bool:
        self._setup_logging('batch')
        apk_dir = os.path.abspath(self.input_dir)
        if not os.path.isdir(apk_dir):
            self.logger.error(f"{Color.FAIL}[!] Directory not found: {apk_dir}{Color.RESET}")
            return False

        if not self.output_dir:
            self.output_dir = os.path.join(apk_dir, 'patched_output')

        exts = ('.apk', '.apks', '.xapk', '.apkm')
        apk_files = [f for f in os.listdir(apk_dir) if f.lower().endswith(exts)]
        if not apk_files:
            self.logger.error(f"{Color.FAIL}[!] No APK files found in {apk_dir}{Color.RESET}")
            return False

        self.logger.info(f"{Color.CYAN}[*] Batch mode: processing {len(apk_files)} APK(s) from {apk_dir}{Color.RESET}")
        success = 0
        for apk_file in sorted(apk_files):
            apk_path = self._merge_splits(os.path.join(apk_dir, apk_file))
            result = self._run_single(apk_path)
            if result:
                success += 1

        self.logger.info(f"\n{Color.GREEN}[+] Batch complete: {success}/{len(apk_files)} succeeded{Color.RESET}")
        return success > 0

    def _run_single(self, apk_path: str) -> bool:
        apk_name = os.path.splitext(os.path.basename(apk_path))[0]
        self._setup_logging(apk_name)

        if not self.output_dir:
            self.output_dir = os.path.dirname(os.path.abspath(apk_path))

        banner = f"""{Color.CYAN}╔══════════════════════════════════════╗
║        {Color.BOLD}PairIP Auto Patcher{Color.RESET}{Color.CYAN}        ║
╠══════════════════════════════════════╣
║  Input : {os.path.basename(apk_path):<28}║
║  Output: {os.path.basename(self.output_dir):<28}║
╚══════════════════════════════════════╝{Color.RESET}"""
        print(banner)

        if self.android_mode:
            print(f"{Color.DIM}[i] Android mode: running from {os.getcwd()}{Color.RESET}")

        ensure_dir(self.output_dir)
        self.analyzer = APKAnalyzer(apk_path, self.output_dir, self.logger,
                                    use_apktool=self.use_apktool)

        print(f"{Color.CYAN}[i] Analyzing APK structure...{Color.RESET}")
        try:
            if not self.analyzer.analyze():
                self.logger.error(f"{Color.FAIL}[!] APK analysis failed{Color.RESET}")
                return False
        except Exception as e:
            self.logger.error(f"{Color.FAIL}[!] APK analysis error: {e}{Color.RESET}")
            return False

        if not self.skip_pairip:
            print(f"{Color.YELLOW}[i] Detecting PairIP protection...{Color.RESET}")
            self._handle_pairip()
        else:
            self.logger.info(f"{Color.DIM}[*] Skipping PairIP processing (--skip-pairip){Color.RESET}")

        self._extract_artifacts()

        ext = os.path.splitext(apk_path)[1]
        output_apk = os.path.join(self.output_dir, f'{apk_name}_patched.apk')
        print(f"{Color.MAGENTA}[i] Rebuilding patched APK...{Color.RESET}")
        builder = APKBuilder(self.analyzer, output_apk, self.logger, self.keystore, use_apktool=self.use_apktool)
        final_apk = builder.build()

        if not final_apk or not os.path.isfile(final_apk):
            self.logger.error(f"{Color.FAIL}[!] APK building failed!{Color.RESET}")
            return False

        if not self.keep_decompile:
            self.analyzer.cleanup()

        # Remove temp files, keep only merged and patched APKs
        merged_name = f'{apk_name}_merged.apk'
        for f in os.listdir(self.output_dir):
            fpath = os.path.join(self.output_dir, f)
            if f == merged_name or os.path.abspath(fpath) == os.path.abspath(final_apk):
                continue
            try:
                if os.path.isfile(fpath):
                    os.remove(fpath)
                elif os.path.isdir(fpath):
                    shutil.rmtree(fpath, ignore_errors=True)
            except Exception:
                pass

        print(f"\n{Color.GREEN}[+] Done! Patched APK: {final_apk}{Color.RESET}")
        elapsed = time.time() - self.start_time
        print(f"{Color.GREEN}[+] Time: {elapsed:.1f}s{Color.RESET}")
        return True

    def _setup_logging(self, name: str):
        if not self.output_dir:
            default = '/tmp/pairip_output'
            if self.android_mode:
                default = os.path.join(os.path.expanduser('~'), 'pairip_output')
            self.output_dir = default
        ensure_dir(self.output_dir)
        log_file = os.path.join(self.output_dir, f'{name}_pairip_autopatcher.log')
        level = logging.DEBUG if self.verbose else logging.INFO
        self.logger = setup_logger(f'PairIP_{name}', log_file)

    def _handle_pairip(self):
        detector = PairIPDetector(self.analyzer, self.logger)
        pairip_findings = detector.detect()
        self.all_findings['pairip_detector'] = pairip_findings
        self.analyzer.apk_info['has_pairip'] = detector.has_pairip()

        patcher = PairIPPatcher(self.analyzer, pairip_findings, self.logger)
        if patcher.patch_all():
            self.all_findings['pairip_patches'] = patcher.patches_applied
            self.all_patches.extend(patcher.patches_applied)

    def _extract_artifacts(self):
        try:
            endpoints = list(set(self.analyzer.api_endpoints))
            if endpoints:
                ep_path = os.path.join(self.output_dir, 'extracted_api_endpoints.txt')
                with open(ep_path, 'w', encoding='utf-8') as f:
                    f.write('# API Endpoints extracted by PairIPAutoPatcher\n')
                    f.write(f'# Source: {self.analyzer.apk_path}\n\n')
                    for ep in sorted(endpoints):
                        f.write(f'{ep}\n')
                self.logger.info(f"    API endpoints saved: {ep_path}")

            license_endpoints = [ep for ep in endpoints if any(
                kw in ep.lower() for kw in
                ['license', 'validate', 'verify', 'receipt', 'subscription', 'purchase', 'iap', 'billing']
            )]
            if license_endpoints:
                le_path = os.path.join(self.output_dir, 'license_validation_endpoints.txt')
                with open(le_path, 'w', encoding='utf-8') as f:
                    f.write('# License/Subscription validation endpoints\n')
                    f.write(f'# Source: {self.analyzer.apk_path}\n\n')
                    for ep in sorted(license_endpoints):
                        f.write(f'{ep}\n')
                self.logger.info(f"    License endpoints saved: {le_path}")

            shared_prefs = self._extract_shared_prefs()
            if shared_prefs:
                sp_path = os.path.join(self.output_dir, 'shared_preferences_keys.txt')
                with open(sp_path, 'w', encoding='utf-8') as f:
                    f.write('# SharedPreferences keys extracted\n\n')
                    for sp in sorted(set(shared_prefs)):
                        f.write(f'{sp}\n')
                self.logger.info(f"    SharedPrefs keys saved: {sp_path}")

            strings_path = os.path.join(self.output_dir, 'extracted_strings.txt')
            self._extract_strings(strings_path)

        except Exception as e:
            self.logger.debug(f"    Artifact extraction error: {e}")

    def _extract_shared_prefs(self) -> List[str]:
        prefs = []
        patterns = [
            r'getSharedPreferences\s*\(\s*"([^"]+)"',
            r'getSharedPreferences\s*\(\s*\'([^\']+)\'',
            r'getPreferences\s*\(\s*"([^"]+)"',
            r'SharedPreferences\s+\w+\s*=\s*[^;]*getSharedPreferences\s*\(\s*"([^"]+)"',
            r'context\.getSharedPreferences\s*\(\s*"([^"]+)"',
            r'PreferenceManager\.getDefaultSharedPreferences',
        ]
        for smali_file in self.analyzer.all_smali_files:
            try:
                with open(smali_file, 'r', encoding='utf-8', errors='replace') as f:
                    content = f.read()
                for pat in patterns:
                    if pat == 'PreferenceManager.getDefaultSharedPreferences':
                        if pat in content:
                            prefs.append('default_preferences')
                    else:
                        for m in re.finditer(pat, content):
                            if m.group(1) not in prefs:
                                prefs.append(m.group(1))
            except Exception:
                pass
        return prefs

    def _extract_strings(self, output_path: str):
        try:
            strings = set()
            with open(output_path, 'w', encoding='utf-8') as f:
                f.write('# Strings extracted by PairIPAutoPatcher\n')
                f.write(f'# Source: {self.analyzer.apk_path}\n\n')

                for smali_file in self.analyzer.all_smali_files:
                    try:
                        with open(smali_file, 'r', encoding='utf-8', errors='replace') as fh:
                            content = fh.read()
                        for m in re.finditer(r'const-string\s+\w+,\s*"((?:[^"\\]|\\.)*)"', content):
                            s = m.group(1)
                            if len(s) > 3 and s not in strings and not s.startswith('0x'):
                                strings.add(s)
                                f.write(f'{s}\n')
                    except Exception:
                        pass

                for smali_file in self.analyzer.all_smali_files:
                    try:
                        with open(smali_file, 'r', encoding='utf-8', errors='replace') as fh:
                            content = fh.read()
                        for m in re.finditer(r'const-string\s+\w+,\s*\'(.)\'', content):
                            s = m.group(1)
                            if s not in strings:
                                strings.add(s)
                                f.write(f"'{s}'\n")
                    except Exception:
                        pass

            self.logger.info(f"    Strings extracted: {len(strings)} to {output_path}")
        except Exception as e:
            self.logger.debug(f"    String extraction error: {e}")


ANDROID_ARCH = None


def detect_android() -> bool:
    global ANDROID_ARCH
    if os.path.exists('/system/build.prop') or os.path.exists('/data/local/tmp'):
        try:
            import platform
            ANDROID_ARCH = platform.machine()
        except Exception:
            ANDROID_ARCH = 'arm64'
        return True
    return False


def main():
    parser = argparse.ArgumentParser(
        description='PairIPAutoPatcher - Automated Android APK Reverse Engineering Tool',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog='''
Examples:
  python3 pairip_autopatcher.py -i app.apk
  python3 pairip_autopatcher.py -i app.apks
  python3 pairip_autopatcher.py -i app.xapk -o ./output
  python3 pairip_autopatcher.py --batch --dir ./apks/
  python3 pairip_autopatcher.py -i app.apk --keystore ./my.keystore -v
        '''
    )

    target = parser.add_argument_group('Target')
    target.add_argument('-i', '--input', help='Path to APK/APKS/XAPK file (auto-detects extension)')
    target.add_argument('--dir', help='Directory containing APK files (for batch mode)')
    target.add_argument('--batch', action='store_true', help='Enable batch processing mode')

    output = parser.add_argument_group('Output')
    output.add_argument('--output-dir', '-o', default=None,
                       help='Output directory (default: <apk_dir>/<name>_patched/)')
    output.add_argument('--keep-decompile', action='store_true',
                       help='Keep decompiled files after building')
    output.add_argument('--keystore', default=None,
                       help='Custom keystore path for signing')

    engine = parser.add_argument_group('Engine')
    engine.add_argument('-a', '--apktool', action='store_true',
                       help='Use APKTool instead of APKEditor (slower, less stable)')

    skip = parser.add_argument_group('Options')
    skip.add_argument('--skip-pairip', action='store_true',
                     help='Skip PairIP detection and patching')

    misc = parser.add_argument_group('Miscellaneous')
    misc.add_argument('--verbose', '-v', action='store_true', help='Enable verbose debug output')
    misc.add_argument('--version', action='store_true', help='Show version and exit')
    misc.add_argument('--android', action='store_true',
                     help='Force Android/Termux mode (auto-detected on Android)')

    args = parser.parse_args()

    if args.version:
        banner = f"""{Color.CYAN}
╔══════════════════════════════════════╗
║     PairIPAutoPatcher v1.0.0        ║
║  Automated APK Reverse Engineering   ║
╚══════════════════════════════════════╝{Color.RESET}"""
        print(banner)
        return

    if not args.input and not (args.batch and args.dir):
        parser.print_help()
        print(f"\n{Color.FAIL}[!] Use -i <file.apk/.apks/.xapk> or --batch --dir <folder>{Color.RESET}")
        sys.exit(1)

    if args.android or detect_android():
        print(f"{Color.CYAN}[i] Android environment detected ({ANDROID_ARCH or 'unknown'}){Color.RESET}")

    patcher = PairIPAutoPatcher(args)
    success = patcher.run()
    sys.exit(0 if success else 1)


if __name__ == '__main__':
    main()
