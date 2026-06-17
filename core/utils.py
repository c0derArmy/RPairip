import os
import sys
import re
import shutil
import logging
import hashlib
import subprocess
import json
import time
import zipfile
import struct
import tempfile
from datetime import datetime
from pathlib import Path
from typing import Optional, List, Tuple, Dict, Any
from xml.etree import ElementTree

try:
    from rich.console import Console
    from rich.logging import RichHandler
    RICH_AVAILABLE = True
except ImportError:
    RICH_AVAILABLE = False

CONSOLE = Console() if RICH_AVAILABLE else None


JARS_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', '.jars')
os.makedirs(JARS_DIR, exist_ok=True)

JAR_URLS = {
    'APKEditor.jar': 'https://github.com/REAndroid/APKEditor/releases/download/V1.4.7/APKEditor-1.4.7.jar',
    'APKTool.jar': 'https://github.com/iBotPeaches/Apktool/releases/download/v2.9.3/apktool_2.9.3.jar',
}

JAR_CHECKSUMS = {
    'APKEditor.jar': None,
    'APKTool.jar': None,
}


def get_jar_path(name: str) -> str:
    return os.path.join(JARS_DIR, name)


def download_jar(name: str) -> Optional[str]:
    import urllib.request
    jar_path = get_jar_path(name)
    if os.path.isfile(jar_path):
        return jar_path
    url = JAR_URLS.get(name)
    if not url:
        return None
    print(f"{Color.CYAN}[i] Downloading {name}...{Color.RESET}")
    try:
        urllib.request.urlretrieve(url, jar_path)
        print(f"{Color.GREEN}[+] Downloaded {name}{Color.RESET}")
        return jar_path
    except Exception as e:
        print(f"{Color.FAIL}[!] Failed to download {name}: {e}{Color.RESET}")
        return None


def ensure_jar(name: str) -> Optional[str]:
    jar_path = get_jar_path(name)
    if os.path.isfile(jar_path):
        return jar_path
    return download_jar(name)


class Color:
    HEADER = '\033[95m'
    BLUE = '\033[94m'
    CYAN = '\033[96m'
    GREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    RED = '\033[91m'
    MAGENTA = '\033[95m'
    YELLOW = '\033[93m'
    WHITE = '\033[97m'
    RESET = '\033[0m'
    BOLD = '\033[1m'
    DIM = '\033[2m'

    @staticmethod
    def colorize(text, color_code):
        return f"{color_code}{text}{Color.RESET}"


def setup_logger(name: str = "PairIPAutoPatcher", log_file: Optional[str] = None) -> logging.Logger:
    logger = logging.getLogger(name)
    logger.setLevel(logging.DEBUG)

    if log_file:
        fh = logging.FileHandler(log_file, encoding='utf-8')
        fh.setLevel(logging.DEBUG)
        fh.setFormatter(logging.Formatter('%(asctime)s [%(levelname)s] %(message)s'))
        logger.addHandler(fh)

    if RICH_AVAILABLE:
        rh = RichHandler(console=CONSOLE, show_time=False, show_path=False, rich_tracebacks=True)
        rh.setLevel(logging.INFO)
        logger.addHandler(rh)
    else:
        ch = logging.StreamHandler()
        ch.setLevel(logging.INFO)
        ch.setFormatter(logging.Formatter('[%(levelname)s] %(message)s'))
        logger.addHandler(ch)

    return logger


def run_command_stream(cmd: List[str], timeout: int = 300, cwd: Optional[str] = None, prefix: str = "",
                       show_lines: Optional[List[str]] = None) -> Tuple[int, str, str]:
    try:
        if shutil.which('stdbuf'):
            cmd = ['stdbuf', '-oL', '-eL'] + cmd
        proc = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            cwd=cwd,
            bufsize=0,
            universal_newlines=True
        )
        out_lines = []
        for line in proc.stdout:
            line = line.rstrip('\n')
            out_lines.append(line)
            if line.strip():
                if show_lines:
                    for pat in show_lines:
                        if re.search(pat, line):
                            print(f"{prefix}{line}")
                            break
                else:
                    print(f"{prefix}{line}")
        proc.wait(timeout=timeout)
        return proc.returncode, '\n'.join(out_lines), ''
    except subprocess.TimeoutExpired:
        try: proc.kill()
        except: pass
        return -1, '', f"Command timed out after {timeout}s: {' '.join(cmd)}"
    except FileNotFoundError:
        return -2, '', f"Command not found: {cmd[0]}"
    except Exception as e:
        return -3, '', str(e)


def run_command(cmd: List[str], timeout: int = 300, cwd: Optional[str] = None) -> Tuple[int, str, str]:
    try:
        proc = subprocess.run(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=timeout,
            cwd=cwd
        )
        return proc.returncode, proc.stdout.decode('utf-8', errors='replace'), proc.stderr.decode('utf-8', errors='replace')
    except subprocess.TimeoutExpired:
        return -1, '', f"Command timed out after {timeout}s: {' '.join(cmd)}"
    except FileNotFoundError:
        return -2, '', f"Command not found: {cmd[0]}"
    except Exception as e:
        return -3, '', str(e)


def find_tool_path(name: str) -> Optional[str]:
    which = shutil.which(name)
    if which:
        return which
    common_locations = [
        f"/usr/bin/{name}", f"/usr/local/bin/{name}",
        f"/opt/android-sdk/build-tools/36.0.0/{name}",
        f"/opt/android-sdk/build-tools/35.0.0/{name}",
        f"/opt/android-sdk/build-tools/34.0.0/{name}",
        f"/usr/lib/android-sdk/build-tools/debian/{name}",
        f"{os.path.expanduser('~')}/Android/Sdk/build-tools/36.0.0/{name}",
        f"{os.path.expanduser('~')}/Android/Sdk/build-tools/35.0.0/{name}",
        f"{os.path.expanduser('~')}/Android/Sdk/build-tools/34.0.0/{name}",
        f"{os.path.expanduser('~')}/android-sdk/build-tools/36.0.0/{name}",
        f"{os.path.expanduser('~')}/android-sdk/build-tools/35.0.0/{name}",
        f"{os.path.expanduser('~')}/android-sdk/build-tools/34.0.0/{name}",
        f"{os.path.expanduser('~')}/.local/bin/{name}",
        f"/data/data/com.termux/files/usr/bin/{name}",
        f"/data/data/com.termux/files/usr/local/bin/{name}",
    ]
    for loc in common_locations:
        if os.path.isfile(loc) and os.access(loc, os.X_OK):
            return loc
    return None


def generate_debug_keystore(path: str) -> bool:
    keytool = find_tool_path('keytool')
    if not keytool:
        return False
    if os.path.isfile(path):
        return True
    os.makedirs(os.path.dirname(path), exist_ok=True)
    cmd = [
        keytool, '-genkey', '-v',
        '-keystore', path,
        '-alias', 'androiddebugkey',
        '-storepass', 'android',
        '-keypass', 'android',
        '-keyalg', 'RSA',
        '-keysize', '2048',
        '-validity', '10000',
        '-dname', 'CN=Android Debug, OU=Debug, O=Android, L=Unknown, ST=Unknown, C=US'
    ]
    ret, out, err = run_command(cmd, timeout=30)
    return ret == 0


class CRC32Fixer:
    def __init__(self, logger: logging.Logger):
        self.logger = logger

    def fix_dex_crc(self, dex_path: str) -> bool:
        try:
            with open(dex_path, 'rb') as f:
                data = bytearray(f.read())
            actual_crc = zlib_crc32(data[8:]) & 0xFFFFFFFF
            struct.pack_into('<I', data, 8, actual_crc)
            with open(dex_path, 'wb') as f:
                f.write(data)
            self.logger.debug(f"Fixed CRC32 for {dex_path}: 0x{actual_crc:08X}")
            return True
        except Exception as e:
            self.logger.error(f"Failed to fix CRC for {dex_path}: {e}")
            return False

    def fix_all_dex_in_apk(self, apk_path: str) -> bool:
        try:
            import zipfile
            import tempfile
            temp_dir = tempfile.mkdtemp()
            fixed_apk = apk_path + '.fixed.apk'
            with zipfile.ZipFile(apk_path, 'r') as zin:
                with zipfile.ZipFile(fixed_apk, 'w', zipfile.ZIP_DEFLATED) as zout:
                    for item in zin.infolist():
                        data = zin.read(item.filename)
                        if item.filename.endswith('.dex'):
                            actual_crc = zlib_crc32(data[8:]) & 0xFFFFFFFF
                            data_fixed = bytearray(data)
                            struct.pack_into('<I', data_fixed, 8, actual_crc)
                            data = bytes(data_fixed)
                            self.logger.debug(f"Fixed CRC for {item.filename}")
                        zout.writestr(item, data)
            shutil.move(fixed_apk, apk_path)
            shutil.rmtree(temp_dir, ignore_errors=True)
            return True
        except Exception as e:
            self.logger.error(f"Failed to fix DEX CRC in APK: {e}")
            return False


def zlib_crc32(data: bytes) -> int:
    import zlib
    return zlib.crc32(data)

def ensure_dir(path: str):
    os.makedirs(path, exist_ok=True)

def safe_delete(path: str):
    try:
        if os.path.isfile(path):
            os.remove(path)
        elif os.path.isdir(path):
            shutil.rmtree(path, ignore_errors=True)
    except Exception:
        pass

def get_file_hash(path: str) -> str:
    h = hashlib.sha256()
    with open(path, 'rb') as f:
        for chunk in iter(lambda: f.read(65536), b''):
            h.update(chunk)
    return h.hexdigest()

def human_size(size_bytes: int) -> str:
    for unit in ['B', 'KB', 'MB', 'GB']:
        if size_bytes < 1024:
            return f"{size_bytes:.1f} {unit}"
        size_bytes /= 1024
    return f"{size_bytes:.1f} TB"

class SmaliHelper:
    @staticmethod
    def make_method_return_true(method_body: str) -> str:
        lines = method_body.split('\n')
        new_lines = []
        for line in lines:
            stripped = line.strip()
            if stripped.startswith('#'):
                new_lines.append(line)
                continue
            if '.registers' in stripped or '.locals' in stripped:
                new_lines.append(line)
                continue
            if '.prologue' in stripped:
                new_lines.append(line)
                continue
            if 'const/' in stripped or 'return-' in stripped:
                continue
            if '.end method' in stripped:
                new_lines.append('    const/4 v0, 0x1')
                new_lines.append('    return v0')
                new_lines.append(line)
                continue
        return '\n'.join(new_lines)

    @staticmethod
    def make_method_return_false(method_body: str) -> str:
        lines = method_body.split('\n')
        new_lines = []
        for line in lines:
            stripped = line.strip()
            if stripped.startswith('#'):
                new_lines.append(line)
                continue
            if '.registers' in stripped or '.locals' in stripped:
                new_lines.append(line)
                continue
            if '.prologue' in stripped:
                new_lines.append(line)
                continue
            if 'const/' in stripped or 'return-' in stripped:
                continue
            if '.end method' in stripped:
                new_lines.append('    const/4 v0, 0x0')
                new_lines.append('    return v0')
                new_lines.append(line)
                continue
        return '\n'.join(new_lines)

    @staticmethod
    def make_method_return_one(method_body: str) -> str:
        return SmaliHelper.make_method_return_true(method_body)

    @staticmethod
    def make_method_void_nop(method_body: str) -> str:
        lines = method_body.split('\n')
        new_lines = []
        for line in lines:
            stripped = line.strip()
            if stripped.startswith('#'):
                new_lines.append(line)
                continue
            if '.registers' in stripped or '.locals' in stripped:
                new_lines.append(line)
                continue
            if '.prologue' in stripped:
                new_lines.append(line)
                continue
            if '.end method' in stripped:
                new_lines.append('    return-void')
                new_lines.append(line)
                continue
        return '\n'.join(new_lines)

    @staticmethod
    def extract_method_body(smali_content: str, method_name: str, descriptor: str = None) -> Optional[str]:
        pattern = re.compile(
            r'\.method\s+.*\s+' + re.escape(method_name) +
            (r'\(' + re.escape(descriptor.split(')')[0][1:]) + r'\)' if descriptor else r'\(.*?\).*?') +
            r'.*?\n(.*?)\.end\s+method',
            re.DOTALL
        )
        match = pattern.search(smali_content)
        if match:
            return f".method {match.group(0)}"
        alt = re.compile(
            r'\.method\s+.*\s+' + re.escape(method_name) + r'.*?\n(.*?)\.end\s+method',
            re.DOTALL
        )
        m2 = alt.search(smali_content)
        if m2:
            return f".method {m2.group(0)}"
        return None

    @staticmethod
    def find_methods_by_return_type(smali_content: str, return_type: str = 'Z') -> List[str]:
        regex = rf'\.method\s+.*\s+\w+\(.*?\){re.escape(return_type)}\s*'
        matches = re.findall(r'\.method\s+(?:public|private|protected|static|final|native)?\s*(\w+)\(.*?\)' + re.escape(return_type), smali_content)
        return matches

    @staticmethod
    def replace_method_body(smali_content: str, method_name: str, new_body: str) -> str:
        pattern = re.compile(
            r'\.method\s+.*\s+' + re.escape(method_name) + r'.*?\n.*?\.end\s+method',
            re.DOTALL
        )
        return pattern.sub(new_body, smali_content)
