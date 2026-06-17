# RPairip

Automated PairIP protection removal tool for Android APK/APKS/XAPK files.

## Installation

### One-liner (auto-detect Termux/Linux)
```bash
curl -Ls https://raw.githubusercontent.com/c0derArmy/RPairip/main/RKPairip.sh | bash
```

### Manual
```bash
git clone https://github.com/c0derArmy/RPairip.git
cd RPairip
pip install -r requirements.txt
pip install .
```

## Usage

```bash
RPairip -i app.apks
RPairip -i app.apk -o ./patched_output
RPairip --batch --dir ./apk_folder/
```

### Options

| Flag | Description |
|------|-------------|
| `-i, --input` | Input APK/APKS/XAPK file |
| `-o, --output-dir` | Output directory |
| `--batch --dir` | Batch process all APKs in a directory |
| `--keep-decompile` | Keep decompiled smali files after build |
| `--keystore` | Custom keystore path for signing |
| `-a, --apktool` | Use apktool instead of APKEditor |
| `--skip-pairip` | Skip PairIP patching (analysis only) |

## What it does

1. **Merge** split APKs (APKS/XAPK) into single APK
2. **Decompile** DEX → smali
3. **Detect** PairIP protection (native libs, smali, assets)
4. **Patch** — stub PairIP classes, rename native libs, switch Application superclass
5. **Rebuild** smali → DEX
6. **Sign** the patched APK
7. **Zip-align** for optimal storage

## Requirements

- Python 3.8+
- Java 17+ (auto-installed on Termux/Linux)
- Internet for first run (APKEditor.jar download)
