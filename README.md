# Explorer Memory Scanner

**Explorer Memory Scanner** is a small Windows C++ tool that scans the memory of the `explorer.exe` process to detect executable files (EXE) loaded by PCA clients or the Explorer itself. It also checks if these files exist and whether they are digitally signed.

---

## Features

- Scans the memory of the Explorer process for EXE files.
- Detects PCAClient-related paths (containing `"trace,"`).
- Checks if found files exist on disk.
- Verifies digital signatures of files (Signed / Unsigned).
- Color-coded console output:
  - Yellow/Orange: Unsigned files
  - Red: Deleted files
  - Default color: Signed files

---

## Requirements

- Windows 10/11
- Visual Studio or a C++ compiler with Win32 API support.
- Administrator privileges to access other process memory.

---
