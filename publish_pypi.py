"""
AutoPatch AI - PyPI Release Automation Script
Usage:
  python publish_pypi.py --test      (Uploads to test.pypi.org)
  python publish_pypi.py --prod      (Uploads to official pypi.org)
"""
import os
import sys
import subprocess
from pathlib import Path

def main():
    if len(sys.argv) < 2 or sys.argv[1] not in ["--test", "--prod"]:
        print("Usage:")
        print("  python publish_pypi.py --test   (Upload to TestPyPI for verification)")
        print("  python publish_pypi.py --prod   (Upload to Official PyPI for pip install)")
        sys.exit(1)

    mode = sys.argv[1]
    dist_dir = Path("dist")
    if not dist_dir.exists() or not list(dist_dir.glob("*.whl")):
        print("[*] Building package artifacts...")
        subprocess.run([sys.executable, "-m", "build"], check=True)

    print("[*] Verifying package distribution with twine...")
    subprocess.run(["twine", "check", "dist/*"], check=True)

    if mode == "--test":
        print("\n[+] Uploading to TestPyPI...")
        cmd = ["twine", "upload", "--repository", "testpypi", "dist/*"]
    else:
        print("\n[+] Uploading to Official PyPI (pypi.org)...")
        cmd = ["twine", "upload", "dist/*"]

    print(f"Executing: {' '.join(cmd)}")
    subprocess.run(cmd)

if __name__ == "__main__":
    main()
