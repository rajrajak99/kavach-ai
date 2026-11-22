"""
Kavach AI - PyPI Release Automation Script
Usage:
  python publish_pypi.py --test      (Uploads to test.pypi.org)
  python publish_pypi.py --prod      (Uploads to official pypi.org)
"""
import sys
import glob
import subprocess
from pathlib import Path

def main():
    if len(sys.argv) < 2 or sys.argv[1] not in ["--test", "--prod"]:
        print("Usage:")
        print("  python publish_pypi.py --test   (Upload to TestPyPI for verification)")
        print("  python publish_pypi.py --prod   (Upload to Official PyPI for pip install)")
        sys.exit(1)

    mode = sys.argv[1]

    if mode == "--prod":
        confirm = input("⚠️  Are you SURE you want to upload a LIVE production release to pypi.org? [y/N]: ").strip().lower()
        if confirm not in ("y", "yes"):
            print("Aborted.")
            sys.exit(0)

    dist_dir = Path("dist")
    if dist_dir.exists():
        import shutil
        print("[*] Cleaning stale dist/ directory...")
        shutil.rmtree(dist_dir, ignore_errors=True)

    print("[*] Building fresh package artifacts with build...")
    subprocess.run([sys.executable, "-m", "build"], check=True)

    dist_files = glob.glob(str(dist_dir / "*"))
    if not dist_files:
        print("Error: No artifacts found in dist/ to upload.", file=sys.stderr)
        sys.exit(1)

    print("[*] Verifying package distribution with twine...")
    subprocess.run([sys.executable, "-m", "twine", "check"] + dist_files, check=True)

    if mode == "--test":
        print("\n[+] Uploading to TestPyPI...")
        cmd = [sys.executable, "-m", "twine", "upload", "--repository", "testpypi"] + dist_files
    else:
        print("\n[+] Uploading to Official PyPI (pypi.org)...")
        cmd = [sys.executable, "-m", "twine", "upload"] + dist_files

    print(f"Executing: {' '.join(cmd)}")
    subprocess.run(cmd, check=True)
    print("\n[✓] Release uploaded successfully!")

if __name__ == "__main__":
    main()
