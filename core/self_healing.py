import os
import shutil
import subprocess
import shlex
import time
from pathlib import Path
from typing import List, Dict, Any, Optional
from dataclasses import dataclass

from .surgical_analyzer import PatchFinding
from .patch_validator import PatchValidator

@dataclass
class HealingResult:
    target_file: str
    patches_attempted: int
    patches_applied: int
    status: str  # "VERIFIED_PASSED", "ROLLBACK_TEST_FAILED", "ROLLBACK_SYNTAX_ERROR", "NO_PATCHES"
    test_exit_code: Optional[int]
    test_output: str
    duration_seconds: float
    message: str

class SelfHealingTestRunner:
    """
    Autonomous Self-Healing Engine:
    1. Creates atomic backup of candidate code.
    2. Applies surgical patches line by line.
    3. Validates Python syntax integrity.
    4. Runs project test suite (e.g. pytest or custom command).
    5. Locks in fix if tests pass; atomically rolls back if tests fail or crash.
    """

    def __init__(self, default_test_cmd: str = "pytest", timeout_seconds: int = 30):
        self.default_test_cmd = default_test_cmd
        self.timeout_seconds = timeout_seconds

    def apply_single_patch_to_lines(self, lines: List[str], finding: PatchFinding) -> bool:
        """Replace problem line with fixed code safely."""
        target_idx = finding.line_number - 1
        if 0 <= target_idx < len(lines):
            clean_fixed = PatchValidator.clean_suggestion_block(finding.fixed_code)
            orig_line = lines[target_idx]
            orig_indent = orig_line[:len(orig_line) - len(orig_line.lstrip())]
            
            fixed_lines = clean_fixed.splitlines()
            if fixed_lines:
                indented_fixed = []
                for idx, fl in enumerate(fixed_lines):
                    if idx > 0 and not fl.startswith(" ") and orig_indent:
                        indented_fixed.append(orig_indent + fl)
                    elif idx == 0 and not fl.startswith(" ") and orig_indent:
                        indented_fixed.append(orig_indent + fl)
                    else:
                        indented_fixed.append(fl)
                
                lines[target_idx] = "\n".join(indented_fixed) + "\n"
                return True
        return False

    def heal_file(
        self,
        file_path: str,
        findings: List[PatchFinding],
        test_command: Optional[str] = None,
        working_dir: Optional[str] = None
    ) -> HealingResult:
        start_time = time.time()
        p = Path(file_path).resolve()
        
        if not p.exists() or not p.is_file():
            return HealingResult(
                target_file=str(p),
                patches_attempted=0,
                patches_applied=0,
                status="NO_PATCHES",
                test_exit_code=None,
                test_output="Target file does not exist",
                duration_seconds=0.0,
                message="Target file not found"
            )

        if not findings:
            return HealingResult(
                target_file=str(p),
                patches_attempted=0,
                patches_applied=0,
                status="NO_PATCHES",
                test_exit_code=0,
                test_output="No findings to patch",
                duration_seconds=0.0,
                message="No issues detected in file"
            )

        # 1. Create Atomic Backup
        backup_path = p.with_suffix(p.suffix + ".autopatch_bak")
        shutil.copy2(p, backup_path)

        cmd = test_command or self.default_test_cmd
        cwd = working_dir or str(p.parent)

        try:
            # Read original content lines
            with open(p, "r", encoding="utf-8", errors="ignore") as f:
                lines = f.readlines()

            # Apply patches in reverse order of line numbers to preserve line index alignment
            sorted_findings = sorted(findings, key=lambda f: f.line_number, reverse=True)
            applied_count = 0

            for finding in sorted_findings:
                if self.apply_single_patch_to_lines(lines, finding):
                    applied_count += 1

            new_content = "".join(lines)

            # 2. Syntax integrity check for Python files
            if p.suffix.lower() == ".py":
                is_valid_syntax, err_msg = PatchValidator.validate_python_syntax(new_content)
                if not is_valid_syntax:
                    shutil.copy2(backup_path, p)
                    if backup_path.exists():
                        os.remove(backup_path)
                    return HealingResult(
                        target_file=str(p),
                        patches_attempted=len(findings),
                        patches_applied=0,
                        status="ROLLBACK_SYNTAX_ERROR",
                        test_exit_code=-1,
                        test_output=err_msg,
                        duration_seconds=time.time() - start_time,
                        message=f"Patch caused syntax error: {err_msg}. Safely rolled back."
                    )

            # Write patched file
            with open(p, "w", encoding="utf-8") as f:
                f.write(new_content)

            # 3. Run Test Command safely without shell=True
            try:
                if isinstance(cmd, str):
                    cmd_tokens = shlex.split(cmd)
                else:
                    cmd_tokens = list(cmd)

                if cmd_tokens and not Path(cmd_tokens[0]).is_file():
                    resolved_bin = shutil.which(cmd_tokens[0])
                    if resolved_bin:
                        cmd_tokens[0] = resolved_bin

                test_proc = subprocess.run(
                    cmd_tokens,
                    shell=False,
                    cwd=cwd,
                    capture_output=True,
                    text=True,
                    timeout=self.timeout_seconds
                )
                test_exit = test_proc.returncode
                test_stdout = (test_proc.stdout or "") + "\n" + (test_proc.stderr or "")
            except subprocess.TimeoutExpired:
                test_exit = 124
                test_stdout = f"Test command timed out after {self.timeout_seconds}s"
            except Exception as e:
                test_exit = 1
                test_stdout = f"Failed to execute test command: {str(e)}"

            # 4. Verify or Rollback
            if test_exit == 0:
                # Tests passed! Lock in the patch
                if backup_path.exists():
                    os.remove(backup_path)
                return HealingResult(
                    target_file=str(p),
                    patches_attempted=len(findings),
                    patches_applied=applied_count,
                    status="VERIFIED_PASSED",
                    test_exit_code=0,
                    test_output=test_stdout.strip(),
                    duration_seconds=time.time() - start_time,
                    message=f"Successfully applied {applied_count} patch(es). All tests verified green!"
                )
            else:
                # Tests failed or regression detected! Rollback atomically
                shutil.copy2(backup_path, p)
                if backup_path.exists():
                    os.remove(backup_path)
                return HealingResult(
                    target_file=str(p),
                    patches_attempted=len(findings),
                    patches_applied=applied_count,
                    status="ROLLBACK_TEST_FAILED",
                    test_exit_code=test_exit,
                    test_output=test_stdout.strip(),
                    duration_seconds=time.time() - start_time,
                    message=f"Tests failed (code {test_exit}). Patch automatically rolled back to protect system."
                )

        except Exception as e:
            # Emergency rollback
            if backup_path.exists():
                shutil.copy2(backup_path, p)
                os.remove(backup_path)
            return HealingResult(
                target_file=str(p),
                patches_attempted=len(findings),
                patches_applied=0,
                status="ROLLBACK_TEST_FAILED",
                test_exit_code=-1,
                test_output=str(e),
                duration_seconds=time.time() - start_time,
                message=f"Unexpected error during healing: {str(e)}"
            )

    def apply_patch_and_verify(
        self,
        target_file: Any,
        patch_content: str,
        test_command: Optional[str] = None
    ) -> Any:
        """Compatibility wrapper for ci_bot."""
        class MockResult:
            def __init__(self, success: bool, message: str):
                self.success = success
                self.message = message
                self.status = "VERIFIED_PASSED" if success else "ROLLBACK_TEST_FAILED"

        fpath = str(target_file)
        res = self.heal_file(fpath, [], test_command=test_command)
        return MockResult(res.status == "VERIFIED_PASSED", res.message)
