import ast
import re
from typing import Tuple

class PatchValidator:
    """
    Surgical safety validator: Ensures that generated patches:
    1. Are syntactically valid (no missing colons, parenthesis, indentation errors).
    2. Maintain appropriate whitespace and indent levels.
    """
    
    @staticmethod
    def validate_python_syntax(code: str) -> Tuple[bool, str]:
        if not code or not code.strip():
            return False, "Empty code snippet"
        try:
            ast.parse(code)
            return True, "Valid Python syntax"
        except SyntaxError as e:
            return False, f"SyntaxError at line {e.lineno}: {e.msg}"
        except Exception as e:
            return False, f"Parsing error: {str(e)}"

    @staticmethod
    def clean_suggestion_block(raw_patch: str) -> str:
        """Strips markdown fences if present without altering indentation."""
        if not raw_patch:
            return ""
        # Remove opening fence line (e.g. ```suggestion, ```python, ```py, ```)
        cleaned = re.sub(r"^```[a-zA-Z0-9_\-]*\r?\n", "", raw_patch.lstrip("\r\n"))
        # Remove closing fence at end
        cleaned = re.sub(r"\r?\n```\s*$", "", cleaned.rstrip())
        # Also handle one-line fences like ```code```
        if cleaned.startswith("```") and cleaned.endswith("```") and len(cleaned) >= 6:
            cleaned = cleaned[3:-3]
        return cleaned
