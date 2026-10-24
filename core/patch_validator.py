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
        try:
            ast.parse(code)
            return True, "Valid Python syntax"
        except SyntaxError as e:
            return False, f"SyntaxError at line {e.lineno}: {e.msg}"
        except Exception as e:
            return False, f"Parsing error: {str(e)}"

    @staticmethod
    def clean_suggestion_block(raw_patch: str) -> str:
        """Strips markdown fences if present."""
        cleaned = raw_patch.strip()
        if cleaned.startswith("```suggestion"):
            cleaned = cleaned[len("```suggestion"):].strip()
        elif cleaned.startswith("```python"):
            cleaned = cleaned[len("```python"):].strip()
        elif cleaned.startswith("```"):
            cleaned = cleaned[3:].strip()
            
        if cleaned.endswith("```"):
            cleaned = cleaned[:-3].strip()
        return cleaned
