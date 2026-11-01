"""
Kavach AI Core Security Engine Package.
"""
from .diff_parser import DiffParser, ParsedFileDiff, DiffHunk, ChangedLine
from .surgical_analyzer import SurgicalAnalyzer, PatchFinding
from .ai_reasoner import AIReasoner
from .license_manager import LicenseManager, PlanTier
from .patch_validator import PatchValidator

__all__ = [
    "DiffParser",
    "ParsedFileDiff",
    "DiffHunk",
    "ChangedLine",
    "SurgicalAnalyzer",
    "PatchFinding",
    "AIReasoner",
    "LicenseManager",
    "PlanTier",
    "PatchValidator",
]
