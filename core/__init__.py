"""
Kavach AI Core Security Engine Package.
"""
__version__ = "1.4.0"
from .diff_parser import DiffParser, ParsedFileDiff, DiffHunk, ChangedLine
from .surgical_analyzer import SurgicalAnalyzer, PatchFinding
from .ai_reasoner import AIReasoner
from .license_manager import LicenseManager, PlanTier
from .patch_validator import PatchValidator
from .billing import BillingManager
from .project_scanner import ProjectASTScanner, CrossFileTaintFinding
from .sca_scanner import SCAScanner, SCAReachabilityFinding

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
    "BillingManager",
    "ProjectASTScanner",
    "CrossFileTaintFinding",
    "SCAScanner",
    "SCAReachabilityFinding",
]
