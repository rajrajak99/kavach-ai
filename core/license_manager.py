try:
    from kavach_license import PlanTier, LicenseManager, generate_signed_license, verify_signed_license
except ImportError:
    import sys
    from pathlib import Path
    _root = str(Path(__file__).resolve().parent.parent)
    if _root not in sys.path:
        sys.path.insert(0, _root)
    from kavach_license import PlanTier, LicenseManager, generate_signed_license, verify_signed_license

__all__ = ["PlanTier", "LicenseManager", "generate_signed_license", "verify_signed_license"]
