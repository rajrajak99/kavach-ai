import sys
import os
from pathlib import Path

_root = str(Path(__file__).resolve().parent.parent)
if _root not in sys.path or sys.path[0] != _root:
    if _root in sys.path:
        sys.path.remove(_root)
    sys.path.insert(0, _root)

# If kavach_license in sys.modules is an older version missing new symbols, purge it
if "kavach_license" in sys.modules:
    if not hasattr(sys.modules["kavach_license"], "generate_signed_license"):
        del sys.modules["kavach_license"]

try:
    from kavach_license import PlanTier, LicenseManager, generate_signed_license, verify_signed_license
except (ImportError, AttributeError):
    import importlib.util
    _lic_file = os.path.join(_root, "kavach_license.py")
    if os.path.exists(_lic_file):
        _spec = importlib.util.spec_from_file_location("kavach_license", _lic_file)
        _mod = importlib.util.module_from_spec(_spec)
        sys.modules["kavach_license"] = _mod
        _spec.loader.exec_module(_mod)
        PlanTier = _mod.PlanTier
        LicenseManager = _mod.LicenseManager
        generate_signed_license = _mod.generate_signed_license
        verify_signed_license = _mod.verify_signed_license
    else:
        raise

__all__ = ["PlanTier", "LicenseManager", "generate_signed_license", "verify_signed_license"]
