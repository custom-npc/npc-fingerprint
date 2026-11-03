"""Test-environment helper only. If `rich` is not installed, alias the copy vendored inside pip so the renderer
can still be exercised. With the real dependency installed (normal case) this module does nothing."""
import sys

try:
    import rich  # noqa: F401
except ImportError:  # pragma: no cover
    import pip._vendor.rich as _r
    import pip._vendor.rich.console, pip._vendor.rich.text, pip._vendor.rich.style, pip._vendor.rich.segment  # noqa: F401
    sys.modules["rich"] = _r
    for _k in list(sys.modules):
        if _k.startswith("pip._vendor.rich."):
            sys.modules["rich." + _k[len("pip._vendor.rich."):]] = sys.modules[_k]
