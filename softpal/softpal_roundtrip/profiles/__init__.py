from __future__ import annotations

from .classic_softpal import ClassicSoftPalProfile


PROFILE_REGISTRY = {
    "classic-softpal": ClassicSoftPalProfile,
}


def load_profile(name: str = "classic-softpal") -> ClassicSoftPalProfile:
    try:
        factory = PROFILE_REGISTRY[name]
    except KeyError as exc:
        available = ", ".join(sorted(PROFILE_REGISTRY))
        raise ValueError(f"unknown profile {name!r}; available profiles: {available}") from exc
    return factory()


__all__ = ["ClassicSoftPalProfile", "PROFILE_REGISTRY", "load_profile"]
