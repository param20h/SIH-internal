"""Lookalike/typosquat domain detection against a configurable trusted-brand
baseline (the "Sacred Timeline").

Four independent signals, each cheap and fully offline:
  1. Homoglyph skeleton match -- normalize confusable characters (Cyrillic,
     Greek, digit-for-letter) to what they visually mimic; a domain whose
     skeleton exactly matches a trusted brand but whose actual characters
     don't is a strong impersonation signal.
  2. Levenshtein edit distance -- catches classic whole-domain typosquats
     (dropped/swapped/inserted characters).
  3. Jaro-Winkler similarity -- catches near-matches Levenshtein alone can
     under-weight, particularly prefix-preserving edits.
  4. Brand-plus-suffix substring match -- catches the extremely common
     "brand name + hyphenated suffix" pattern (e.g.
     "micr0soft-online.com", "paypal-secure-login.com") that whole-domain
     Levenshtein distance misses, since appending "-online" alone is
     several character edits even though the brand-impersonating part is
     an exact (or near-exact) match.

Punycode/IDN is also detected and reported independently, since an
IDN-encoded domain is worth surfacing regardless of which distance metric
fires.
"""

import re
from pathlib import Path
from typing import Literal

import yaml
from pydantic import BaseModel
from rapidfuzz.distance import JaroWinkler, Levenshtein

from app.ai.confusables import to_skeleton

_TRUSTED_BRANDS_PATH = Path(__file__).parent / "trusted_brands.yaml"
_TOKEN_SPLIT_RE = re.compile(r"[-_]")

LEVENSHTEIN_MAX_DISTANCE = 2
JARO_WINKLER_MIN_SIMILARITY = 0.92  # normalized_similarity is 0.0-1.0
TOKEN_MAX_DISTANCE = 1

MatchMethod = Literal["homoglyph_skeleton", "levenshtein", "jaro_winkler", "brand_substring"]


def _load_trusted_brands() -> list[str]:
    with _TRUSTED_BRANDS_PATH.open() as f:
        brands: list[str] = yaml.safe_load(f)
    return brands


TRUSTED_BRANDS = _load_trusted_brands()


class LookalikeMatch(BaseModel):
    matched_brand: str
    method: MatchMethod
    detail: str


class LookalikeAnalysis(BaseModel):
    domain: str
    is_punycode: bool
    decoded_unicode: str | None = None
    matches: list[LookalikeMatch]


def _first_label(domain: str) -> str:
    return domain.split(".")[0]


def _tokens(label: str) -> list[str]:
    return [t for t in _TOKEN_SPLIT_RE.split(label) if t]


def _decode_punycode(domain: str) -> str | None:
    if "xn--" not in domain.lower():
        return None
    try:
        return domain.encode("ascii").decode("idna")
    except (UnicodeError, UnicodeDecodeError):
        return None


def analyze_domain(domain: str, trusted_brands: list[str] | None = None) -> LookalikeAnalysis:
    brands = trusted_brands if trusted_brands is not None else TRUSTED_BRANDS
    domain = domain.lower().strip().rstrip(".")

    is_punycode = "xn--" in domain
    decoded = _decode_punycode(domain)
    display_form = decoded if decoded is not None else domain
    skeleton = to_skeleton(display_form)

    matches: list[LookalikeMatch] = []

    for brand in brands:
        brand_lower = brand.lower()
        if display_form == brand_lower:
            continue  # it IS the trusted domain, not a lookalike of it

        if skeleton == brand_lower:
            matches.append(
                LookalikeMatch(
                    matched_brand=brand,
                    method="homoglyph_skeleton",
                    detail=(
                        f"{domain!r} normalizes to {skeleton!r} via confusable-character "
                        f"substitution, an exact visual match for {brand!r}"
                    ),
                )
            )
            continue  # skeleton match is already the strongest signal available

        distance = Levenshtein.distance(display_form, brand_lower)
        if 0 < distance <= LEVENSHTEIN_MAX_DISTANCE:
            matches.append(
                LookalikeMatch(
                    matched_brand=brand,
                    method="levenshtein",
                    detail=f"{distance} character edit(s) away from {brand!r}",
                )
            )
            continue

        similarity = JaroWinkler.normalized_similarity(display_form, brand_lower)
        if similarity >= JARO_WINKLER_MIN_SIMILARITY:
            matches.append(
                LookalikeMatch(
                    matched_brand=brand,
                    method="jaro_winkler",
                    detail=f"{similarity:.0%} Jaro-Winkler similarity to {brand!r}",
                )
            )
            continue

        brand_token = _first_label(brand_lower)
        candidate_first_label = _first_label(skeleton)
        candidate_tokens = _tokens(candidate_first_label)
        if len(candidate_tokens) > 1:
            for token in candidate_tokens:
                token_distance = Levenshtein.distance(token, brand_token)
                if token_distance <= TOKEN_MAX_DISTANCE and len(token) >= len(brand_token) - 1:
                    matches.append(
                        LookalikeMatch(
                            matched_brand=brand,
                            method="brand_substring",
                            detail=(
                                f"{brand_token!r} appears as its own token in "
                                f"{candidate_first_label!r} (brand-plus-suffix pattern), "
                                f"{token_distance} edit(s) away"
                            ),
                        )
                    )
                    break

    return LookalikeAnalysis(
        domain=domain,
        is_punycode=is_punycode,
        decoded_unicode=decoded,
        matches=matches,
    )
