from app.ai.lookalike_domain import analyze_domain

TEST_BRANDS = ["paypal.com", "microsoft.com", "apple.com", "google.com"]


def test_exact_trusted_domain_has_no_matches() -> None:
    result = analyze_domain("paypal.com", TEST_BRANDS)
    assert result.matches == []


def test_unrelated_domain_has_no_matches() -> None:
    result = analyze_domain("example-corp.test", TEST_BRANDS)
    assert result.matches == []


def test_single_char_typosquat_caught_by_levenshtein() -> None:
    result = analyze_domain("paypaI.com", TEST_BRANDS)
    assert any(m.method == "levenshtein" and m.matched_brand == "paypal.com" for m in result.matches)


def test_homoglyph_punycode_domain_caught() -> None:
    # xn--pple-43d.com decodes to "аpple.com" with a Cyrillic а
    result = analyze_domain("xn--pple-43d.com", TEST_BRANDS)
    assert result.is_punycode is True
    assert result.decoded_unicode is not None
    assert any(m.method == "homoglyph_skeleton" and m.matched_brand == "apple.com" for m in result.matches)


def test_digit_substitution_homoglyph_domain_caught() -> None:
    # micr0soft-online.com: "0" for "o" *and* an appended suffix -- this is
    # the case that needed the brand_substring check, since the *whole*
    # domain is far more than LEVENSHTEIN_MAX_DISTANCE edits from
    # "microsoft.com" once the "-online" suffix is included.
    result = analyze_domain("micr0soft-online.com", TEST_BRANDS)
    assert any(m.matched_brand == "microsoft.com" for m in result.matches)


def test_brand_plus_suffix_pattern_caught() -> None:
    result = analyze_domain("paypal-secure-login.com", TEST_BRANDS)
    hit = next((m for m in result.matches if m.matched_brand == "paypal.com"), None)
    assert hit is not None
    assert hit.method == "brand_substring"


def test_non_punycode_domain_reports_is_punycode_false() -> None:
    result = analyze_domain("microsoft.com", TEST_BRANDS)
    assert result.is_punycode is False
    assert result.decoded_unicode is None


def test_malformed_punycode_degrades_gracefully() -> None:
    # "xn--" prefix present but not valid punycode -- must not raise.
    result = analyze_domain("xn--not-valid-punycode-!!!.com", TEST_BRANDS)
    assert result.is_punycode is True
    assert result.decoded_unicode is None


def test_no_false_positive_on_short_unrelated_word_overlap() -> None:
    # Sanity check: a domain that happens to share a short substring with
    # a brand name shouldn't be flagged just for that.
    result = analyze_domain("googolplex-math-blog.test", TEST_BRANDS)
    assert result.matches == []


def test_custom_trusted_brand_list_is_respected() -> None:
    result = analyze_domain("paypaI.com", trusted_brands=["totallydifferent.com"])
    assert result.matches == []


def test_default_trusted_brands_loaded_from_config() -> None:
    from app.ai.lookalike_domain import TRUSTED_BRANDS

    assert "paypal.com" in TRUSTED_BRANDS
    assert len(TRUSTED_BRANDS) > 10
