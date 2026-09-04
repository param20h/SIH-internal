from app.ai.url_analysis import analyze_urls, extract_links

TEST_BRANDS = ["paypal.com", "docusign.com"]


def test_extract_links_from_html_anchors() -> None:
    html = '<a href="https://example.test/x">Click here</a>'
    links = extract_links(html, is_html=True)
    assert ("https://example.test/x", "Click here") in links


def test_extract_bare_urls_from_plain_text() -> None:
    text = "Visit https://example.test/path for details."
    links = extract_links(text, is_html=False)
    assert links == [("https://example.test/path", None)]


def test_no_urls_returns_empty_list() -> None:
    result = analyze_urls("Hello, no links here.", is_html=False)
    assert result.urls == []


def test_ip_literal_url_flagged() -> None:
    result = analyze_urls('<a href="http://185.220.101.9/x">click</a>', is_html=True, trusted_brands=TEST_BRANDS)
    assert len(result.urls) == 1
    assert result.urls[0].is_ip_literal is True
    assert result.urls[0].lookalike is None  # lookalike check doesn't apply to bare IPs


def test_anchor_text_mismatch_detected() -> None:
    html = '<a href="https://evil-tracker.test/r?x=1">Sign in at docusign.com</a>'
    result = analyze_urls(html, is_html=True, trusted_brands=TEST_BRANDS)
    url = result.urls[0]
    assert url.anchor_claimed_domain == "docusign.com"
    assert url.anchor_text_mismatch is True


def test_anchor_text_matching_href_is_not_a_mismatch() -> None:
    html = '<a href="https://docusign.com/sign">docusign.com</a>'
    result = analyze_urls(html, is_html=True, trusted_brands=TEST_BRANDS)
    assert result.urls[0].anchor_text_mismatch is False


def test_anchor_text_subdomain_is_not_a_mismatch() -> None:
    html = '<a href="https://checkout.paypal.com/pay">paypal.com</a>'
    result = analyze_urls(html, is_html=True, trusted_brands=TEST_BRANDS)
    assert result.urls[0].anchor_text_mismatch is False


def test_anchor_text_with_no_domain_pattern_is_not_a_mismatch() -> None:
    html = '<a href="https://example.test/x">Click here</a>'
    result = analyze_urls(html, is_html=True)
    assert result.urls[0].anchor_text_mismatch is False


def test_base64_redirect_param_unwrapped() -> None:
    # base64 for "http://phish.test/steal"
    import base64

    target = "http://phish.test/steal"
    encoded = base64.urlsafe_b64encode(target.encode()).decode().rstrip("=")
    html = f'<a href="https://redirector.test/go?next={encoded}">continue</a>'
    result = analyze_urls(html, is_html=True)
    assert result.urls[0].unwrapped_target == target


def test_urlencoded_redirect_param_unwrapped() -> None:
    html = '<a href="https://redirector.test/go?url=http%3A%2F%2Fphish.test%2Fsteal">continue</a>'
    result = analyze_urls(html, is_html=True)
    assert result.urls[0].unwrapped_target == "http://phish.test/steal"


def test_no_redirect_param_leaves_unwrapped_target_none() -> None:
    html = '<a href="https://example.test/page?id=42">page</a>'
    result = analyze_urls(html, is_html=True)
    assert result.urls[0].unwrapped_target is None


def test_lookalike_domain_surfaced_on_link_host() -> None:
    html = '<a href="https://paypaI.com/login">click</a>'
    result = analyze_urls(html, is_html=True, trusted_brands=TEST_BRANDS)
    assert result.urls[0].lookalike is not None
    assert any(m.matched_brand == "paypal.com" for m in result.urls[0].lookalike.matches)


def test_network_disabled_by_default_leaves_domain_intel_none() -> None:
    html = '<a href="https://example.test/x">click</a>'
    result = analyze_urls(html, is_html=True)
    assert result.urls[0].domain_intel is None
    assert result.urls[0].is_newly_registered is None


def test_duplicate_urls_deduplicated() -> None:
    html = (
        '<a href="https://example.test/x">one</a>'
        '<a href="https://example.test/x">two (same link)</a>'
    )
    result = analyze_urls(html, is_html=True)
    assert len(result.urls) == 1


def test_malformed_html_degrades_gracefully() -> None:
    result = analyze_urls("<a href='https://example.test'>unclosed", is_html=True)
    assert isinstance(result.urls, list)


def test_non_http_scheme_ignored() -> None:
    html = '<a href="mailto:someone@example.test">email me</a>'
    result = analyze_urls(html, is_html=True)
    assert result.urls == []
