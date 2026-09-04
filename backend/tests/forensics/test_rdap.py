from app.forensics import rdap


def test_network_disabled_by_default_returns_unavailable() -> None:
    rdap._CACHE.clear()
    result = rdap.lookup_domain_age("example-not-cached.test", enable_network=False)
    assert result.source == "unavailable"
    assert result.age_days is None


def test_cache_hit_short_circuits_network(monkeypatch) -> None:  # type: ignore[no-untyped-def]
    rdap._CACHE.clear()
    calls = {"count": 0}

    def fake_fetch(domain: str) -> rdap.DomainIntel:
        calls["count"] += 1
        return rdap.DomainIntel(domain=domain, source="live", age_days=100)

    monkeypatch.setattr(rdap, "_fetch_live", fake_fetch)

    first = rdap.lookup_domain_age("cached-example.test", enable_network=True)
    assert first.source == "live"
    assert calls["count"] == 1

    second = rdap.lookup_domain_age("cached-example.test", enable_network=True)
    assert second.source == "cached"
    assert second.age_days == 100
    assert calls["count"] == 1  # no second network call


def test_never_raises_on_unreachable_host() -> None:
    rdap._CACHE.clear()
    # Reserved TLD that will never resolve; must degrade, not raise.
    result = rdap.lookup_domain_age("does-not-exist.invalid", enable_network=True)
    assert result.source == "unavailable"
