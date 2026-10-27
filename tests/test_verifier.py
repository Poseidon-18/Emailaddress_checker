import verifier as v


def test_syntax():
    assert v.check_syntax("a@b.com") == ("b.com", None)
    for bad in ["plain", "a@@b.com", "a b@c.com", "a@b", ".a@b.com", "a..b@c.com", "a@-b.com"]:
        assert v.check_syntax(bad)[1]


def test_classify():
    assert v.classify(250, "OK")[0] == v.DELIVERABLE
    assert v.classify(550, "5.1.1 User unknown")[0] == v.UNDELIVERABLE
    assert v.classify(550, "5.7.1 blocked by spamhaus")[0] == v.UNKNOWN
    assert v.classify(451, "try later")[0] == v.UNKNOWN


def test_pipeline(monkeypatch):
    monkeypatch.setattr(v, "resolve_mx", lambda d: ("ok", ["mx.test"]))
    monkeypatch.setattr(v, "smtp_available", lambda: (True, ""))
    monkeypatch.setattr(v, "_public", lambda h: True)
    monkeypatch.setattr(v, "smtp_rcpt", lambda *a: (250, "OK", False))
    assert v.check_email("x@ok.test")["status"] == v.DELIVERABLE
    monkeypatch.setattr(v, "smtp_rcpt", lambda *a: (250, "OK", True))
    assert v.check_email("x@catchall.test")["status"] == v.UNKNOWN
    monkeypatch.setattr(v, "smtp_available", lambda: (False, "blocked"))
    assert v.check_email("x@blocked.test")["status"] == v.UNKNOWN
    monkeypatch.setattr(v, "resolve_mx", lambda d: ("nxdomain", []))
    assert v.check_email("x@gone.test")["status"] == v.UNDELIVERABLE
