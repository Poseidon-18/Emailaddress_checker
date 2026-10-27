"""Email deliverability checks: syntax -> DNS -> (optional) SMTP RCPT probe.The SMTP probe stops after RCPT TO. It never issues DATA, so no message is sent.
"""
import ipaddress, os, re, secrets, smtplib, socket, threading, time
from concurrent.futures import ThreadPoolExecutor

import dns.exception, dns.resolver

DELIVERABLE, UNDELIVERABLE, UNKNOWN = "deliverable", "undeliverable", "unknown"

HELO_HOST = os.getenv("PROBE_HELO", "mail-checker.example.com")
MAIL_FROM = os.getenv("PROBE_MAIL_FROM", "probe@mail-checker.example.com")
SMTP_TIMEOUT = float(os.getenv("SMTP_TIMEOUT", "6"))
DNS_TIMEOUT = float(os.getenv("DNS_TIMEOUT", "4"))
SMTP_MODE = os.getenv("SMTP_PROBE", "auto").lower()  
MAX_ADDRESSES = int(os.getenv("MAX_ADDRESSES", "50"))

LOCAL_RE = re.compile(r"^[A-Za-z0-9!#$%&'*+/=?^_`{|}~-]+(\.[A-Za-z0-9!#$%&'*+/=?^_`{|}~-]+)*$")
LABEL_RE = re.compile(r"^(?!-)[A-Za-z0-9-]{1,63}(?<!-)$")
USER_GONE = re.compile(r"5\.1\.[1-6]|user unknown|no such (user|mailbox|recipient|address)|does not exist|"
                       r"unknown (user|recipient)|mailbox (not found|unavailable)|invalid (mailbox|recipient|address)|"
                       r"recipient (rejected|not found)|address rejected", re.I)
POLICY = re.compile(r"block|spam|blacklist|blocklist|denied|reputation|policy|spamhaus|rbl|not allowed|banned|"
                    r"access|relay|authenticat", re.I)
DISPOSABLE = {"mailinator.com", "guerrillamail.com", "10minutemail.com", "tempmail.com", "yopmail.com",
              "trashmail.com", "sharklasers.com", "getnada.com", "throwawaymail.com", "dispostable.com"}
ROLE = {"admin", "info", "support", "sales", "contact", "postmaster", "webmaster", "noreply", "no-reply", "abuse"}

_catch_all = {}            ## using boolean for domain, simple true-false
_lock = threading.Lock()
_smtp_state = {"t": 0, "ok": None, "why": ""}


def check_syntax(addr):
    """Return (domain, None) if valid, else (None, reason)."""
    if addr.count("@") != 1:
        return None, "Must contain exactly one @"
    local, domain = addr.split("@")
    if not local or not domain:
        return None, "Missing local part or domain"
    if len(addr) > 254 or len(local) > 64:
        return None, "Address too long"
    if not LOCAL_RE.match(local):
        return None, "Invalid characters in local part"
    try:
        domain = domain.encode("idna").decode("ascii").lower()
    except UnicodeError:
        return None, "Invalid domain"
    labels = domain.split(".")
    if len(labels) < 2 or not all(LABEL_RE.match(l) for l in labels) or labels[-1].isdigit():
        return None, "Invalid domain"
    return domain, None


def resolve_mx(domain):
    """Return (state, hosts). state: ok | nxdomain | null | nomail | error."""
    r = dns.resolver.Resolver()
    r.lifetime = r.timeout = DNS_TIMEOUT
    try:
        recs = sorted((a.preference, str(a.exchange).rstrip(".")) for a in r.resolve(domain, "MX"))
        if len(recs) == 1 and recs[0][1] == "":
            return "null", []                      # RFC 7505: domain refuses all mail
        return "ok", [h for _, h in recs]
    except dns.resolver.NXDOMAIN:
        return "nxdomain", []
    except dns.resolver.NoAnswer:
        for rtype in ("A", "AAAA"):                # RFC 5321 implicit MX
            try:
                r.resolve(domain, rtype)
                return "ok", [domain]
            except dns.resolver.NoAnswer:
                continue
            except dns.exception.DNSException:
                return "error", []
        return "nomail", []
    except dns.exception.DNSException:
        return "error", []


def smtp_available():
    """Can this host open outbound port 25? Cached for 5 minutes."""
    if SMTP_MODE == "off":
        return False, "Disabled by SMTP_PROBE=off"
    if SMTP_MODE == "on":
        return True, "Forced on by SMTP_PROBE=on"
    if time.time() - _smtp_state["t"] > 300:
        try:
            socket.create_connection(("gmail-smtp-in.l.google.com", 25), timeout=4).close()
            _smtp_state.update(ok=True, why="Outbound port 25 is open")
        except OSError as e:
            __smtp_state.update(ok=False, why="Outbound port 25 is blocked on this host")
        _smtp_state["t"] = time.time()
    return _smtp_state["ok"], _smtp_state["why"]


def classify(code, msg):
    """Map an RCPT TO reply to (status, reason)."""
    if code in (250, 251):
        return DELIVERABLE, "Mail server accepted the recipient"
    if 500 <= code < 600:
        if USER_GONE.search(msg):
            return UNDELIVERABLE, "Mail server says the mailbox does not exist"
        if POLICY.search(msg):
            return UNKNOWN, "Mail server refused the check (policy or block)"
        if code in (550, 551, 553):
            return UNDELIVERABLE, "Mail server rejected the recipient"
        if code == 552:
            return UNKNOWN, "Mailbox exists but may be full"
    if 400 <= code < 500:
        return UNKNOWN, "Temporary refusal (greylisting or rate limit)"
    return UNKNOWN, f"Unexpected server reply {code}"


def _public(host):
    try:
        return all(ipaddress.ip_address(i[4][0]).is_global for i in socket.getaddrinfo(host, 25, proto=socket.IPPROTO_TCP))
    except (OSError, ValueError):
        return False


def smtp_rcpt(host, addr, domain, test_catch_all):
    """One SMTP session: EHLO, MAIL FROM, RCPT TO (and RCPT for a random address to spot catch-alls)."""
    with smtplib.SMTP(host, 25, local_hostname=HELO_HOST, timeout=SMTP_TIMEOUT) as s:
        s.ehlo()
        code, msg = s.mail(MAIL_FROM)
        if code >= 400:
            return code, msg.decode(errors="replace"), None
        code, msg = s.rcpt(addr)
        catch = None
        if code in (250, 251) and test_catch_all:
            s.rset(); s.mail(MAIL_FROM)
            catch = s.rcpt(f"{secrets.token_hex(6)}@{domain}")[0] in (250, 251)
        return code, msg.decode(errors="replace"), catch


def check_email(raw):
    addr = raw.strip()
    res = {"email": addr, "status": UNKNOWN, "reason": "", "mx": None, "smtp": None, "flags": []}
    domain, err = check_syntax(addr)
    if err:
        res.update(status=UNDELIVERABLE, reason=f"Invalid syntax: {err}")
        return res
    if domain in DISPOSABLE:
        res["flags"].append("disposable")
    if addr.split("@")[0].lower() in ROLE:
        res["flags"].append("role account")

    state, hosts = resolve_mx(domain)
    res["mx"] = hosts[0] if hosts else None
    if state in ("nxdomain", "nomail", "null"):
        why = {"nxdomain": "Domain does not exist", "nomail": "Domain has no mail server",
               "null": "Domain explicitly refuses mail (null MX)"}[state]
        res.update(status=UNDELIVERABLE, reason=why)
        return res
    if state == "error":
        res["reason"] = "DNS lookup failed or timed out; try again"
        return res

    ok, why = smtp_available()
    if not ok:
        res["reason"] = f"Domain accepts mail, but the mailbox could not be checked. {why}."
        return res

    last = "Could not connect to any mail server"
    for host in hosts[:2]:
        if not _public(host):
            last = "Mail server resolves to a non-public address; skipped"
            continue
        try:
            with _lock:
                known = domain in _catch_all
            code, msg, catch = smtp_rcpt(host, addr, domain, not known)
        except (OSError, smtplib.SMTPException) as e:
            last = f"Could not complete SMTP check ({e.__class__.__name__})"
            continue
        if catch is not None:
            with _lock:
                _catch_all[domain] = catch
        status, reason = classify(code, msg)
        res["smtp"] = f"{code} {msg[:120]}"
        if status == DELIVERABLE and _catch_all.get(domain):
            status, reason = UNKNOWN, "Server accepts every address (catch-all), so the mailbox cannot be confirmed"
        res.update(status=status, reason=reason, mx=host)
        return res
    res["reason"] = last
    return res


def parse_addresses(text):
    seen, out = set(), []
    for tok in re.split(r"[\s,;]+", text or ""):
        tok = tok.strip("<>\"'")
        if tok and tok.lower() not in seen:
            seen.add(tok.lower()); out.append(tok)
    return out


def check_many(addresses):
    with ThreadPoolExecutor(max_workers=8) as ex:
        return list(ex.map(check_email, addresses))
