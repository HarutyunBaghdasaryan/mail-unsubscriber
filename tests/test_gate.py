"""T1 (gate rejects) and T2 (gate accepts). Every reject must name the right reason."""

from conftest import GMAIL_AR, OUTLOOK_AR, SIG_ESP, SIG_NO_LU

from mail_unsubscriber import gate
from mail_unsubscriber.model import Code


def two(mk, **kw):
    return [mk(0, **kw), mk(1, **kw)]


# ---------- T2: accept ----------

def test_accepts_signed_aligned_one_click_gmail(mk):
    r = gate.check(two(mk))
    assert r.passed and r.code == Code.GATE_PASS
    assert r.unsub_url == "https://list.esp.example.net/u/abc123"  # ESP host is fine: the sender signed it


def test_accepts_outlook_shape(mk):
    r = gate.check(two(mk, ar=[OUTLOOK_AR], authserv=None))
    assert r.passed


def test_extra_unaligned_esp_signature_is_ignored(mk):
    from conftest import SIG_OK

    assert gate.check(two(mk, sigs=[SIG_OK, SIG_ESP])).passed


# ---------- T1: reject ----------

def test_dmarc_fail_anywhere(mk):
    bad = GMAIL_AR.replace("dmarc=pass", "dmarc=fail")
    msgs = two(mk) + [mk(5, ar=[bad])]
    assert gate.check(msgs).code == Code.DMARC_FAIL_SEEN


def test_needs_two_dmarc_passes(mk):
    assert gate.check([mk(0)]).code == Code.NOT_AUTHENTICATED


def test_messages_without_auth_do_not_count(mk):
    assert gate.check([mk(0), mk(1, ar=[])]).code == Code.NOT_AUTHENTICATED


def test_dmarc_about_other_domain(mk):
    other = GMAIL_AR.replace("header.from=news.example.com", "header.from=evil.example.org")
    assert gate.check(two(mk, ar=[other])).code == Code.NOT_AUTHENTICATED


def test_forged_auth_header_above_real_one(mk):
    forged = "evil.example.org; dmarc=pass header.from=news.example.com"
    assert gate.check(two(mk, ar=[forged, GMAIL_AR])).code == Code.AUTH_HEADER_UNTRUSTED


def test_forged_copy_claiming_provider_id(mk):
    forged = "mx.google.com; dmarc=pass header.from=news.example.com"
    assert gate.check(two(mk, ar=[GMAIL_AR, forged])).code == Code.AUTH_HEADER_UNTRUSTED


def test_duplicate_auth_headers_outlook(mk):
    assert gate.check(two(mk, ar=[OUTLOOK_AR, OUTLOOK_AR], authserv=None)).code == Code.AUTH_HEADER_UNTRUSTED


def test_unsubscribe_headers_not_signed(mk):
    assert gate.check(two(mk, sigs=[SIG_NO_LU])).code == Code.UNSUB_NOT_SIGNED


def test_one_aligned_signature_missing_coverage_denies(mk):
    from conftest import SIG_OK

    assert gate.check(two(mk, sigs=[SIG_OK, SIG_NO_LU])).code == Code.UNSUB_NOT_SIGNED


def test_only_unaligned_signature_covers(mk):
    assert gate.check(two(mk, sigs=[SIG_ESP])).code == Code.UNSUB_NOT_SIGNED


def test_missing_post_header(mk):
    assert gate.check(two(mk, lup=None)).code == Code.NO_ONE_CLICK


def test_wrong_post_value(mk):
    assert gate.check(two(mk, lup="List-Unsubscribe=Yes")).code == Code.NO_ONE_CLICK


def test_http_or_mailto_only(mk):
    assert gate.check(two(mk, lu="<mailto:u@news.example.com>")).code == Code.NO_ONE_CLICK
    assert gate.check(two(mk, lu="<http://news.example.com/u>")).code == Code.NO_ONE_CLICK


def test_odd_urls_rejected(mk):
    for lu in ("<https://user:pw@news.example.com/u>", "<https://news.example.com:8443/u>", "<https://10.0.0.1/u>"):
        assert gate.check(two(mk, lu=lu)).code == Code.NO_ONE_CLICK, lu


def test_spam_folder(mk):
    msgs = two(mk) + [mk(3, in_junk=True)]
    assert gate.check(msgs).code == Code.IN_SPAM


def test_unknown_outlook_cat_denies(mk):
    assert gate.check(two(mk, ms_cat="NEWCAT")).code == Code.PROVIDER_FLAGGED


def test_outlook_bad_sfv(mk):
    assert gate.check(two(mk, ms_cat="NONE", ms_sfv="SKB")).code == Code.PROVIDER_FLAGGED


def test_outlook_bulk_ok(mk):
    assert gate.check(two(mk, ms_cat="BULK", ms_sfv="NSPM")).passed


def test_newest_message_decides_unsubscribe(mk):
    msgs = [mk(0), mk(1), mk(2, lup=None)]
    assert gate.check(msgs).code == Code.NO_ONE_CLICK


def test_only_esp_signature_passed_and_covers(mk):
    """DMARC passes via SPF; the only passing DKIM is the ESP's (unaligned). Must deny."""
    ar = GMAIL_AR.replace("dkim=pass header.i=@news.example.com", "dkim=pass header.i=@esp.example.net")
    assert gate.check(two(mk, ar=[ar], sigs=[SIG_ESP])).code == Code.UNSUB_NOT_SIGNED


def test_gmail_reports_parent_domain_for_subdomain_sender(mk):
    """Real Gmail behaviour: From email.example.com, AR says header.from=example.com."""
    ar = GMAIL_AR.replace("header.from=news.example.com", "header.from=example.com")
    assert gate.check(two(mk, ar=[ar])).passed


def test_dmarc_about_child_sibling_or_tld_is_rejected(mk):
    for other in ("deep.news.example.com", "shop.example.com", "com"):
        ar = GMAIL_AR.replace("header.from=news.example.com", f"header.from={other}")
        assert gate.check(two(mk, ar=[ar])).code == Code.NOT_AUTHENTICATED, other
