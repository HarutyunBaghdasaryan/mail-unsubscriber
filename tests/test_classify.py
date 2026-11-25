from conftest import GMAIL_AR

from mail_unsubscriber.classify import classify
from mail_unsubscriber.headers import aligned, parse_from
from mail_unsubscriber.model import Code, Group


def test_groups_and_order(mk):
    msgs = [mk(0), mk(1), mk(2)]  # good sender, 3 messages
    msgs += [mk(i, frm="r@shop.example.org", ar=[], lu=None, lup=None) for i in range(2)]
    out = classify(msgs)
    assert [d.group for d in out] == [Group.CAN_UNSUBSCRIBE, Group.UNSURE]
    assert out[0].count == 3 and out[0].unsub_host == "list.esp.example.net"


def test_sender_is_full_address(mk):
    msgs = [mk(0, frm="deals@news.example.com"), mk(1, frm="orders@news.example.com")]
    assert {d.sender for d in classify(msgs)} == {"deals@news.example.com", "orders@news.example.com"}


def test_outlook_phish_is_danger(mk):
    d = classify([mk(0), mk(1, ms_cat="PHSH")])[0]
    assert (d.group, d.code) == (Group.DANGER, Code.PROVIDER_PHISH)


def test_punycode_is_danger(mk):
    ar = GMAIL_AR.replace("news.example.com", "xn--pypal-4ve.example.com")
    d = classify([mk(i, frm="a@xn--pypal-4ve.example.com", ar=[ar]) for i in range(2)])[0]
    assert (d.group, d.code) == (Group.DANGER, Code.PUNYCODE_FROM)


def test_protected_and_kept(mk):
    msgs = [mk(0), mk(1)]
    assert classify(msgs, protected_domains=frozenset({"example.com"}))[0].code == Code.PROTECTED
    assert classify(msgs, user_kept=frozenset({"deals@news.example.com"}))[0].code == Code.USER_KEPT


def test_spam_is_unsure_not_danger(mk):
    d = classify([mk(0), mk(1, in_junk=True)])[0]
    assert (d.group, d.code) == (Group.UNSURE, Code.IN_SPAM)


def test_alignment_is_conservative():
    assert aligned("news.example.com", "example.com")
    assert aligned("example.com", "mail.example.com")
    assert not aligned("a.example.com", "b.example.com")  # siblings denied (stricter than DMARC)
    assert not aligned("example.com", "notexample.com")


def test_parse_from_rejects_garbage():
    assert parse_from("a@b@c.example.com") is None
    assert parse_from("one@example.com, two@example.com") is None
    assert parse_from("x" * 9000) is None
    assert parse_from('"Bank" <Alerts@Example.COM>') == ("alerts@example.com", "example.com")
