"""The frozen egress URL contract, consumed in place from the repository root."""

from __future__ import annotations

import json
from importlib.metadata import version
from pathlib import Path

import pytest

from aweb_naapp.egress import (
    PUBLIC_SUFFIX_LIST_VERSION,
    EgressRefused,
    HeaderRules,
    InternalDestinations,
    canonical_url,
    check_headers,
    check_injected,
    match_destination,
    parse_destination,
)

AWEB_ROOT = Path(__file__).resolve().parents[3]
VECTORS = json.loads((AWEB_ROOT / "docs" / "vectors" / "egress-url-v2.json").read_text())


def _named(cases: list[dict]) -> list:
    return [pytest.param(case, id=case["name"]) for case in cases]


def test_public_suffix_list_is_the_pinned_one() -> None:
    pinned = VECTORS["public_suffix_list"]["version"]
    assert PUBLIC_SUFFIX_LIST_VERSION == pinned
    assert version(VECTORS["public_suffix_list"]["package"]) == pinned


@pytest.mark.parametrize("case", _named(VECTORS["canonical"]))
def test_canonical(case: dict) -> None:
    assert str(canonical_url(case["url"])) == case["canonical"]


@pytest.mark.parametrize("case", _named(VECTORS["canonical"]))
def test_canonical_is_a_fixed_point(case: dict) -> None:
    assert str(canonical_url(case["canonical"])) == case["canonical"]


@pytest.mark.parametrize("case", _named(VECTORS["refused"]))
def test_refused(case: dict) -> None:
    with pytest.raises(EgressRefused) as refused:
        canonical_url(case["url"])
    assert (refused.value.code, refused.value.rule) == (case["code"], case["rule"])


@pytest.mark.parametrize("case", _named(VECTORS["destinations"]))
def test_destination(case: dict) -> None:
    parse_destination(
        case["destination"],
        internal_destinations=InternalDestinations(case["internal_destinations"]),
    )


@pytest.mark.parametrize("case", _named(VECTORS["refused_destinations"]))
def test_refused_destination(case: dict) -> None:
    with pytest.raises(EgressRefused) as refused:
        parse_destination(
            case["destination"],
            internal_destinations=InternalDestinations(case["internal_destinations"]),
        )
    assert (refused.value.code, refused.value.rule) == (case["code"], case["rule"])


@pytest.mark.parametrize("case", _named(VECTORS["matches"]))
def test_match(case: dict) -> None:
    setting = InternalDestinations(case["internal_destinations"])
    destination = parse_destination(case["destination"], internal_destinations=setting)
    params = match_destination(
        destination, case["method"], case["url"], internal_destinations=setting
    )
    assert params == case["params"]


@pytest.mark.parametrize("case", _named(VECTORS["refused_matches"]))
def test_refused_match(case: dict) -> None:
    # A destination confirmed while internal destinations were allowed must
    # still be refused at dispatch once the deployment disables them.
    destination = parse_destination(
        case["destination"], internal_destinations=InternalDestinations.ALLOWED
    )
    with pytest.raises(EgressRefused) as refused:
        match_destination(
            destination,
            case["method"],
            case["url"],
            internal_destinations=InternalDestinations(case["internal_destinations"]),
        )
    assert (refused.value.code, refused.value.rule) == (case["code"], case["rule"])


HEADERS = VECTORS["headers"]
CANARY = "credential-canary"


def _never(value: str) -> bool:
    return False


def _rules(case: dict | None = None, detector=_never) -> HeaderRules:
    case = case or {}
    return HeaderRules(
        injected=case.get("injected", []),
        amz_allowed=case.get("amz_allowed", []),
        is_credential=detector,
    )


@pytest.mark.parametrize("case", _named(HEADERS["allowed"]))
def test_headers_allowed(case: dict) -> None:
    headers = [tuple(pair) for pair in case["headers"]]
    assert check_headers(headers, header_allow=case["header_allow"], rules=_rules(case)) == headers


@pytest.mark.parametrize("case", _named(HEADERS["refused"]))
def test_headers_refused(case: dict) -> None:
    with pytest.raises(EgressRefused) as refused:
        check_headers(
            [tuple(pair) for pair in case["headers"]],
            header_allow=case["header_allow"],
            rules=_rules(case),
        )
    assert refused.value.code == case["code"]


def test_every_always_rejected_header_is_refused_even_when_allowed() -> None:
    for name in HEADERS["always_rejected"]:
        for spelling in (name, name.upper(), name.lower()):
            with pytest.raises(EgressRefused):
                check_headers([(spelling, "x")], header_allow=[name], rules=_rules())


def test_every_always_rejected_prefix_is_refused_even_when_allowed() -> None:
    for prefix in HEADERS["always_rejected_prefixes"]:
        for name in (prefix + "For", prefix + "Host", (prefix + "Proto").upper()):
            with pytest.raises(EgressRefused):
                check_headers([(name, "x")], header_allow=[name], rules=_rules())


def test_every_default_allowed_header_passes() -> None:
    for name in HEADERS["default_allow"]:
        assert check_headers([(name, "x")], header_allow=[], rules=_rules()) == [(name, "x")]


def test_a_credential_shaped_value_is_refused() -> None:
    def detector(value: str) -> bool:
        return CANARY in value

    check_headers(
        [("Accept", "application/json")], header_allow=[], rules=_rules(detector=detector)
    )
    with pytest.raises(EgressRefused) as refused:
        check_headers([("Accept", CANARY)], header_allow=[], rules=_rules(detector=detector))
    assert refused.value.code == "header_not_allowed"


def test_the_extra_refusal_cannot_allow_a_refused_header() -> None:
    def refuse(name: str, value: str) -> bool:
        return value.startswith("block")

    with pytest.raises(EgressRefused):
        check_headers([("Accept", "block-me")], header_allow=[], rules=_rules(), refuse=refuse)
    with pytest.raises(EgressRefused):
        check_headers([("Cookie", "a")], header_allow=["Cookie"], rules=_rules(), refuse=refuse)


def test_header_rules_have_no_defaults() -> None:
    with pytest.raises(TypeError):
        HeaderRules()  # type: ignore[call-arg]


INJECTED = HEADERS["injected"]


def _declared(case: dict) -> HeaderRules:
    return HeaderRules(injected=case["declared"], amz_allowed=[], is_credential=_never)


@pytest.mark.parametrize("case", _named(INJECTED["allowed"]))
def test_injected_allowed(case: dict) -> None:
    headers = [tuple(pair) for pair in case["headers"]]
    assert check_injected(headers, rules=_declared(case)) == headers


@pytest.mark.parametrize("case", _named(INJECTED["refused"]))
def test_injected_refused(case: dict) -> None:
    with pytest.raises(EgressRefused) as refused:
        check_injected([tuple(pair) for pair in case["headers"]], rules=_declared(case))
    assert refused.value.code == case["code"]
    for _, value in case["headers"]:
        assert value not in str(refused.value)


@pytest.mark.parametrize("case", _named(INJECTED["caller_refused"]))
def test_a_caller_header_with_a_declared_injected_name_is_refused(case: dict) -> None:
    with pytest.raises(EgressRefused) as refused:
        check_headers(
            [tuple(pair) for pair in case["headers"]],
            header_allow=case["header_allow"],
            rules=_declared(case),
        )
    assert refused.value.code == case["code"]


def test_every_guard_set_header_is_refused_even_when_declared() -> None:
    for name in INJECTED["guard_set"]:
        for spelling in (name, name.lower(), name.upper()):
            rules = HeaderRules(injected=[name], amz_allowed=[], is_credential=_never)
            with pytest.raises(EgressRefused):
                check_injected([(spelling, "x")], rules=rules)


def test_an_injected_credential_value_is_not_checked_by_the_detector() -> None:
    rules = HeaderRules(injected=["Authorization"], amz_allowed=[], is_credential=lambda v: True)
    assert check_injected([("Authorization", CANARY)], rules=rules) == [("Authorization", CANARY)]
