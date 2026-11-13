"""The protected round trip's fault injector: the front withholds the 2xx
answer to one request (a signer's prepare, an app's owner-act delivery)."""

import pytest
from protected_round_trip import AnswerDrop

SITES = {
    "aweb.lf.test": "aweb:8000",
    "console.secrets.lf.test": "secrets:8770",
    "api.logs.lf.test": "logs:8765",
}
WITHOUT_SIGNER = "{\n  auto_https off\n}\n" + "".join(
    f"{host}:443 {{\n  tls /tls/c.pem /tls/k.pem\n  reverse_proxy {target}\n}}\n" for host, target in SITES.items())
WITH_SIGNER = WITHOUT_SIGNER + "signer.lf.test:443 {\n  tls /tls/c.pem /tls/k.pem\n  reverse_proxy signer:8080\n}\n"


def drop(tmp_path, text, host="signer.lf.test", path="/protected-operations", upstream="signer:8080"):
    rendered = tmp_path / "Caddyfile"
    rendered.write_text(text)
    reloads = []
    answer = AnswerDrop(rendered, host, "POST", path, upstream, lambda: reloads.append(rendered.read_text()))
    return rendered, reloads, answer


def test_the_drop_uses_the_front_as_rendered_when_it_starts_not_when_built(tmp_path):
    rendered, reloads, answer = drop(tmp_path, WITHOUT_SIGNER)
    rendered.write_text(WITH_SIGNER)
    with answer:
        dropped = rendered.read_text()
        assert dropped.count("@dropped {") == 1
        assert "signer.lf.test:443 {\n  @dropped {\n    method POST\n    path /protected-operations\n  }\n" in dropped
        assert "  reverse_proxy @dropped signer:8080 {\n" in dropped and dropped.count("abort") == 1
        # Every other site, and the host's own proxy, are untouched.
        assert dropped.replace(dropped[dropped.index("  @dropped {"):dropped.index("  tls /tls/c.pem", dropped.index(
            "  @dropped {"))], "") == WITH_SIGNER
        assert reloads == [dropped]
    assert rendered.read_text() == WITH_SIGNER and reloads[-1] == WITH_SIGNER and len(reloads) == 2


def test_the_drop_withholds_an_apps_owner_act_answer_on_its_console_host(tmp_path):
    rendered, reloads, answer = drop(tmp_path, WITH_SIGNER, host="console.secrets.lf.test",
                                     path="/.well-known/aweb-owner-act", upstream="secrets:8770")
    with answer:
        dropped = rendered.read_text()
        assert "console.secrets.lf.test:443 {\n  @dropped {\n    method POST\n    path /.well-known/aweb-owner-act\n" in dropped
        assert "  reverse_proxy @dropped secrets:8770 {\n" in dropped
        assert "signer.lf.test:443 {\n  tls" in dropped
    assert rendered.read_text() == WITH_SIGNER


def test_the_front_is_restored_when_the_step_under_the_drop_fails(tmp_path):
    rendered, reloads, answer = drop(tmp_path, WITH_SIGNER)
    with pytest.raises(RuntimeError, match="the step failed"):
        with answer:
            raise RuntimeError("the step failed")
    assert rendered.read_text() == WITH_SIGNER and reloads[-1] == WITH_SIGNER


@pytest.mark.parametrize("text", [
    WITHOUT_SIGNER,
    WITH_SIGNER + "signer.lf.test:443 {\n  respond 200\n}\n",
])
def test_a_front_without_exactly_one_site_for_the_host_is_refused_and_left_alone(tmp_path, text):
    rendered, reloads, answer = drop(tmp_path, text)
    with pytest.raises(SystemExit, match="signer.lf.test"):
        with answer:
            pytest.fail("the step ran under a drop that was never installed")
    assert rendered.read_text() == text and reloads == []


def test_a_drop_cannot_start_twice(tmp_path):
    rendered, reloads, answer = drop(tmp_path, WITH_SIGNER)
    with answer:
        with pytest.raises(SystemExit, match="already"):
            answer.__enter__()
    assert rendered.read_text() == WITH_SIGNER
