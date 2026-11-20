"""The persisted stand-in: the same Graph app folder, served over real TLS."""

import ssl
import stat

import httpx
import pytest

from deploy.standin_tls import TLSStandIn, lab_ca
from onedrive import Destination, GraphAppFolder, ProviderUnavailable
from tests.standin import TOKEN


@pytest.fixture
def lab(tmp_path):
    return lab_ca(tmp_path / "lab-ca")


@pytest.fixture
def folder():
    clients = []

    def make(served, cafile) -> GraphAppFolder:
        context = ssl.create_default_context(cafile=str(cafile))
        clients.append(httpx.Client(verify=context, trust_env=False))
        return GraphAppFolder(clients[-1], token=lambda: TOKEN, base=f"{served.graph_origin}/v1.0")

    yield make
    for client in clients:
        client.close()


def test_the_lab_ca_signs_one_leaf_and_keeps_no_signing_key(lab):
    assert sorted(path.name for path in lab.directory.iterdir()) == [
        "ca.pem",
        "leaf.key",
        "leaf.pem",
    ]
    assert stat.S_IMODE(lab.directory.stat().st_mode) == 0o700
    assert stat.S_IMODE(lab.leaf_key.stat().st_mode) == 0o600
    context = ssl.create_default_context(cafile=str(lab.ca_pem))
    context.load_cert_chain(lab.leaf_pem, lab.leaf_key)


def test_a_publication_round_trips_over_tls_with_the_bearer_only_to_graph(lab, folder):
    with TLSStandIn(lab) as served:
        app = folder(served, lab.ca_pem)
        assert app.destination() == Destination("standin-drive", "STANDIN-APPROOT")
        item = app.upload_new("summary.md", b"# Synthetic brief\n", "bound")
        [listed] = app.list_items()
        assert (listed.id, app.download(item.id)) == (item.id, b"# Synthetic brief\n")
        origins = {request.url.netloc.decode() for request in served.requests}
        assert len(origins) == 3
        for request in served.requests:
            to_graph = f"https://{request.url.netloc.decode()}" == served.graph_origin
            assert ("Authorization" in request.headers) == to_graph


def test_a_lost_answer_after_commit_is_a_dropped_connection(lab, folder):
    with TLSStandIn(lab) as served:
        served.standin.lose_next_commit_response = True
        with pytest.raises(ProviderUnavailable):
            folder(served, lab.ca_pem).upload_new("summary.md", b"x", "bound")
        assert served.standin.committed_uploads == 1
        assert [item["name"] for item in served.standin.items.values()] == ["summary.md"]


def test_a_client_without_the_lab_ca_is_refused_before_any_request(lab, folder, tmp_path):
    other = lab_ca(tmp_path / "other-ca")
    with TLSStandIn(lab) as served:
        with pytest.raises(ProviderUnavailable):
            folder(served, other.ca_pem).destination()
        assert served.requests == []
