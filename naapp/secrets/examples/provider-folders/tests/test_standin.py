"""The stand-in serves any three origins it is given, as the TLS drill needs."""

import httpx

from onedrive import Destination, GraphAppFolder
from tests.standin import TOKEN, OneDriveStandIn

GRAPH = "https://127.0.0.1:8443"
UPLOAD = "https://127.0.0.1:8444"
DOWNLOAD = "https://127.0.0.1:8445"


def folder(standin, requests) -> GraphAppFolder:
    def handle(request):
        requests.append(request)
        return standin.handle(request)

    client = httpx.Client(transport=httpx.MockTransport(handle))
    return GraphAppFolder(client, token=lambda: TOKEN, base=f"{GRAPH}/v1.0")


def test_given_origins_route_uploads_downloads_and_pages():
    standin = OneDriveStandIn(graph=f"{GRAPH}/v1.0", upload_origin=UPLOAD, download_origin=DOWNLOAD)
    standin.add_item("a.md", b"a")
    standin.add_item("b.md", b"b")
    requests = []
    app = folder(standin, requests)
    assert app.destination() == Destination("standin-drive", "STANDIN-APPROOT")
    item = app.upload_new("c.md", b"third", "bound")
    assert [listed.name for listed in app.list_items()] == ["a.md", "b.md", "c.md"]
    assert app.download(item.id) == b"third"
    origins = {f"{r.url.scheme}://{r.url.netloc.decode()}" for r in requests}
    assert origins == {GRAPH, UPLOAD, DOWNLOAD}
    for request in requests:
        sent_to_graph = request.url.netloc.decode() == "127.0.0.1:8443"
        assert ("Authorization" in request.headers) == sent_to_graph


def test_a_host_matching_only_by_name_is_not_the_upload_origin():
    standin = OneDriveStandIn(graph=f"{GRAPH}/v1.0", upload_origin=UPLOAD, download_origin=DOWNLOAD)
    response = standin.handle(httpx.Request("PUT", "https://127.0.0.1:9999/session/x"))
    assert response.status_code == 401
