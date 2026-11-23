"""An ASGI app for running_app's own tests: each /noise request writes more
than a pipe holds to its output, and /secret logs a token and a UUID."""

import json
import sys

NOISE_BYTES = 1 << 20
TOKEN = "Zk3PqX9vR2mN7tYw5Lh8Jc4Bd6Fg1Sa0"
ASSET_ID = "0a0a0a0a-1111-4222-8333-444444444444"


def create_app():
    async def app(scope, receive, send):
        if scope["type"] == "lifespan":
            while True:
                message = await receive()
                if message["type"] == "lifespan.startup":
                    await send({"type": "lifespan.startup.complete"})
                elif message["type"] == "lifespan.shutdown":
                    await send({"type": "lifespan.shutdown.complete"})
                    return
        body = b"{}"
        if scope["path"] == "/aweb-app.json":
            body = json.dumps({"app": {"id": "noisy"}}).encode()
        elif scope["path"] == "/noise":
            for stream in (sys.stdout, sys.stderr):
                print("noise " * (NOISE_BYTES // 6), file=stream, flush=True)
        elif scope["path"] == "/secret":
            print(f"app-says token={TOKEN} asset={ASSET_ID} in_a_function_name", flush=True)
        await send(
            {
                "type": "http.response.start",
                "status": 200,
                "headers": [(b"content-type", b"application/json")],
            }
        )
        await send({"type": "http.response.body", "body": body})

    return app
