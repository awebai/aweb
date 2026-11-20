"""An ASGI app for running_app's own tests: it serves the two routes the
helper waits for, then never finishes its lifespan shutdown."""

import asyncio
import json


def create_app():
    async def app(scope, receive, send):
        if scope["type"] == "lifespan":
            while True:
                message = await receive()
                if message["type"] == "lifespan.startup":
                    await send({"type": "lifespan.startup.complete"})
                elif message["type"] == "lifespan.shutdown":
                    await asyncio.Event().wait()
            return
        body = b"{}"
        if scope["path"] == "/aweb-app.json":
            body = json.dumps({"app": {"id": "stuck"}}).encode()
        await send(
            {
                "type": "http.response.start",
                "status": 200,
                "headers": [(b"content-type", b"application/json")],
            }
        )
        await send({"type": "http.response.body", "body": body})

    return app
