from starlette.applications import Starlette
from starlette.responses import PlainTextResponse
from starlette.routing import Route, WebSocketRoute
from starlette.websockets import WebSocket, WebSocketDisconnect
from starlette.types import Receive, Scope, Send


async def hello(request):
    print("request", request)
    return PlainTextResponse("Hello World!!!")


async def ws(websocket: WebSocket):
    await websocket.accept()

    try:
        while True:
            message = await websocket.receive_text()
            await websocket.send_text(message)
    except WebSocketDisconnect:
        pass


starlette = Starlette(
    routes=[
        Route("/", hello),
        WebSocketRoute("/ws", ws),
    ]
)


async def app(scope: Scope, receive: Receive, send: Send) -> None:
    await starlette(scope, receive, send)
