import asyncio
from threading import Lock
from typing import Any, Callable, OrderedDict, TypeVar

Handler_T = TypeVar("Handler_T", bound=Callable)


class EventEmitter:
    def __init__(self) -> None:
        self._events: dict[str, OrderedDict[Callable, Callable]] = dict()
        self._lock = Lock()

    def on(
        self, event: str, f: Handler_T | None = None
    ) -> Handler_T | Callable[[Handler_T], Handler_T]:
        if f:
            return self.add_listener(event, f)
        else:
            return self.listens_to(event)

    def _on_call_handler(
        self,
        event: str,
        f: Callable,
        args: tuple[Any, ...],
        kwargs: dict[str, Any],
    ):
        f(*args, **kwargs)

    def _call_handlers(
        self, event: str, args: tuple[Any, ...], kwargs: dict[str, Any]
    ) -> bool:
        handled = False

        with self._lock:
            funcs = list(self._events.get(event, OrderedDict()).values())

        for f in funcs:
            self._on_call_handler(event, f, args, kwargs)
            handled = True

        return handled

    def _emit_handle_potential_error(self, event: str, error: Any) -> None:
        if event == "error":
            if isinstance(error, Exception):
                raise error

    def emit(
        self,
        event: str,
        *args: Any,
        **kwargs: Any,
    ) -> bool:
        handled = self._call_handlers(event, args, kwargs)

        if not handled:
            self._emit_handle_potential_error(event, args[0] if args else None)

        return handled

    def _add_event_handler(self, event: str, key: Callable, val: Callable):
        self.emit("new_listener", event, key)

        with self._lock:
            if event not in self._events:
                self._events[event] = OrderedDict()
            self._events[event][key] = val

    def listens_to(self, event: str) -> Callable[[Handler_T], Handler_T]:
        def on(f: Handler_T) -> Handler_T:
            self._add_event_handler(event, f, f)
            return f

        return on

    def add_listener(self, event: str, f: Handler_T) -> Handler_T:
        self._add_event_handler(event, f, f)
        return f

    def remove_listener(self, event: str, f: Callable):
        with self._lock:
            self._events[event].pop(f)
            if not len(self._events[event]):
                del self._events[event]

    def remove_all_listeners(self, event: str | None = None):
        with self._lock:
            if event is not None:
                self._events[event] = OrderedDict()
            else:
                self._events = dict()


class AsyncEventEmitter(EventEmitter):
    def __init__(self, loop: asyncio.AbstractEventLoop | None = None) -> None:
        super(AsyncEventEmitter, self).__init__()
        self.__loop = loop
        self._waiting = set[asyncio.Future]()
        self._fallback_waiting = set[asyncio.Future]()

    def _on_call_handler(
        self, event: str, f: Callable, args: tuple[Any, ...], kwargs: dict[str, Any]
    ):
        try:
            coro = f(*args, **kwargs)
        except Exception as e:
            self.emit("error", e)
        else:
            if asyncio.iscoroutine(coro):
                from webrtc.runtime_services import current_execution_scope, ScopeState

                scope = current_execution_scope()
                if scope is not None and scope.state is ScopeState.ACTIVE:
                    try:
                        future = scope.start(
                            lambda: coro,
                            name=f"event:{event}",
                            kind="event",
                            metadata={"event": event},
                        )
                    except BaseException:
                        coro.close()
                        raise
                else:
                    future = (self.__loop or asyncio.get_running_loop()).create_task(
                        coro, name=f"event:{event}")
                    self._fallback_waiting.add(future)
            elif isinstance(coro, asyncio.Future):
                future = coro
            else:
                return

            def callback(f: asyncio.Future):
                self._waiting.discard(f)
                self._fallback_waiting.discard(f)

                if f.cancelled():
                    return

                if e := f.exception():
                    self.emit("error", e)

            future.add_done_callback(callback)
            self._waiting.add(future)

    async def aclose(self) -> None:
        """Cancel and join emitter-owned callbacks, including no-Runtime fallbacks."""
        waiting = tuple(self._waiting)
        current = asyncio.current_task()
        for future in waiting:
            if future is not current and not future.done():
                future.cancel()
        await asyncio.gather(
            *(future for future in waiting if future is not current),
            return_exceptions=True,
        )
        self._waiting.clear()
        self._fallback_waiting.clear()
