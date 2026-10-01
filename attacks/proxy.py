"""Man-in-the-middle TCP proxy.

Sits between a client and the gateway, sees every frame in both directions,
records them (passive eavesdropping) and can rewrite or drop them through
hook functions (active tampering). Runs on its own event loop thread so the
synchronous attack scenarios can drive it.
"""

from __future__ import annotations

import asyncio
import threading
from typing import Callable

from flowstate.core.codec import read_frame, write_frame
from flowstate.core.reasons import SecurityError
from flowstate.gateway.runtime import cancel_pending_tasks

Hook = Callable[[bytes], bytes]


class MitmProxy:
    def __init__(
        self,
        upstream: tuple[str, int],
        *,
        on_client_frame: Hook | None = None,
        on_server_frame: Hook | None = None,
    ) -> None:
        self.upstream = upstream
        self.on_client_frame = on_client_frame
        self.on_server_frame = on_server_frame
        self.client_frames: list[bytes] = []  # as sent by the client, before tampering
        self.server_frames: list[bytes] = []  # as sent by the gateway, before tampering
        self._loop = asyncio.new_event_loop()
        self._thread = threading.Thread(target=self._loop.run_forever, daemon=True)
        self._server: asyncio.Server | None = None
        self.address: tuple[str, int] | None = None

    async def _pump(self, reader, writer, captured: list[bytes], hook: Hook | None) -> None:
        try:
            while (raw := await read_frame(reader)) is not None:
                captured.append(raw)
                await write_frame(writer, hook(raw) if hook else raw)
        except (ConnectionError, SecurityError, asyncio.CancelledError):
            pass
        finally:
            writer.close()

    async def _on_connection(self, c_reader, c_writer) -> None:
        g_reader, g_writer = await asyncio.open_connection(*self.upstream)
        await asyncio.gather(
            self._pump(c_reader, g_writer, self.client_frames, self.on_client_frame),
            self._pump(g_reader, c_writer, self.server_frames, self.on_server_frame),
        )

    def start(self) -> "MitmProxy":
        self._thread.start()

        async def boot() -> asyncio.Server:
            return await asyncio.start_server(self._on_connection, "127.0.0.1", 0)

        self._server = asyncio.run_coroutine_threadsafe(boot(), self._loop).result(5)
        self.address = ("127.0.0.1", self._server.sockets[0].getsockname()[1])
        return self

    def stop(self) -> None:
        async def close() -> None:
            self._server.close()
            await cancel_pending_tasks()

        asyncio.run_coroutine_threadsafe(close(), self._loop).result(5)
        self._loop.call_soon_threadsafe(self._loop.stop)
        self._thread.join(5)
        self._loop.close()

    def __enter__(self) -> "MitmProxy":
        return self.start()

    def __exit__(self, *exc) -> None:
        self.stop()
