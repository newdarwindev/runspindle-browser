"""One bounded binary frame over application-owned pipes, no launcher or issuer.

The trusted application supplies Receiver and an opaque out-of-band authority
 ticket. The external Core owner reserves before sending and supervises a total
 deadline/child process group. Both sides close their write end after one frame;
 EOF is required before executing or accepting a response. No persistent state.
"""

from __future__ import annotations

import struct
from typing import BinaryIO

from browser_runtime.effect_wire import MAX_REQUEST, Receiver

MAX_RESPONSE = 4096


def _exact(stream: BinaryIO, size: int) -> bytes:
    pieces = bytearray()
    while len(pieces) < size:
        part = stream.read(size - len(pieces))
        if type(part) is not bytes or not part or len(part) > size - len(pieces):
            raise ValueError
        pieces.extend(part)
    return bytes(pieces)


def serve_once(
    reader: BinaryIO, writer: BinaryIO, receiver: Receiver, ticket: object
) -> bool:
    """Return False on any failure; caller must close pipes and exit nonzero.

    Blocking I/O is bounded by the application's supervising process deadline,
    not an internal thread or timer. Never derive ticket/authority from bytes.
    A partial response, lost reply or cancellation must remain unknown in Core.
    """
    succeeded = False
    try:
        size = struct.unpack(">I", _exact(reader, 4))[0]
        if not 0 < size <= MAX_REQUEST:
            raise ValueError
        raw = _exact(reader, size)
        if reader.read(1) != b"":
            raise ValueError
        response = receiver.exchange(raw, ticket)
        if type(response) is not bytes or not 0 < len(response) <= MAX_RESPONSE:
            raise ValueError
        framed = struct.pack(">I", len(response)) + response
        offset = 0
        while offset < len(framed):
            written = writer.write(framed[offset:])
            if type(written) is not int or not 0 < written <= len(framed) - offset:
                raise ValueError
            offset += written
        writer.flush()
        succeeded = True
    except BaseException:
        # No raw errors, chained exception objects or fixture bytes escape.
        pass
    return succeeded
