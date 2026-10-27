# fdunix.py -- OpenChange RPC-over-HTTP implementation
#
# Copyright (C) 2012  Wolfgang Sourdeau <wsourdeau@inverse.ca>
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.
#

"""Pass socket ownership between processes over a UNIX socket.

The sender keeps its socket. The receiver owns a new descriptor referring to
that socket and is responsible for closing the returned socket object.
"""

from array import array
import os
import socket as _socket


def send_socket(socket, sobject):
    """Send a socket descriptor over a connected UNIX socket; return True.

    Socket and transport errors propagate as OSError.
    """
    if not isinstance(sobject, _socket.socket):
        raise TypeError("'sobject' must be a socket object")
    descriptors = array("i", [sobject.fileno()])
    socket.sendmsg([b"A"], [(_socket.SOL_SOCKET, _socket.SCM_RIGHTS, descriptors)])
    return True


def receive_socket(socket):
    """Receive and take ownership of exactly one socket descriptor.

    Raise EOFError for a closed transport and ValueError for missing, extra or
    truncated descriptors. Received descriptors are closed on every error path.
    """
    descriptors = array("i")
    flags = getattr(_socket, "MSG_CMSG_CLOEXEC", 0)
    data, ancillary, message_flags, _address = socket.recvmsg(
        1, _socket.CMSG_SPACE(descriptors.itemsize), flags
    )
    malformed = False
    try:
        for level, kind, payload in ancillary:
            if level == _socket.SOL_SOCKET and kind == _socket.SCM_RIGHTS:
                usable = len(payload) - len(payload) % descriptors.itemsize
                descriptors.frombytes(payload[:usable])
                malformed = malformed or usable != len(payload)
        if message_flags & _socket.MSG_CTRUNC or malformed:
            raise ValueError("truncated socket descriptor message")
        if not data:
            raise EOFError("socket descriptor transport closed")
        if len(descriptors) != 1:
            raise ValueError("expected exactly one socket descriptor")
        descriptor = descriptors[0]
        os.set_inheritable(descriptor, False)
        # Adopt the descriptor instead of fromfd(), which duplicates it. Let
        # Python detect its family and type rather than assuming AF_INET.
        result = _socket.socket(fileno=descriptor)
        descriptors.pop()
        return result
    finally:
        for descriptor in descriptors:
            os.close(descriptor)
