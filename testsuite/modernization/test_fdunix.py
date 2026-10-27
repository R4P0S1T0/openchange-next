"""Real UNIX socket descriptor transfers for the Python 3 RPC utility."""

from array import array
import importlib.util
import os
from pathlib import Path
import socket
import subprocess
import sys
import unittest


ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location("fdunix", ROOT / "python/openchange/utils/fdunix.py")
fdunix = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(fdunix)


@unittest.skipUnless(hasattr(socket.socket, "sendmsg"), "requires UNIX descriptor passing")
class DescriptorTests(unittest.TestCase):
    def pair(self):
        pair = socket.socketpair()
        for endpoint in pair:
            self.addCleanup(endpoint.close)
            endpoint.settimeout(2)
        return pair

    def test_transfer_survives_sender_close_and_preserves_family(self):
        sender, receiver = self.pair()
        original, peer = self.pair()
        self.assertTrue(fdunix.send_socket(sender, original))
        transferred = fdunix.receive_socket(receiver)
        self.addCleanup(transferred.close)
        self.assertEqual(transferred.family, socket.AF_UNIX)
        self.assertFalse(os.get_inheritable(transferred.fileno()))
        original.close()
        peer.sendall(b"openchange")
        self.assertEqual(transferred.recv(10), b"openchange")
        transferred.sendall(b"reply")
        self.assertEqual(peer.recv(5), b"reply")

    def test_sender_retains_ownership(self):
        sender, receiver = self.pair()
        original, peer = self.pair()
        fdunix.send_socket(sender, original)
        with fdunix.receive_socket(receiver):
            pass
        original.sendall(b"still open")
        self.assertEqual(peer.recv(10), b"still open")

    def test_transfer_from_another_process(self):
        sender, receiver = self.pair()
        original, peer = self.pair()
        code = (
            "import socket,sys; sys.path.insert(0,sys.argv[1]); "
            "from fdunix import send_socket; "
            "transport=socket.socket(fileno=int(sys.argv[2])); "
            "source=socket.socket(fileno=int(sys.argv[3])); "
            "send_socket(transport,source)"
        )
        subprocess.run([sys.executable, '-c', code,
                        str(ROOT / 'python/openchange/utils'),
                        str(sender.fileno()), str(original.fileno())],
                       pass_fds=(sender.fileno(), original.fileno()),
                       check=True, timeout=10, capture_output=True)
        original.close()
        with fdunix.receive_socket(receiver) as transferred:
            transferred.sendall(b'child transfer')
            self.assertEqual(peer.recv(14), b'child transfer')

    def test_non_socket_is_rejected(self):
        sender, _receiver = self.pair()
        with self.assertRaises(TypeError):
            fdunix.send_socket(sender, object())

    def test_missing_descriptor_is_rejected(self):
        sender, receiver = self.pair()
        sender.sendall(b"A")
        with self.assertRaises(ValueError):
            fdunix.receive_socket(receiver)

    def test_closed_transport_is_reported(self):
        sender, receiver = self.pair()
        sender.close()
        with self.assertRaises(EOFError):
            fdunix.receive_socket(receiver)

    @unittest.skipUnless(Path("/proc/self/fd").is_dir(), "requires Linux fd inventory")
    def test_repeated_transfers_do_not_leak_descriptors(self):
        sender, receiver = self.pair()
        original, _peer = self.pair()
        before = len(os.listdir("/proc/self/fd"))
        for _ in range(30):
            fdunix.send_socket(sender, original)
            fdunix.receive_socket(receiver).close()
        self.assertEqual(len(os.listdir("/proc/self/fd")), before)

    @unittest.skipUnless(Path("/proc/self/fd").is_dir(), "requires Linux fd inventory")
    def test_extra_descriptors_are_rejected_and_closed(self):
        sender, receiver = self.pair()
        original, peer = self.pair()
        before = len(os.listdir("/proc/self/fd"))
        rights = array("i", [original.fileno(), peer.fileno()] * 4)
        sender.sendmsg([b"A"], [(socket.SOL_SOCKET, socket.SCM_RIGHTS, rights)])
        with self.assertRaises(ValueError):
            fdunix.receive_socket(receiver)
        self.assertEqual(len(os.listdir("/proc/self/fd")), before)

    @unittest.skipUnless(Path("/proc/self/fd").is_dir(), "requires Linux fd inventory")
    def test_non_socket_descriptor_is_closed_on_error(self):
        sender, receiver = self.pair()
        with open(os.devnull, 'rb') as source:
            before = len(os.listdir('/proc/self/fd'))
            sender.sendmsg([b'A'], [(socket.SOL_SOCKET, socket.SCM_RIGHTS,
                                    array('i', [source.fileno()]))])
            with self.assertRaises(OSError):
                fdunix.receive_socket(receiver)
            self.assertEqual(len(os.listdir('/proc/self/fd')), before)


if __name__ == "__main__":
    unittest.main()
