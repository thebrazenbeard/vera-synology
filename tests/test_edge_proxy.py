from __future__ import annotations
import importlib.util
import socket
import threading
import unittest
from collections import namedtuple
from pathlib import Path

ROOT=Path(__file__).resolve().parents[1]
spec=importlib.util.spec_from_file_location("veramesh_edge_unit",ROOT/"payload/bin/veramesh_edge.py")
edge=importlib.util.module_from_spec(spec)
assert spec and spec.loader
spec.loader.exec_module(edge)

class StateStub:
    @staticmethod
    def verify(_path):
        return {"semantic_state":"READY","reason":"LIVE_EDGE_PROXY_READY_DURABLE_RELAY_NOT_IMPLEMENTED"}

class EdgeProxyTests(unittest.TestCase):
    def config(self,target_port=17444):
        return {
            "schema":"VERA_MESH_EDGE_CONFIG_V1","listen_host":"127.0.0.1","listen_port":17445,
            "target_host":"127.0.0.1","target_port":target_port,"connect_timeout_s":2.0,
            "idle_timeout_s":5.0,"max_connections":4,
        }

    def test_config_rejects_non_loopback_listener(self):
        value=self.config()
        value["listen_host"]="0.0.0.0"
        with self.assertRaisesRegex(ValueError,"loopback"):
            edge._validate_config(value)

    def test_status_truthfully_claims_proxy_not_durable_relay(self):
        edge._load_state=lambda: StateStub
        B=namedtuple("B","lifecycle_profile_id lifecycle_profile_sha256 package_version installation_incarnation_id start_generation start_transition_id process_instance_id")
        b=B("p","a"*64,"0.1.0-0017","1"*32,2,"2"*32,"3"*32)
        payload=edge.status_payload(b)
        self.assertTrue(payload["edge_proxy_implemented"])
        self.assertTrue(payload["mesh_delivery_implemented"])
        self.assertTrue(payload["end_to_end_veraport_auth_preserved"])
        self.assertFalse(payload["durable_relay_implemented"])

    def test_transparent_proxy_round_trip(self):
        target=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
        target.bind(("127.0.0.1",0))
        target.listen(1)
        port=target.getsockname()[1]
        done=threading.Event()
        def echo():
            conn,_=target.accept()
            with conn:
                data=conn.recv(1024)
                conn.sendall(data)
            target.close()
            done.set()
        threading.Thread(target=echo,daemon=True).start()
        client_side,edge_side=socket.socketpair()
        stop=threading.Event()
        thread=threading.Thread(target=edge._proxy_connection,args=(edge_side,self.config(port),stop),daemon=True)
        thread.start()
        client_side.sendall(b"opaque-veraport-tls-bytes")
        self.assertEqual(b"opaque-veraport-tls-bytes",client_side.recv(1024))
        client_side.close()
        thread.join(2)
        self.assertTrue(done.wait(2))

    def test_transparent_proxy_large_bidirectional_stream(self):
        payload=(b"0123456789abcdef"*131072)
        target=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
        target.bind(("127.0.0.1",0))
        target.listen(1)
        port=target.getsockname()[1]
        done=threading.Event()
        def echo():
            conn,_=target.accept()
            received=bytearray()
            with conn:
                while len(received)<len(payload):
                    chunk=conn.recv(65536)
                    if not chunk:
                        break
                    received.extend(chunk)
                conn.sendall(received)
            target.close()
            done.set()
        threading.Thread(target=echo,daemon=True).start()
        client_side,edge_side=socket.socketpair()
        stop=threading.Event()
        thread=threading.Thread(target=edge._proxy_connection,args=(edge_side,self.config(port),stop),daemon=True)
        thread.start()
        client_side.settimeout(10)
        client_side.sendall(payload)
        client_side.shutdown(socket.SHUT_WR)
        echoed=bytearray()
        while len(echoed)<len(payload):
            chunk=client_side.recv(65536)
            if not chunk:
                break
            echoed.extend(chunk)
        self.assertEqual(payload,bytes(echoed))
        client_side.close()
        thread.join(2)
        self.assertTrue(done.wait(2))

    def test_backpressure_never_reads_past_remaining_capacity(self):
        original_cap=edge.MAX_BUFFER_BYTES
        edge.MAX_BUFFER_BYTES=8192
        payload=b"x"*32768
        target=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
        target.bind(("127.0.0.1",0))
        target.listen(1)
        port=target.getsockname()[1]
        done=threading.Event()
        def echo():
            conn,_=target.accept()
            received=bytearray()
            with conn:
                while len(received)<len(payload):
                    chunk=conn.recv(4096)
                    if not chunk:
                        break
                    received.extend(chunk)
                conn.sendall(received)
            target.close()
            done.set()
        threading.Thread(target=echo,daemon=True).start()
        client_side,edge_side=socket.socketpair()
        stop=threading.Event()
        thread=threading.Thread(target=edge._proxy_connection,args=(edge_side,self.config(port),stop),daemon=True)
        try:
            thread.start()
            client_side.settimeout(5)
            client_side.sendall(payload)
            client_side.shutdown(socket.SHUT_WR)
            echoed=bytearray()
            while len(echoed)<len(payload):
                chunk=client_side.recv(4096)
                if not chunk:
                    break
                echoed.extend(chunk)
            self.assertEqual(payload,bytes(echoed))
            self.assertTrue(done.wait(2))
        finally:
            edge.MAX_BUFFER_BYTES=original_cap
            client_side.close()
            thread.join(2)

if __name__=="__main__":
    unittest.main()
