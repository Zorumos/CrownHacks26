"""All broker observations in these tests are synthetic fixtures, never live-demo evidence."""
import base64
from concurrent.futures import ThreadPoolExecutor
import importlib.util
import json
from pathlib import Path
import secrets
import tempfile
import time
import unittest
from unittest.mock import patch
from cryptography.fernet import Fernet
from fastapi.testclient import TestClient
from backend.app import create_app
from backend.privacy_disclosure import PrivacyDisclosureGate
from backend.security import totp, valid_step
from backend.settings import Settings
from backend.shield_manager import OneClickShieldManager
from backend.vpn import BrokerUnavailable, UnixBroker, allocate, public_key
from backend.warnings_engine import PlainLanguageWarningEngine


def key():
    return base64.b64encode(secrets.token_bytes(32)).decode()


class TestBroker:
    def __init__(self):
        self.peers = {}
        self.fail = False
        self.calls = []

    def call(self, server, operation, **payload):
        self.calls.append((operation, payload))
        if self.fail:
            raise BrokerUnavailable()
        peer = payload.get("key")
        if operation == "provision":
            self.peers.setdefault(peer, None)
        if operation == "revoke":
            self.peers.pop(peer, None)
        return dict(ok=True, public_key=server["public_key"], peer_present=peer in self.peers, handshake=self.peers.get(peer))


class BackendTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.server = dict(id="test-server", country="TEST FIXTURE", city="Not a real location",
                           public_key=key(), endpoint="vpn.example.test:51820",
                           socket="/run/cyber-one/test.sock", subnet4="10.42.0.0/24",
                           subnet6="fd42::/120", dns_plain=["10.42.0.1"], dns_filtered=["10.42.0.53"])
        self.cfg = Settings(database=str(Path(self.temp.name)/"test.sqlite3"), secret=Fernet.generate_key().decode(), servers=[self.server])
        self.broker = TestBroker()
        self.app = create_app(self.cfg, self.broker)
        self.client = TestClient(self.app, raise_server_exceptions=False)
        self.username = "user_"+secrets.token_hex(3)
        self.password = "a long password for tests"
        self.register(self.username)
        self.enroll()

    def tearDown(self):
        self.client.close()
        self.temp.cleanup()

    def register(self, username, invitation=None):
        disclosure = self.client.get("/api/disclosure").json()
        data = dict(username=username, password=self.password, name="Test Person", signature="test person",
                    agreed=True, disclosure_version=disclosure["version"], document_hash=disclosure["document_hash"], invitation=invitation)
        result = self.client.post("/api/auth/register", json=data)
        self.assertEqual(result.status_code, 201, result.text)
        self.client.headers["Authorization"] = "Bearer "+result.json()["access_token"]
        self.register_data = data
        self.registration = result.json()

    def enroll(self):
        self.secret = self.client.get("/api/auth/mfa/setup").json()["secret"]
        self.used_code = totp(self.secret, int(time.time()//30))
        result = self.client.post("/api/auth/mfa/confirm", json={"code": self.used_code})
        self.assertEqual(result.status_code, 200, result.text)
        self.codes = result.json()["recovery_codes"]
        self.client.headers["Authorization"] = "Bearer "+result.json()["access_token"]

    def device(self):
        result = self.client.post("/api/devices", json=dict(label="Test laptop", public_key=key()))
        self.assertEqual(result.status_code, 201, result.text)
        return result.json()["id"]

    def connect(self, device):
        return self.client.post("/api/connections", json={"device_id": device})

    def test_core_flow_never_fabricates_protection(self):
        device = self.device()
        result = self.connect(device)
        self.assertEqual(result.status_code, 200, result.text)
        body = result.json()
        self.assertEqual(body["state"], "waiting_for_client")
        self.assertIsNone(body["protected"])
        self.assertIsNone(body["evidence"]["public_ip"])
        self.assertIsNone(body["timing"]["protection_under_60_seconds"])
        self.assertEqual(body["configuration"]["peer"]["allowed_ips"], ["0.0.0.0/0", "::/0"])
        self.assertNotIn("private_key", body["configuration"])
        self.assertIsNone(body["configuration"]["adblock_verified"])
        self.assertEqual(self.client.delete("/api/connections/"+device).status_code, 200)
        self.assertEqual(len(self.broker.peers), 0)

    def test_realistic_handshake_is_limited_evidence(self):
        device = self.device()
        self.connect(device)
        peer = next(iter(self.broker.peers))
        self.broker.peers[peer] = int(time.time())
        body = self.client.get("/api/connections/"+device).json()
        self.assertTrue(body["evidence"]["recent_handshake"])
        self.assertIsNone(body["protected"])
        self.assertEqual(body["state"], "tunnel_contact_observed")

    def test_idempotent_connect_reuses_address(self):
        device = self.device()
        first, second = self.connect(device).json(), self.connect(device).json()
        self.assertEqual(first["configuration"], second["configuration"])
        self.assertEqual(len(self.broker.peers), 1)

    def test_parallel_device_allocations_are_unique(self):
        devices = [self.device(), self.device()]
        with ThreadPoolExecutor(2) as pool:
            replies = list(pool.map(self.connect, devices))
        self.assertTrue(all(r.status_code == 200 for r in replies))
        self.assertNotEqual(replies[0].json()["configuration"]["interface"]["address"], replies[1].json()["configuration"]["interface"]["address"])

    def test_family_owner_cannot_read_member_device(self):
        owner_token = self.client.headers["Authorization"]
        invitation = self.client.post("/api/family/invites").json()["invitation"]
        self.register("member_"+secrets.token_hex(3), invitation)
        self.enroll()
        device = self.device()
        self.client.headers["Authorization"] = owner_token
        self.assertEqual(self.client.get("/api/connections/"+device).status_code, 404)
        self.assertEqual(self.connect(device).status_code, 404)
        self.assertEqual(self.client.delete("/api/devices/"+device).status_code, 404)

    def test_family_limit_counts_outstanding_invitations(self):
        for _ in range(3):
            self.assertEqual(self.client.post("/api/family/invites").status_code, 201)
        self.assertEqual(self.client.post("/api/family/invites").status_code, 409)

    def test_enrollment_scope_cannot_provision(self):
        self.register("pending_"+secrets.token_hex(3))
        self.assertEqual(self.client.get("/api/devices").status_code, 403)

    def test_consent_names_not_stored_in_plaintext(self):
        with self.app.state.store.tx() as db:
            row = dict(db.execute("SELECT * FROM consents LIMIT 1").fetchone())
        self.assertNotIn("test person", json.dumps(row).lower())
        self.assertEqual(len(row["name_attestation"]), 64)

    def test_rejects_unsigned_or_stale_disclosure(self):
        for change in ({"agreed": False}, {"document_hash": "0"*64}, {"signature": "Other Person"}):
            data = dict(self.register_data, username="new_"+secrets.token_hex(3), **change)
            self.assertIn(self.client.post("/api/auth/register", json=data).status_code, (409,422))

    def test_no_sensitive_echo_in_validation(self):
        result = self.client.post("/api/auth/login", json={"username":"test", "password": "VERYSECRET"*100})
        self.assertEqual(result.status_code, 422)
        self.assertNotIn("VERYSECRET", result.text)

    def test_strict_types_and_unknown_fields(self):
        device = self.device()
        for body in ({"device_id":device,"adblock":"false"}, {"device_id":device,"destination_host":"127.0.0.1"}, {"device_id":device,"private_key":"secret"}):
            self.assertEqual(self.client.post("/api/connections", json=body).status_code, 422)

    def test_invalid_key_is_rejected(self):
        result = self.client.post("/api/devices", json={"label":"Laptop", "public_key":base64.b64encode(bytes(32)).decode()})
        self.assertEqual(result.status_code, 422)

    def test_unknown_server_rejected_before_probing(self):
        device = self.device()
        self.assertEqual(self.client.post("/api/connections", json={"device_id":device,"server_id":"unknown"}).status_code, 404)
        self.assertEqual(self.broker.calls, [])

    def test_no_broker_is_an_error_not_success(self):
        self.broker.fail = True
        self.assertEqual(self.connect(self.device()).status_code, 503)

    def test_failed_revocation_preserves_tracking(self):
        device = self.device()
        self.connect(device)
        self.broker.fail = True
        self.assertEqual(self.client.delete("/api/connections/"+device).status_code, 503)
        self.assertEqual(self.client.get("/api/connections/"+device).json()["state"], "revocation_pending")
        self.assertEqual(self.client.delete("/api/devices/"+device).status_code, 503)
        self.assertEqual(self.connect(device).status_code, 409)
        self.broker.fail = False
        self.assertEqual(self.client.delete("/api/connections/"+device).status_code, 200)

    def test_changed_dns_requires_explicit_disconnect(self):
        device = self.device()
        self.connect(device)
        self.assertEqual(self.client.post("/api/connections", json={"device_id":device,"adblock":False}).status_code, 409)

    def test_stale_handshake_warns_once_on_transition(self):
        device = self.device()
        self.connect(device)
        peer = next(iter(self.broker.peers))
        self.broker.peers[peer] = int(time.time())
        self.client.get("/api/connections/"+device)
        self.broker.peers[peer] = int(time.time())-181
        first = self.client.get("/api/connections/"+device).json()
        second = self.client.get("/api/connections/"+device).json()
        self.assertTrue(any(w["interrupt"] for w in first["warnings"]))
        self.assertFalse(any(w["interrupt"] for w in second["warnings"]))

    def test_totp_replay_and_recovery_code_reuse(self):
        self.assertEqual(self.client.post("/api/auth/login", json={"username":self.username,"password":self.password,"code":self.used_code}).status_code,401)
        data = dict(username=self.username,password=self.password,code=self.codes[0])
        self.assertEqual(self.client.post("/api/auth/login", json=data).status_code,200)
        self.assertEqual(self.client.post("/api/auth/login", json=data).status_code,401)

    def test_expired_session_and_logout(self):
        self.assertEqual(self.client.post("/api/auth/logout").status_code,200)
        self.assertEqual(self.client.get("/api/devices").status_code,401)

    def test_expired_session_is_removed(self):
        with self.app.state.store.tx() as db:
            db.execute("UPDATE sessions SET expires=0")
        self.assertEqual(self.client.get("/api/devices").status_code,401)

    def test_mfa_reset_invalidates_old_sessions(self):
        previous=self.client.headers["Authorization"]
        result=self.client.post("/api/auth/mfa/reset",json={"password":self.password,"code":self.codes[0]})
        self.assertEqual(result.status_code,200,result.text)
        self.assertEqual(result.json()["scope"],"enroll")
        self.assertEqual(self.client.get("/api/me").status_code,401)
        self.client.headers["Authorization"]="Bearer "+result.json()["access_token"]
        self.assertEqual(self.client.get("/api/devices").status_code,403)
        self.enroll()
        self.assertNotEqual(previous,self.client.headers["Authorization"])

    def test_partial_provision_timeout_retains_allocation(self):
        device=self.device()
        original=self.broker.call
        def ambiguous(server,operation,**payload):
            result=original(server,operation,**payload)
            if operation=="provision":raise BrokerUnavailable()
            return result
        self.broker.call=ambiguous
        self.assertEqual(self.connect(device).status_code,503)
        self.assertEqual(len(self.broker.peers),1)
        with self.app.state.store.tx() as db:
            row=db.execute("SELECT * FROM connections WHERE device_id=?",(device,)).fetchone()
            self.assertEqual(row["state"],"provisioning")
        self.broker.call=original
        self.assertEqual(self.client.delete("/api/connections/"+device).status_code,200)
        self.assertFalse(self.broker.peers)

    def test_origin_and_request_size(self):
        self.assertEqual(self.client.post("/api/auth/logout", headers={"Origin":"https://other.example"}).status_code,403)
        self.assertEqual(self.client.post("/api/auth/login", content=b"x"*16385).status_code,413)

    def test_security_headers_and_frontend(self):
        result = self.client.get("/")
        self.assertEqual(result.status_code,200)
        self.assertEqual(result.headers["cache-control"],"no-store")
        self.assertIn("frame-ancestors 'none'", result.headers["content-security-policy"])
        self.assertIn('aria-live="polite"',result.text)

    def test_identity_required_fails_closed(self):
        self.cfg.require_identity = True
        other = TestClient(create_app(self.cfg,self.broker))
        document = other.get("/api/disclosure").json()
        data = dict(self.register_data,username="blocked",document_hash=document["document_hash"])
        self.assertEqual(other.post("/api/auth/register",json=data).status_code,503)
        other.close()

    def test_delete_account_removes_records_and_peers(self):
        device = self.device()
        self.connect(device)
        response = self.client.request("DELETE","/api/account",json={"password":self.password,"code":self.codes[0]})
        self.assertEqual(response.status_code,200,response.text)
        self.assertFalse(self.broker.peers)
        self.assertEqual(self.client.get("/api/me").status_code,401)
        with self.app.state.store.tx() as db:
            for table in ["accounts","consents","devices","connections","sessions","recovery_codes"]:
                self.assertEqual(db.execute("SELECT count(*) FROM "+table).fetchone()[0],0)


class UnitTests(unittest.TestCase):
    def test_rfc6238_sha1_vector(self):
        secret=base64.b32encode(b"12345678901234567890").decode()
        self.assertEqual(totp(secret,1),"287082")
        self.assertEqual(valid_step(secret,"287082",-1,59),1)
        self.assertIsNone(valid_step(secret,"287082",1,59))

    def test_public_key_canonicalization(self):
        with self.assertRaises(ValueError): public_key("; arbitrary command")

    def test_dns_addresses_are_not_allocated_to_devices(self):
        server=dict(subnet4="10.42.0.0/29",subnet6="fd42::/120",dns_plain=["10.42.0.2"],dns_filtered=["10.42.0.3"])
        self.assertEqual(allocate(server,set())[0],"10.42.0.4")

    def test_blocklist_compilation_is_label_based_and_explicit(self):
        spec=importlib.util.spec_from_file_location("policy",Path(__file__).parent.parent/"agent/compile_blocklist.py")
        module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
        self.assertEqual(module.domain("ADS.Example.test."),"ads.example.test")
        rules=module.compile_rules({"ads.example.test","allowed.example.test"},{"allowed.example.test"})
        self.assertIn("local=/ads.example.test/",rules)
        self.assertIn("server=/allowed.example.test/#",rules)
        self.assertNotIn("local=/allowed.example.test/",rules)
        for bad in ["example.test\nlog-queries", "https://example.test", "127.0.0.1", "*.example.test", "example"]:
            with self.assertRaises(ValueError):module.domain(bad)

    def test_unix_broker_rejects_malformed_and_mismatched_observations(self):
        from unittest.mock import MagicMock
        server={"socket":"/run/test.sock","public_key":key()}
        for payload in [b'{"ok":true}\n',json.dumps(dict(ok=True,public_key=key(),peer_present=False,handshake=None)).encode()+b'\n']:
            fake=MagicMock();fake.__enter__.return_value=fake;fake.recv.return_value=payload
            with patch('backend.vpn.socket.socket',return_value=fake):
                with self.assertRaises(BrokerUnavailable):UnixBroker().call(server,"health")

    def test_receipt_document_changes_with_collection_policy(self):
        first=PrivacyDisclosureGate.get_plain_language_disclosure(False)
        second=PrivacyDisclosureGate.get_plain_language_disclosure(True)
        self.assertNotEqual(first["document_hash"],second["document_hash"])

    def test_warning_cooldown_and_recovery(self):
        engine=PlainLanguageWarningEngine()
        self.assertTrue(engine.build("a","b",["TUNNEL_LOST"])[0]["interrupt"])
        self.assertFalse(engine.build("a","b",["TUNNEL_LOST"])[0]["interrupt"])
        engine.build("a","b",[])
        self.assertTrue(engine.build("a","b",["TUNNEL_LOST"])[0]["interrupt"])

    def test_evidence_confusion_cases(self):
        # Eight labeled, synthetic cases test recent-contact logic only, not malware detection.
        cases=[(True,1000,True),(True,820,True),(True,819,False),(True,1001,False),
               (True,None,False),(False,1000,False),(False,None,False),(True,0,False)]
        engine=OneClickShieldManager(PlainLanguageWarningEngine())
        for index,(present,stamp,expected) in enumerate(cases):
            result=engine.evaluate("test",str(index),{"requested":900,"adblock":1},
                                   {"peer_present":present,"handshake":stamp},now=1000)
            self.assertEqual(result["evidence"]["recent_handshake"],expected)
            self.assertIsNone(result["protected"])

    def test_provisioned_but_unavailable_stays_unknown(self):
        engine=OneClickShieldManager(PlainLanguageWarningEngine())
        result=engine.evaluate("a","b",{"requested":100,"adblock":1},unavailable=True,now=200)
        self.assertIsNone(result["protected"])
        self.assertEqual(result["state"],"unknown")

    def test_broker_rejects_unexpected_operation_and_nonpool_address(self):
        spec=importlib.util.spec_from_file_location("broker",Path(__file__).parent.parent/"agent/broker.py")
        module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
        agent=module.Agent(dict(interface="wg0",subnet4="10.42.0.0/24",subnet6="fd42::/120"))
        with self.assertRaises(ValueError):agent.execute({"operation":"shell"})
        with patch.object(agent,"run",return_value=key()):
            with self.assertRaises(ValueError):agent.execute(dict(operation="provision",key=key(),address4="127.0.0.1",address6="fd42::2"))

    def test_broker_parses_real_wg_space_separated_allowed_ips(self):
        spec=importlib.util.spec_from_file_location("broker",Path(__file__).parent.parent/"agent/broker.py")
        module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
        agent=module.Agent(dict(interface="wg0",subnet4="10.42.0.0/24",subnet6="fd42::/120"))
        server,peer=key(),key()
        def run(*args):
            if args[-1]=="public-key":return server
            if args[-1]=="allowed-ips":return peer+"\t10.42.0.2/32 fd42::2/128"
            if args[-1]=="latest-handshakes":return peer+"\t0"
            return ""
        with patch.object(agent,"run",side_effect=run) as calls:
            result=agent.execute(dict(operation="provision",key=peer,address4="10.42.0.2",address6="fd42::2"))
            self.assertTrue(result["peer_present"])
            self.assertIsNone(result["handshake"])
            self.assertTrue(any(c.args[0]=="set" for c in calls.call_args_list))


if __name__ == "__main__":
    unittest.main()
