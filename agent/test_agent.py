"""Standard-library unit tests; all wg output is a synthetic fixture."""
import base64
import hashlib
import hmac
import json
from pathlib import Path
import secrets
import tempfile
import time
import unittest
from unittest.mock import patch
from server import Agent

def key():return base64.b64encode(secrets.token_bytes(32)).decode()

class AgentTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.server=key();self.peer=key()
        self.agent=Agent(dict(interface='wg0',subnet4='10.42.0.0/24',subnet6='fd42::/120',shared_secret='a-test-only-secret-with-enough-characters',state_database=str(Path(self.tmp.name)/'state.db'),reserved_addresses=['10.42.0.53']))
        self.peers={};self.ranges={};self.calls=[]
        def run(*args):
            self.calls.append(args)
            if args[-1]=='public-key':return self.server
            if args[-1]=='allowed-ips':return '\n'.join(k+'\t'+v for k,v in self.ranges.items())
            if args[-1]=='latest-handshakes':return '\n'.join(k+'\t0' for k in self.peers)
            if args[0]=='set':
                peer=args[3]
                if args[-1]=='remove':self.peers.pop(peer,None);self.ranges.pop(peer,None)
                else:self.peers[peer]=True;self.ranges[peer]=args[-1].replace(',',' ')
            return ''
        self.patch=patch.object(self.agent,'run',side_effect=run);self.patch.start()
    def tearDown(self):self.patch.stop();self.agent.state.close();self.tmp.cleanup()
    def provision(self,sequence=1):return dict(operation='provision',key=self.peer,sequence=sequence,address4='10.42.0.2',address6='fd42::2')
    def headers(self,body,nonce=None):
        stamp=str(int(time.time()*1000));nonce=nonce or secrets.token_hex(24)
        signature=hmac.new(self.agent.secret,stamp.encode()+b'\n'+nonce.encode()+b'\n'+body,hashlib.sha256).hexdigest()
        return {'x-co-time':stamp,'x-co-nonce':nonce,'x-co-signature':signature}
    def test_provision_is_idempotent_and_uses_fixed_interface(self):
        self.assertTrue(self.agent.execute(self.provision())['peerPresent']);self.assertTrue(self.agent.execute(self.provision())['peerPresent'])
        self.assertTrue(all(args[1]=='wg0' for args in self.calls))
        self.assertFalse(any('private-key' in args or 'dump' in args for args in self.calls))
    def test_revoke_sequence_prevents_late_provision(self):
        self.agent.execute(self.provision());self.agent.execute(dict(operation='revoke',key=self.peer,sequence=2))
        with self.assertRaises(ValueError):self.agent.execute(self.provision())
        self.assertFalse(self.peers)
    def test_same_sequence_cannot_change_operation(self):
        self.agent.execute(self.provision())
        with self.assertRaises(ValueError):self.agent.execute(dict(operation='revoke',key=self.peer,sequence=1))
    def test_outside_pool_and_reserved_addresses_rejected(self):
        for address in ['127.0.0.1','10.42.0.1','10.42.0.53','10.43.0.2']:
            with self.assertRaises(ValueError):self.agent.execute(dict(self.provision(),address4=address))
    def test_authenticated_nonce_replay_rejected(self):
        body=b'{"operation":"health"}';headers=self.headers(body)
        self.agent.authenticate(headers,body)
        with self.assertRaises(Exception):self.agent.authenticate(headers,body)
    def test_modified_body_and_signature_rejected(self):
        body=b'{"operation":"health"}';headers=self.headers(body)
        with self.assertRaises(ValueError):self.agent.authenticate(headers,body+b' ')
        headers['x-co-signature']='0'*64
        with self.assertRaises(ValueError):self.agent.authenticate(headers,body)
    def test_stale_request_timestamp_rejected(self):
        body=b'{}';headers=self.headers(body);headers['x-co-time']=str(int(time.time()*1000)-60000)
        with self.assertRaises(ValueError):self.agent.authenticate(headers,body)
    def test_command_and_extra_field_rejected(self):
        for request in [dict(operation='shell'),dict(operation='health',interface='eth0'),dict(self.provision(),sequence=True)]:
            with self.assertRaises(ValueError):self.agent.execute(request)

if __name__=='__main__':unittest.main()
