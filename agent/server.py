#!/usr/bin/env python3
"""Linux-only fixed-interface HTTPS WireGuard manager. Standard library only.

This is a management service, not a VPN protocol. Deploy only on your owned host.
Require an operator TLS certificate, private firewall, and a separate HMAC secret.
"""
import argparse
import base64
import hashlib
import hmac
from http.server import BaseHTTPRequestHandler, HTTPServer
import ipaddress
import json
import os
from pathlib import Path
import re
import sqlite3
import ssl
import stat
import subprocess
import time


def public_key(value):
    raw=base64.b64decode(value,validate=True)
    if len(raw)!=32 or raw==bytes(32) or base64.b64encode(raw).decode()!=value:
        raise ValueError('Invalid public key')
    return value


class Agent:
    def __init__(self,config):
        self.config=config
        self.interface=config['interface']
        if not re.fullmatch(r'[a-zA-Z0-9_-]{1,15}',self.interface):raise ValueError('Invalid fixed interface')
        self.networks=[ipaddress.ip_network(config['subnet4']),ipaddress.ip_network(config['subnet6'])]
        if self.networks[0].version!=4 or self.networks[0].prefixlen!=24 or self.networks[1].version!=6 or self.networks[1].prefixlen!=120 or not all(network.is_private for network in self.networks):raise ValueError('Use private /24 IPv4 and /120 IPv6 tunnel pools')
        self.secret=config['shared_secret'].encode()
        if len(self.secret)<32:raise ValueError('Use a strong independent management secret')
        self.wg=config.get('wg_binary','/usr/bin/wg')
        if not Path(self.wg).is_absolute():raise ValueError('wg must use a fixed absolute path')
        self.state=sqlite3.connect(config['state_database'],timeout=5)
        self.state.executescript('CREATE TABLE IF NOT EXISTS nonces(hash TEXT PRIMARY KEY,expires INTEGER NOT NULL); CREATE TABLE IF NOT EXISTS operations(key TEXT PRIMARY KEY,sequence INTEGER NOT NULL,fingerprint TEXT NOT NULL);')
        if os.name!='nt':os.chmod(config['state_database'],0o600)

    def run(self,*args):
        return subprocess.run([self.wg,*args],check=True,timeout=2,capture_output=True,text=True,env={'PATH':'/usr/bin:/bin','LC_ALL':'C'}).stdout.strip()

    def authenticate(self,headers,body):
        stamp=headers.get('x-co-time','');nonce=headers.get('x-co-nonce','');signature=headers.get('x-co-signature','')
        if not re.fullmatch(r'\d{13}',stamp) or abs(int(stamp)-int(time.time()*1000))>30000 or not re.fullmatch(r'[a-f0-9]{48}',nonce):raise ValueError('Invalid request authentication')
        expected=hmac.new(self.secret,stamp.encode()+b'\n'+nonce.encode()+b'\n'+body,hashlib.sha256).hexdigest()
        if not hmac.compare_digest(expected,signature):raise ValueError('Invalid signature')
        now=int(time.time()*1000)
        with self.state:
            self.state.execute('DELETE FROM nonces WHERE expires<=?',(now,))
            self.state.execute('INSERT INTO nonces VALUES(?,?)',(hashlib.sha256(nonce.encode()).hexdigest(),now+60000))

    def execute(self,request):
        if not isinstance(request,dict):raise ValueError('Object required')
        op=request.get('operation')
        permitted={'health':{'operation'},'status':{'operation','key'},'revoke':{'operation','key','sequence'},'provision':{'operation','key','sequence','address4','address6'}}
        if op not in permitted or set(request)!=permitted[op]:raise ValueError('Unsupported operation or fields')
        server_key=public_key(self.run('show',self.interface,'public-key'))
        if op=='health':return dict(publicKey=server_key,peerPresent=False,handshake=None)
        key=public_key(request['key'])
        if op in ('provision','revoke'):
            sequence=request['sequence']
            if isinstance(sequence,bool) or not isinstance(sequence,int) or not 1<=sequence<=9007199254740991:raise ValueError('Invalid operation sequence')
            fingerprint=hashlib.sha256(json.dumps(request,sort_keys=True).encode()).hexdigest()
            previous=self.state.execute('SELECT sequence,fingerprint FROM operations WHERE key=?',(key,)).fetchone()
            if previous and (sequence<previous[0] or (sequence==previous[0] and fingerprint!=previous[1])):raise ValueError('Stale operation')
            if op=='provision':
                addresses=[ipaddress.ip_address(request['address4']),ipaddress.ip_address(request['address6'])]
                for address,network in zip(addresses,self.networks):
                    if address not in network or int(address)-int(network.network_address)<2 or address==network.broadcast_address or str(address) in self.config.get('reserved_addresses',[]):raise ValueError('Invalid allocation')
                expected={str(addresses[0])+'/32',str(addresses[1])+'/128'}
                for line in self.run('show',self.interface,'allowed-ips').splitlines():
                    other,ranges=line.split('\t',1)
                    networks=[ipaddress.ip_network(value) for value in ranges.split() if value!='(none)']
                    if other!=key and any(address.version==network.version and address in network for address in addresses for network in networks):raise ValueError('Allocation conflict')
                    if other==key and {str(network) for network in networks}!=expected:raise ValueError('Peer allocation changed')
                args=('set',self.interface,'peer',key,'allowed-ips',','.join(sorted(expected)))
            else:args=('set',self.interface,'peer',key,'remove')
            # Persist the sequence before side effects: retries may reapply the same
            # request; an older request can never overtake a later revoke after restart.
            with self.state:self.state.execute('INSERT INTO operations VALUES(?,?,?) ON CONFLICT(key) DO UPDATE SET sequence=excluded.sequence,fingerprint=excluded.fingerprint',(key,sequence,fingerprint))
            self.run(*args)
        stamps={}
        for line in self.run('show',self.interface,'latest-handshakes').splitlines():
            peer,stamp=line.split('\t');stamps[peer]=int(stamp)*1000 or None
        return dict(publicKey=server_key,peerPresent=key in stamps,handshake=stamps.get(key))


def main():
    parser=argparse.ArgumentParser();parser.add_argument('config',type=Path);args=parser.parse_args()
    info=args.config.stat()
    if info.st_uid!=0 or stat.S_IMODE(info.st_mode)&0o022:raise SystemExit('Config must be root-owned and not group/world writable')
    config=json.loads(args.config.read_text())
    state=Path(config['state_database'])
    if not state.is_absolute() or state.is_symlink() or state.parent.stat().st_uid!=0 or state.parent.stat().st_mode&0o022:raise SystemExit('Use a root-owned, non-writable directory and absolute state database path')
    if state.exists() and (state.stat().st_uid!=0 or state.stat().st_mode&0o077):raise SystemExit('State database must be root-owned and private')
    key_info=Path(config['tls_private_key']).stat()
    if key_info.st_uid!=0 or key_info.st_mode&0o077:raise SystemExit('TLS private key must be root-owned and private')
    agent=Agent(config)
    class Handler(BaseHTTPRequestHandler):
        def log_message(self,*args):pass
        def do_POST(self):
            self.connection.settimeout(5)
            try:
                if self.path!='/v1/peer' or self.headers.get('transfer-encoding'):raise ValueError('Invalid path/encoding')
                length=int(self.headers.get('content-length','0'))
                if not 1<=length<=4096 or self.headers.get('content-type')!='application/json':raise ValueError('Invalid body')
                body=self.rfile.read(length)
                if len(body)!=length:raise ValueError('Incomplete body')
                agent.authenticate(self.headers,body)
                reply=agent.execute(json.loads(body));encoded=json.dumps(reply).encode();self.send_response(200)
            except Exception:
                encoded=b'{"error":"Management operation not confirmed"}';self.send_response(503)
            self.send_header('content-type','application/json');self.send_header('cache-control','no-store');self.send_header('content-length',str(len(encoded)));self.end_headers();self.wfile.write(encoded)
    server=HTTPServer((config.get('listen_host','127.0.0.1'),int(config.get('listen_port',9443))),Handler)
    context=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER);context.minimum_version=ssl.TLSVersion.TLSv1_2
    context.load_cert_chain(config['tls_certificate'],config['tls_private_key']);server.socket=context.wrap_socket(server.socket,server_side=True)
    server.serve_forever()


if __name__=='__main__':main()
