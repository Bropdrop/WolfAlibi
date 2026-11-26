"""Pinned three-member loopback etcd fixture. Each member has a private mount namespace."""
import base64
import hashlib
import http.client
import json
import os
from pathlib import Path
import secrets
import signal
import socket
import ssl
import subprocess
import time
from datetime import datetime,timedelta,timezone
from ipaddress import ip_address

from cryptography import x509
from cryptography.hazmat.primitives import hashes,serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import ExtendedKeyUsageOID as EK, NameOID
from research.blackout.experiment import reader_pid
from research.sovereign.links import Link

BINARY="c054131938a55a4a9826c1d566348d5695fe0e4d9ce655dfe936ab18a84e2983"
PREFIX="/governance/"

def issue(root,names):
    now=datetime.now(timezone.utc)
    name=lambda x:x509.Name([x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME,x)])
    signer=ec.generate_private_key(ec.SECP256R1())
    def builder(who,key):
        return x509.CertificateBuilder().subject_name(name(who)).issuer_name(name("sovereign-ca")).public_key(key.public_key()).serial_number(x509.random_serial_number()).not_valid_before(now-timedelta(minutes=1)).not_valid_after(now+timedelta(hours=2))
    ca=builder("sovereign-ca",signer).add_extension(x509.BasicConstraints(True,0),True).sign(signer,hashes.SHA256())
    for who in names:
        d=root/who
        d.mkdir(mode=0o700)
        key=ec.generate_private_key(ec.SECP256R1())
        cert=builder(who,key).add_extension(x509.SubjectAlternativeName([x509.IPAddress(ip_address("127.0.0.1")),x509.DNSName(who)]),False).add_extension(x509.ExtendedKeyUsage([EK.CLIENT_AUTH,EK.SERVER_AUTH]),False).sign(signer,hashes.SHA256())
        for fn,obj in (("ca",ca),("cert",cert)):
            (d/(fn+".pem")).write_bytes(obj.public_bytes(serialization.Encoding.PEM))
        (d/"key.pem").write_bytes(key.private_bytes(serialization.Encoding.PEM,serialization.PrivateFormat.PKCS8,serialization.NoEncryption()))
        (d/"key.pem").chmod(0o600)


def tls(d,server=False):
    ctx=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER if server else ssl.PROTOCOL_TLS_CLIENT)
    ctx.minimum_version=ssl.TLSVersion.TLSv1_3
    ctx.verify_mode=ssl.CERT_REQUIRED
    ctx.load_verify_locations(cafile=d/"ca.pem")
    ctx.load_cert_chain(d/"cert.pem",d/"key.pem")
    return ctx


def rpc(port,ctx,method,data,timeout=1):
    conn=http.client.HTTPSConnection("127.0.0.1",port,context=ctx,timeout=timeout)
    try:
        conn.connect()
        expected=ctx.member_pins[str(port)]
        if hashlib.sha256(conn.sock.getpeercert(binary_form=True)).hexdigest()!=expected:
            raise ValueError("member TLS identity")
        headers={"Content-Type":"application/json"}
        if getattr(ctx,"token",None):headers["Authorization"]=ctx.token
        conn.request("POST","/v3/"+method,json.dumps(data).encode(),headers)
        r=conn.getresponse()
        body=r.read()
        if not body.startswith(b"{"):raise RuntimeError((r.status,body[:250]))
        result=json.loads(body)
        if r.status!=200 or "error" in result:
            raise RuntimeError(result)
        return result
    finally:conn.close()


def b64(b):return base64.b64encode(b).decode()
def key(index):return b64((PREFIX+str(index)).encode())
def write(port,ctx,index,record):
    k=key(index)
    compare=[dict(key=k,target="VERSION",version="0")]
    if index>1:compare.append(dict(key=key(index-1),target="VERSION",result="GREATER",version="0"))
    return rpc(port,ctx,"kv/txn",dict(compare=compare,success=[dict(request_put=dict(key=k,value=b64(json.dumps(record,sort_keys=True).encode())))],failure=[])).get("succeeded",False)


def read(port,ctx,index,timeout=1):
    doc=rpc(port,ctx,"kv/range",dict(key=key(index)),timeout)
    return json.loads(base64.b64decode(doc["kvs"][0]["value"])) if doc.get("kvs") else None


class Cluster:
    def __init__(self,root,binary):
        self.root=root
        self.binary=Path(binary).resolve()
        if hashlib.sha256(self.binary.read_bytes()).hexdigest()!=BINARY:raise ValueError("etcd binary pin")
        ports=[]
        with socket.socket() as test:
            test.bind(("127.0.0.1",0))
        leased=[socket.socket() for _ in range(6)]
        try:
            for s in leased:
                s.bind(("127.0.0.1",0)); ports.append(s.getsockname()[1])
        finally:
            for s in leased:s.close()
        self.clients,self.peers=ports[:3],ports[3:]
        self.procs={}
        self.pids={}
        self.stopped=set()
        self.ctx=tls(root/"root")
        self.writer=tls(root/"publisher")
        self.reader=tls(root/"target")
        self.pins={str(port):x509.load_pem_x509_certificate((root/f"m{i}"/"cert.pem").read_bytes()).fingerprint(hashes.SHA256()).hex() for i,port in enumerate(self.clients)}
        for ctx in (self.ctx,self.writer,self.reader):ctx.member_pins=self.pins
        self.links={(i,j):Link(i,j,self.peers[j]) for i in range(3) for j in range(3) if i!=j}
        self.initial=",".join(f"m{i}=https://m{i}:{p}" for i,p in enumerate(self.peers))

    def start(self,i):
        d=self.root/f"m{i}"
        data=d/"data";data.mkdir(exist_ok=True)
        u=lambda p:f"https://127.0.0.1:{p}"
        (d/"hosts").write_text("127.0.0.1 localhost\n"+"".join((("127.0.0.1" if j==i else f"127.0.{i+1}.{j+1}")+f" m{j}\n") for j in range(3)))
        args=["bwrap","--die-with-parent","--unshare-all","--share-net","--clearenv","--setenv","GOMAXPROCS","2",
            "--ro-bind","/usr","/usr","--symlink","usr/lib","/lib","--symlink","usr/lib64","/lib64",
            "--proc","/proc","--dev","/dev","--tmpfs","/tmp","--ro-bind",str(self.binary),"/etcd",
            "--ro-bind",str(d/"hosts"),"/etc/hosts","--bind",str(d),"/member","--","/etcd","--name",f"m{i}","--data-dir","/member/data",
            "--initial-cluster",self.initial,"--initial-cluster-token","sovereign-local","--listen-client-urls",u(self.clients[i]),"--advertise-client-urls",u(self.clients[i]),
            "--listen-peer-urls",u(self.peers[i]),"--initial-advertise-peer-urls",f"https://m{i}:{self.peers[i]}",
            "--auth-token-ttl","3600","--client-cert-auth","--peer-client-cert-auth","--trusted-ca-file","/member/ca.pem","--peer-trusted-ca-file","/member/peer/ca.pem",
            "--cert-file","/member/cert.pem","--key-file","/member/key.pem","--peer-cert-file","/member/peer/cert.pem","--peer-key-file","/member/peer/key.pem","--log-level","error"]
        with (d/"run.log").open("ab") as log:self.procs[i]=subprocess.Popen(args,stdout=log,stderr=log)
    def secure(self):
        port=self.clients[0]
        passwords={}
        for who in ("root","publisher","target","auditor"):
            passwords[who]=secrets.token_hex(24)
            rpc(port,self.ctx,"auth/user/add",dict(name=who,password=passwords[who]))
            rpc(port,self.ctx,"auth/role/add",dict(name=who))
            rpc(port,self.ctx,"auth/user/grant",dict(user=who,role=who))
            if who!="root":
                rpc(port,self.ctx,"auth/role/grant",dict(name=who,perm=dict(permType="READWRITE" if who=="publisher" else "READ",key=b64(PREFIX.encode()),range_end=b64(b"/governance0"))))
        rpc(port,self.ctx,"auth/enable",{})
        self.auditor=tls(self.root/"auditor")
        self.auditor.member_pins=self.pins
        for name,ctx in (("root",self.ctx),("publisher",self.writer),("target",self.reader),("auditor",self.auditor)):
            ctx.token=rpc(port,ctx,"auth/authenticate",dict(name=name,password=passwords[name]))["token"]
        self.passwords=passwords
        return passwords
    def status(self,i):
        return rpc(self.clients[i],self.ctx,"maintenance/status",{})
    def wait(self,indices):
        end=time.monotonic()+12
        while time.monotonic()<end:
            try:
                for i in indices:
                    if not int(self.status(i)["leader"]):raise ValueError("no leader")
                read(self.clients[indices[0]],self.ctx,1)
                for i in indices:self.pids[i]=reader_pid(self.procs[i])
                return
            except (OSError,RuntimeError,ValueError,KeyError):time.sleep(.06)
        raise RuntimeError("no quorum: "+str([p.poll() for p in self.procs.values()])+str([(self.root/f"m{i}"/"run.log").read_text()[-400:] for i in indices]))
    def partition(self,member,connected):
        for pair,link in self.links.items():
            if member in pair:link.set(connected)
    def pause(self,i):
        os.kill(self.pids[i],signal.SIGSTOP);self.stopped.add(i)
    def resume(self,i):
        os.kill(self.pids[i],signal.SIGCONT);self.stopped.discard(i)
    def close(self):
        for i in list(self.stopped):self.resume(i)
        for p in self.procs.values():
            if p.poll() is None:p.terminate()
        for p in self.procs.values():
            try:p.wait(4)
            except subprocess.TimeoutExpired:p.kill();p.wait()
        for link in self.links.values():link.close()

