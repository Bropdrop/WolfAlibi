"""Offline artifact cross-check; no live execution or production assurance."""
import json, hashlib, zipfile, struct, statistics, sqlite3, tempfile, pathlib, collections, sys
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from cryptography.exceptions import InvalidSignature
zpath=pathlib.Path(sys.argv[1] if len(sys.argv)>1 else '/mnt/data/WT-SIREN-002-evidence.zip')
H=lambda b:hashlib.sha256(b).hexdigest()
canon=lambda x:json.dumps(x,sort_keys=True,separators=(',',':')).encode()
count=collections.Counter()
def check(name, ok):
    if not ok: raise AssertionError(name)
    count[name]+=1
def sig(pub,domain,message,signature):
    Ed25519PublicKey.from_public_bytes(bytes.fromhex(pub)).verify(bytes.fromhex(signature),domain+b'\0'+canon(message))
with zipfile.ZipFile(zpath) as z:
    files=[i.filename for i in z.infolist() if not i.is_dir()]
    manifest=dict((p,h) for h,p in (l.split('  ',1) for l in z.read('SHA256SUMS').decode().splitlines() if l))
    check('manifest exact coverage',len(files)==len(set(files)) and set(manifest)==set(files)-{'SHA256SUMS'})
    for p,h in manifest.items(): check('manifest file hashes',H(z.read(p))==h)
    if len(sys.argv)>2: check('external manifest equals embedded',pathlib.Path(sys.argv[2]).read_bytes()==z.read('SHA256SUMS'))
    summary={}
    all_challenges=set()
    for series in ('evidence','initial-evidence'):
        data=json.loads(z.read(series+'/results.json')); planned=dict(json.loads(z.read(series+'/planned-runs.json'))); ref=json.loads(z.read(series+'/reference.json'))
        check('source pin',ref['commit']=='774ea270ee00ea5728e8400f54c2fd70f8c467be' and ref['tree']=='0b43d17c4b64e5bed82d9797143e4995c8089911')
        check('trial corpus coverage',len(planned)==len(data['runs'])==10 and set(planned)=={r['run_id'] for r in data['runs']})
        rows=[]
        for row in data['runs']:
            run=row['run_id']; p=series+'/'+run+'/'
            read=lambda f:z.read(p+f)
            load=lambda f:json.loads(read(f))
            expected=load('expected.json'); envelope=load('evidence.json'); sr=envelope['supervisor_record']; ev=envelope['evidence']; pl=ev['payload']; sp=sr['payload']; contract=expected['contract']; nonce=contract['challenge'];
            check('unique challenge and corpus binding',nonce not in all_challenges and len(bytes.fromhex(nonce))==32 and planned[run]==row['challenge']==nonce and contract['run_id']==run); all_challenges.add(nonce)
            check('per-trial result equals aggregate',row==load('result.json'))
            check('contract and receipt binding',contract==pl['contract'] and sp['contract_sha256']==H(canon(contract)) and sp['evidence_sha256']==H(canon(ev)))
            check('assurance',pl['assurance']==sp['assurance']=='BROKER_ONLY')
            check('expected key identities',pl['broker']==expected['broker_pub'] and pl['witness']==expected['witness_pub'])
            sig(expected['supervisor_pub'],b'wolfalibi/solitary/supervisor/v1',sp,sr['signature']); count['supervisor signatures']+=1
            for kind,domain in [('broker',b'alibi/receipt/broker/v1'),('witness',b'alibi/receipt/witness/v1')]:
                sig(expected[kind+'_pub'],domain,pl,ev[kind+'_signature']); count['receipt signatures']+=1
            for item in ev['witness_state_chain']:
                sig(expected['witness_pub'],b'alibi/witness-state-anchor/v1',item['anchor'],item['signature']); count['witness anchor signatures']+=1
            check('witness chain generations',[x['anchor']['generation'] for x in ev['witness_state_chain']]==[1,2,3]); prev=expected['expected_witness_state_digest']
            for item in ev['witness_state_chain']:
                a=item['anchor']; check('witness anchor link',a['previous_state_digest']==prev); prev=a['state_digest']
            wal=read('broker.wal'); check('journal binding',bytes.fromhex(ev['journal_hex'])==wal and pl['journal_sha256']==H(wal)); frames=[]; i=0
            while i<len(wal):
                check('journal magic',wal[i:i+7]==b'WALBJ2\0'); n=struct.unpack_from('>I',wal,i+7)[0]; body=wal[i+11:i+11+n]; digest=wal[i+11+n:i+11+n+32]; check('journal frame digest',len(body)==n and hashlib.sha256(body).digest()==digest); frames.append(json.loads(body)); i+=11+n+32
            check('journal end',i==len(wal)); check('journal shape',len(frames)==4 and [f['t'] for f in frames]==['e','s','e','s'])
            for ix,label in [(1,'start'),(3,'end')]:
                f=frames[ix]; check('journal seal binding',f=={'t':'s','epoch':ix//2,**pl[label]})
                for kind,field,domain in [('broker','sig',b'alibi/broker/v1'),('witness','wsig',b'alibi/witness/v1')]:
                    sig(expected[kind+'_pub'],domain,f['cp'],f[field]); count['checkpoint signatures']+=1
            check('single recorded fixture read',frames[2]=={'t':'e','m':1,'seq':2,'k':b'protected.txt'.hex()} and frames[0]['m']==1 and frames[0]['seq']==1 and bytes.fromhex(frames[0]['k']).startswith(b'\0wolfalibi-stage3:'))
            check('fixture bytes and response',H(read('protected.txt'))==contract['fixture_sha256']==pl['observations']['response_sha256'])
            recon=load('reconciliation.json'); check('reconciliation corroboration',recon['decoded_wal']==frames and all(recon['checks'].values()) and recon['authorized_fixture_reads']==1 and recon['broker_recorded_protected_writes']==0 and recon['fixture_sha256']==H(read('protected.txt')) and recon['post_exit_proc_check']=={'launcher':'ABSENT','worker':'ABSENT'})
            check('worker hash binding',sp['snapshot']['executable']['argv_source_sha256']==ref['sha256']['worker'] and sp['snapshot']['executable']['sha256']==ref['sha256']['python'] and contract['profile']['worker_sha256']==ref['sha256']['worker'])
            check('closure and cleanup report',all(sp['closure'].values()) and row['disposable_state_removed'])
            for label,outcome,exitcode in [('trial','COMPLETED',0),('historical','VERIFIED',0),('altered','REJECTED',2),('incomplete','BLOCKED',2),('expired','REJECTED',2)]:
                stdout=load(label+'.stdout'); cmd=load(label+'.command.json'); check('command outcome and timing',stdout['outcome']==outcome and cmd['exit']==exitcode and cmd['latency_ns']==row[('execution' if label=='trial' else label)+'_latency_ns']);
            hist=load('historical.stdout'); check('historical result binding',hist['witness_state_digest']==prev and hist['assurance']=='BROKER_ONLY' and hist['confinement']=='BLOCKED' and hist['freshness']=='HISTORICAL_VERIFICATION_ONLY')
            check('fresh acceptance',load('trial.stdout')['fresh_acceptance']['outcome']=='VERIFIED' and load('trial.stdout')['fresh_acceptance']['witness_state_digest']==prev)
            altered=load('altered.json'); assert altered['supervisor_record']['signature']==sr['signature'];
            try: sig(expected['supervisor_pub'],b'wolfalibi/solitary/supervisor/v1',altered['supervisor_record']['payload'],sr['signature'])
            except InvalidSignature: count['altered supervisor signature rejected']+=1
            else: raise AssertionError('altered signature verified')
            check('incomplete record has no signature','signature' not in load('incomplete.json')['supervisor_record'])
            check('expired input',load('expired-expectation.json')=={**expected,'now':contract['expires_at']})
            replay=load('replay.json'); check('replay result',replay['result']['outcome']=='REJECTED' and replay['witness_head_unchanged'])
            if series=='evidence':
                fw=load('fresh-validity-window.json'); check('fresh store expiry paired control',fw['expired']['result']['outcome']=='REJECTED' and fw['expired']['head']==expected['expected_witness_state_digest'] and fw['in_window']['result']['outcome']=='VERIFIED' and fw['in_window']['head']==prev)
            with tempfile.TemporaryDirectory() as d:
                db=pathlib.Path(d)/'v.db'; db.write_bytes(read('verifier.db'))
                with sqlite3.connect(db.as_uri()+'?mode=ro',uri=True) as c:
                    check('SQLite integrity',c.execute('pragma integrity_check').fetchone()==('ok',))
                    records=c.execute('select run_id,hex(accepted_head),hex(accepted_envelope) from issued_challenges').fetchall(); check('one accepted challenge store record',len(records)==1 and records[0][0]==run and records[0][1].lower()==prev and records[0][2].lower()==load('trial.stdout')['fresh_acceptance']['accepted_envelope_sha256'])
                    heads=c.execute('select hex(witness),hex(head) from witness_heads').fetchall(); check('accepted witness head',len(heads)==1 and heads[0][0].lower()==expected['witness_pub'] and heads[0][1].lower()==prev)
            rows.append({'run_id':run,'challenge':nonce,'result':row['result'],'checks':row['checks'],'execution_ns':row['execution_latency_ns'],'historical_ns':row['historical_latency_ns'],'receipt_file_sha256':H(read('evidence.json')),'journal_file_sha256':H(wal),'fixture_file_sha256':H(read('protected.txt')),'recorded_authorized_reads':1,'recorded_protected_writes':0})
        summary[series]={'outcome':data['outcome'],'runs':rows,'median_execution_ms':statistics.median(r['execution_ns'] for r in rows)/1e6,'median_historical_ms':statistics.median(r['historical_ns'] for r in rows)/1e6}
    print(json.dumps({'archive_sha256':H(zpath.read_bytes()),'manifest_sha256':H(z.read('SHA256SUMS')),'check_counts':dict(count),'series':summary},indent=2))
