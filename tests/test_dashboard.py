import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch
from dashboard.app import create_app
from dashboard.service import validate_name, parse_status, available_slot


class FakeService:
    def __init__(self):
        self.devices = [{'name':'windows','slot':2,'managed':True,'upload':100,'download':200,'handshake':0,'export':True}]
        self.revoked=[]
    def status(self):
        return {'devices':self.devices,'ip':'203.0.113.1','type':'t3.micro','credits':'standard','active':True,'checked_at':1}
    def create(self,name):
        if any(d['name']==name for d in self.devices):raise ValueError('Device already exists')
        self.devices.append({'name':name,'slot':3,'managed':True,'export':True})
        return {'name':name}
    def revoke(self,name):
        self.revoked.append(name)
        self.devices=[d for d in self.devices if d['name']!=name]
    def artifact(self,name,kind):
        if name not in [d['name'] for d in self.devices]:raise ValueError('Unknown device')
        return (b'PRIVATE_CONTENT' if kind=='conf' else b'PNG_BYTES')


class DashboardAPI(unittest.TestCase):
    def setUp(self):
        self.service=FakeService()
        self.app=create_app(self.service,'test-token')
        self.client=self.app.test_client()
        self.headers={'Authorization':'Bearer test-token','Origin':'http://localhost'}
    def test_status_requires_token_and_never_contains_configuration(self):
        self.assertEqual(self.client.get('/api/status').status_code,401)
        response=self.client.get('/api/status',headers=self.headers)
        self.assertEqual(response.status_code,200)
        self.assertNotIn(b'PRIVATE_CONTENT',response.data)
        self.assertEqual(response.json['devices'][0]['name'],'windows')
    def test_create_and_revoke_leave_windows_intact(self):
        response=self.client.post('/api/devices',json={'name':'phone'},headers=self.headers)
        self.assertEqual(response.status_code,201)
        self.assertEqual(self.client.delete('/api/devices/phone',headers=self.headers).status_code,200)
        self.assertEqual(self.service.devices[0]['name'],'windows')
    def test_invalid_names_cannot_reach_service(self):
        for name in ['../key','hello; id','a\n[Peer]','', 'a'*33,5]:
            response=self.client.post('/api/devices',json={'name':name},headers=self.headers)
            self.assertEqual(response.status_code,400)
        self.assertEqual(len(self.service.devices),1)
    def test_foreign_origin_and_rebinding_host_rejected(self):
        headers={**self.headers,'Origin':'https://evil.example'}
        self.assertEqual(self.client.post('/api/devices',json={'name':'phone'},headers=headers).status_code,403)
        self.assertEqual(self.client.get('/api/status',headers={**self.headers,'Host':'evil.example'}).status_code,403)
    def test_download_is_authorized_attachment_no_cache(self):
        r=self.client.get('/api/devices/windows/conf',headers=self.headers)
        self.assertEqual(r.data,b'PRIVATE_CONTENT')
        self.assertIn('attachment',r.headers['Content-Disposition'])
        self.assertIn('no-store',r.headers['Cache-Control'])
        self.assertEqual(self.client.get('/api/devices/missing/conf',headers=self.headers).status_code,400)
        self.assertEqual(self.client.get('/api/devices/windows/other',headers=self.headers).status_code,404)
    def test_duplicate_create_and_bad_json(self):
        self.assertEqual(self.client.post('/api/devices',json={'name':'windows'},headers=self.headers).status_code,400)
        self.assertEqual(self.client.post('/api/devices',data='bad',content_type='application/json',headers=self.headers).status_code,400)
    def test_errors_do_not_expose_exception_details(self):
        with patch.object(self.service,'status',side_effect=RuntimeError('PRIVATE_CONTENT')):
            r=self.client.get('/api/status',headers=self.headers)
        self.assertEqual(r.status_code,503)
        self.assertNotIn(b'PRIVATE_CONTENT',r.data)
    def test_frontend_is_available_with_security_headers(self):
        r=self.client.get('/')
        self.assertEqual(r.status_code,200)
        self.assertIn('default-src',r.headers['Content-Security-Policy'])
        self.assertEqual(r.headers['X-Frame-Options'],'DENY')
        r.close()
    def test_missing_page_returns_404(self):
        self.assertEqual(self.client.get('/missing').status_code,404)

    def test_request_size_is_limited(self):
        r=self.client.post('/api/devices',data='a'*5000,content_type='application/json',headers=self.headers)
        self.assertEqual(r.status_code,413)


class StatusParsing(unittest.TestCase):
    def test_parse_named_and_unmanaged_peers_and_direction(self):
        result=parse_status({'active':True,'public_key':'SERVER','boot_id':'BOOT','uptime':10,'peers':[{'public_key':'PUBLIC','name':'windows','allowed_ips':'10.66.66.2/32,fd42:66:66::2/128','rx':123,'tx':456,'handshake':0},{'public_key':'OTHER','name':None,'allowed_ips':'10.66.66.9/32','rx':0,'tx':0,'handshake':0}]})
        self.assertEqual(result['devices'][0]['upload'],123)
        self.assertEqual(result['devices'][0]['download'],456)
        self.assertEqual(result['devices'][0]['slot'],2)
        self.assertFalse(result['devices'][1]['managed'])
        self.assertEqual(available_slot(result['devices']),3)
    def test_full_pool(self):
        with self.assertRaises(ValueError):available_slot([{'slot':i} for i in range(2,254)])
    def test_name_validation(self):
        self.assertEqual(validate_name('iphone-2'),'iphone-2')
        for name in ['../a',None,'A',False]:
            with self.assertRaises(ValueError):validate_name(name)



class ServiceOperations(unittest.TestCase):
    def setUp(self):
        import base64
        from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
        from cryptography.hazmat.primitives.serialization import Encoding,PrivateFormat,PublicFormat,NoEncryption
        from dashboard.service import VPNService
        self.temp=tempfile.TemporaryDirectory();self.root=Path(self.temp.name)
        self.service=VPNService(instance='i-test',account='123456789012',root=self.root)
        self.private=X25519PrivateKey.generate()
        self.private_text=base64.b64encode(self.private.private_bytes(Encoding.Raw,PrivateFormat.Raw,NoEncryption())).decode()
        self.public=base64.b64encode(self.private.public_key().public_bytes(Encoding.Raw,PublicFormat.Raw)).decode()
        self.raw={'active':True,'public_key':'SERVER','boot_id':'BOOT','uptime':10,'peers':[{'public_key':self.public,'name':'phone','allowed_ips':'10.66.66.2/32','rx':123,'tx':456,'handshake':0}]}
        self.state=parse_status(self.raw);self.state.update(ip='203.0.113.1')
    def tearDown(self):self.temp.cleanup()
    def config(self, name='phone', wrong=False):
        p=self.service.directory/f'{name}.conf'
        p.write_text(f'[Interface]\nPrivateKey = {self.private_text}\n\n[Peer]\nPublicKey = '+('WRONG' if wrong else 'SERVER')+'\nEndpoint = 203.0.113.1:51820\n')
        p.chmod(0o600)
        return p
    def test_status_verifies_target_maps_data_and_caches(self):
        import json
        def aws(*args):
            if args[0]=='sts':return {'Account':'123456789012'}
            if args[1]=='describe-instances':return {'Reservations':[{'Instances':[{'Tags':[{'Key':'Project','Value':'home-server-vpn'}],'State':{'Name':'running'},'PublicIpAddress':'203.0.113.1','InstanceType':'t3.micro'}]}]}
            return {'InstanceCreditSpecifications':[{'CpuCredits':'standard'}]}
        self.config()
        with patch.object(self.service,'aws',side_effect=aws) as calls,patch.object(self.service,'remote',return_value=json.dumps(self.raw)) as remote:
            state=self.service.status()
            self.assertTrue(state['devices'][0]['export'])
            self.assertEqual(state['credits'],'standard')
            self.assertEqual(self.service.status(),state)
            self.assertEqual(calls.call_count,3)
            self.assertNotIn(self.private_text,str(remote.call_args))
    def test_wrong_account_and_wrong_instance_rejected(self):
        with patch.object(self.service,'aws',return_value={'Account':'wrong'}):
            with self.assertRaises(RuntimeError):self.service.status()
        results=[{'Account':'123456789012'},{'Reservations':[{'Instances':[{'Tags':[],'State':{'Name':'running'}}]}]}]
        with patch.object(self.service,'aws',side_effect=results):
            with self.assertRaises(RuntimeError):self.service.status()
    def test_create_assigns_unused_slot_and_invokes_enrollment_without_shell(self):
        from types import SimpleNamespace
        with patch.object(self.service,'status',return_value=self.state),patch('dashboard.service.subprocess.run',return_value=SimpleNamespace(returncode=0)) as call:
            self.assertEqual(self.service.create('laptop'),{'name':'laptop'})
        command=call.call_args.args[0]
        self.assertIn('3',command)
        self.assertNotIn('shell',call.call_args.kwargs)
    def test_create_rejects_duplicate_exports_and_enrollment_errors(self):
        from types import SimpleNamespace
        with patch.object(self.service,'status',return_value=self.state):
            with self.assertRaises(ValueError):self.service.create('phone')
            self.config('old')
            with self.assertRaises(ValueError):self.service.create('old')
            with patch('dashboard.service.subprocess.run',return_value=SimpleNamespace(returncode=1)):
                with self.assertRaises(RuntimeError):self.service.create('new')
    def test_revoke_changes_only_requested_peer_and_validates(self):
        with patch.object(self.service,'status',return_value=self.state),patch.object(self.service,'remote') as remote:
            self.service.revoke('phone')
            self.assertEqual(remote.call_args.args[0],['/usr/local/sbin/vpn-client remove phone'])
            with self.assertRaises(ValueError):self.service.revoke('missing')
    def test_export_and_qr_stale_key_rejection(self):
        self.config()
        with patch.object(self.service,'status',return_value=self.state):
            self.assertIn(b'[Interface]',self.service.artifact('phone','conf'))
            self.assertTrue(self.service.artifact('phone','qr').startswith(b'\x89PNG'))
            with self.assertRaises(ValueError):self.service.artifact('missing','conf')
            self.config(wrong=True)
            with self.assertRaises(ValueError):self.service.artifact('phone','conf')
    def test_unsafe_files_and_symlinks_are_not_served(self):
        p=self.config();p.chmod(0o644)
        with self.assertRaises(ValueError):self.service._file('phone')
        p.unlink();p.symlink_to(self.root/'outside')
        self.assertIsNone(self.service._file('phone'))
    def test_transport_and_discovery(self):
        from dashboard.service import VPNService
        with patch('dashboard.service.transport.aws',return_value={'ok':True}) as aws,patch('dashboard.service.transport.command',return_value='ok') as remote:
            self.assertEqual(self.service.aws('x'),{'ok':True})
            self.assertEqual(self.service.remote(['x']),'ok')
        with patch('dashboard.service.subprocess.check_output',return_value='{"instance_id":{"value":"i-discovered"},"account_id":{"value":"123456789012"}}'):
            service=VPNService(root=self.root)
            self.assertEqual(service.instance,'i-discovered')
            self.assertEqual(service.account,'123456789012')

class RemoteAndStartup(unittest.TestCase):
    def test_remote_snapshot_contains_no_private_key(self):
        import io,json,runpy
        from types import SimpleNamespace
        config='[Interface]\nPrivateKey = DO_NOT_EXPOSE\n# BEGIN phone\n[Peer]\nPublicKey = PUBLIC\n# END phone\n'
        def text(path):
            if str(path)=='/etc/wireguard/wg0.conf':return config
            if str(path)=='/proc/uptime':return '20.0 100.0'
            return 'BOOT'
        original=Path.read_text
        data={'peers':'PUBLIC','transfer':'PUBLIC\t100\t200','latest-handshakes':'PUBLIC\t123','allowed-ips':'PUBLIC\t10.66.66.2/32','public-key':'SERVER'}
        with patch.object(Path,'read_text',side_effect=None,autospec=True) as read,patch('subprocess.check_output',side_effect=lambda args,**kw:data[args[-1]]),patch('subprocess.run',return_value=SimpleNamespace(returncode=0)),patch('sys.stdout',new_callable=io.StringIO) as out:
            read.side_effect=text
            runpy.run_path(str(Path(__file__).parents[1]/'dashboard/remote_status.py'))
        result=json.loads(out.getvalue())
        self.assertEqual(result['peers'][0]['name'],'phone')
        self.assertNotIn('DO_NOT_EXPOSE',out.getvalue())
    def test_cli_binds_only_loopback_and_closes(self):
        from dashboard.app import main
        from unittest.mock import MagicMock
        server=MagicMock();server.server_port=8765;server.serve_forever.side_effect=KeyboardInterrupt
        with patch('sys.argv',['dashboard']),patch('dashboard.app.VPNService'),patch('dashboard.app.make_server',return_value=server) as factory,patch('builtins.print'):
            main()
        self.assertEqual(factory.call_args.args[0],'127.0.0.1')
        server.server_close.assert_called_once()

if __name__=='__main__':unittest.main()
