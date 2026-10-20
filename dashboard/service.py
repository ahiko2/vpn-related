"""AWS transport, local credential exports, and device lifecycle operations."""
import base64
import importlib.util
import io
import json
from pathlib import Path
import re
import subprocess
import sys
import threading
import time

import qrcode
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('vpn_enrollment', ROOT / 'scripts/create-client.py')
transport = importlib.util.module_from_spec(spec)
spec.loader.exec_module(transport)


def validate_name(value):
    if not isinstance(value, str) or not re.fullmatch(r'[a-z][a-z0-9-]{0,31}', value):
        raise ValueError('Use 1–32 lowercase letters, digits or hyphens, starting with a letter.')
    return value


def available_slot(devices):
    used = {d['slot'] for d in devices}
    for slot in range(2, 254):
        if slot not in used:
            return slot
    raise ValueError('All device addresses are in use.')


def parse_status(raw):
    devices = []
    for peer in raw['peers']:
        match = re.search(r'\b10\.66\.66\.(\d+)/32\b', peer['allowed_ips'])
        name = peer.get('name')
        managed = isinstance(name, str) and bool(re.fullmatch(r'[a-z][a-z0-9-]{0,31}', name))
        devices.append({'name': name if managed else 'Unmanaged device', 'managed': managed,
                        'slot': int(match[1]) if match else None, 'public_key': peer['public_key'],
                        'upload': peer['rx'], 'download': peer['tx'], 'handshake': peer['handshake']})
    return {**{k: raw[k] for k in ('active', 'public_key', 'boot_id', 'uptime')}, 'devices': devices}


class VPNService:
    def __init__(self, instance=None, profile='terraform-admin', region='ap-northeast-1', account=None, root=ROOT):
        self.root, self.profile, self.region, self.account = Path(root), profile, region, account
        if instance is None or account is None:
            outputs = json.loads(subprocess.check_output(['terraform', f'-chdir={self.root / "terraform/server"}', 'output', '-json'], text=True))
            instance = instance or outputs['instance_id']['value']
            account = account or outputs['account_id']['value']
        self.account = account
        self.instance = instance
        self.directory = self.root / '.dashboard/clients'
        self.directory.mkdir(parents=True, exist_ok=True, mode=0o700)
        self.lock = threading.RLock()
        self.cached = None
        self.cached_at = 0

    def aws(self, *args):
        return transport.aws(self.profile, self.region, *args)

    def remote(self, commands):
        return transport.command(self.profile, self.region, self.instance, commands)

    def status(self, force=False):
        with self.lock:
            if not force and self.cached and time.time() - self.cached_at < 10:
                return self.cached
            identity = self.aws('sts', 'get-caller-identity')
            if identity['Account'] != self.account:
                raise RuntimeError('Unexpected AWS account')
            instance = self.aws('ec2', 'describe-instances', '--instance-ids', self.instance)['Reservations'][0]['Instances'][0]
            tags = {t['Key']: t['Value'] for t in instance.get('Tags', [])}
            if tags.get('Project') != 'home-server-vpn' or instance['State']['Name'] != 'running':
                raise RuntimeError('Target is not the running VPN instance')
            credit = self.aws('ec2', 'describe-instance-credit-specifications', '--instance-ids', self.instance)['InstanceCreditSpecifications'][0]['CpuCredits']
            encoded = base64.b64encode((ROOT / 'dashboard/remote_status.py').read_bytes()).decode()
            raw = json.loads(self.remote([f"printf '%s' '{encoded}' | base64 --decode | python3"]))
            result = parse_status(raw)
            result.update(ip=instance['PublicIpAddress'], type=instance['InstanceType'], credits=credit, checked_at=time.time(), instance=self.instance)
            for device in result['devices']:
                device['export'] = bool(device['managed'] and self._file(device['name']))
            self.cached, self.cached_at = result, time.time()
            return result

    def _file(self, name):
        validate_name(name)
        for p in (self.directory / f'{name}.conf', self.root / f'home-vpn-{name}.conf'):
            if p.is_file() and not p.is_symlink():
                if p.stat().st_mode & 0o077:
                    raise ValueError('A configuration file has unsafe permissions. Set its permissions to 600.')
                return p
        return None

    def create(self, name):
        validate_name(name)
        with self.lock:
            state = self.status(force=True)
            if any(d['name'] == name for d in state['devices']):
                raise ValueError('A device with that name already exists.')
            # Never silently reactivate an old exported credential after revocation.
            if self._file(name):
                raise ValueError('That name already has an export. Choose a new name to create a new key.')
            slot = available_slot(state['devices'])
            path = self.directory / f'{name}.conf'
            result = subprocess.run([sys.executable, str(ROOT / 'scripts/create-client.py'), '--profile', self.profile,
                                     '--region', self.region, '--account', self.account, '--instance', self.instance,
                                     '--endpoint', state['ip'], '--name', name, '--slot', str(slot), '--output', str(path)],
                                    capture_output=True, text=True, timeout=330)
            self.cached = None
            if result.returncode:
                raise RuntimeError('Enrollment failed; a private export may remain on disk. Inspect the CLI before retrying.')
            return {'name': name}

    def revoke(self, name):
        validate_name(name)
        with self.lock:
            state = self.status(force=True)
            if not any(d['name'] == name and d['managed'] for d in state['devices']):
                raise ValueError('No managed device with that name exists.')
            self.remote([f'/usr/local/sbin/vpn-client remove {name}'])
            self.cached = None
            return {'name': name}

    def artifact(self, name, kind):
        validate_name(name)
        with self.lock:
            state = self.status(force=True)
            peer = next((d for d in state['devices'] if d['managed'] and d['name'] == name), None)
            path = self._file(name)
            if not peer or not path:
                raise ValueError('No active device with a local export was found.')
            data = path.read_bytes()
            text = data.decode('ascii')
            fields = dict(line.split(' = ', 1) for line in text.splitlines() if ' = ' in line)
            private = X25519PrivateKey.from_private_bytes(base64.b64decode(fields['PrivateKey'], validate=True))
            public = base64.b64encode(private.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)).decode()
            if public != peer['public_key'] or fields['PublicKey'] != state['public_key'] or fields['Endpoint'] != f"{state['ip']}:51820":
                raise ValueError('This export is stale or does not match the server. Do not import it.')
            if kind == 'conf':
                return data
            qr = qrcode.QRCode(error_correction=qrcode.constants.ERROR_CORRECT_M, box_size=8, border=4)
            qr.add_data(data, optimize=0)
            qr.make(fit=True)
            buffer = io.BytesIO()
            qr.make_image(fill_color='black', back_color='white').save(buffer, format='PNG')
            return buffer.getvalue()
