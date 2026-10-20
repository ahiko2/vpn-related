#!/usr/bin/env python3
"""Generate a protected client file locally; enroll only its public key over SSM.
Requires Python cryptography, AWS CLI and permission for SSM Run Command.
"""
import argparse
import base64
import ipaddress
import json
import os
from pathlib import Path
import re
import subprocess
import time
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PrivateFormat, PublicFormat, NoEncryption


def aws(profile, region, *args):
    return json.loads(subprocess.check_output(['aws', '--profile', profile, '--region', region, *args, '--output', 'json'], text=True))


def command(profile, region, instance, commands):
    result = aws(profile, region, 'ssm', 'send-command', '--instance-ids', instance,
                 '--document-name', 'AWS-RunShellScript', '--comment', 'Home VPN public-key enrollment',
                 '--parameters', json.dumps({'commands': ['set -eu', *commands]}))
    command_id = result['Command']['CommandId']
    for _ in range(150):
        time.sleep(2)
        try:
            result = aws(profile, region, 'ssm', 'get-command-invocation', '--command-id', command_id, '--instance-id', instance)
        except subprocess.CalledProcessError:
            continue
        if result['Status'] == 'Success':
            return result['StandardOutputContent'].strip()
        if result['Status'] in ('Failed', 'Cancelled', 'TimedOut'):
            raise RuntimeError(f'SSM command {command_id} failed; inspect its public-only enrollment diagnostics')
    raise RuntimeError(f'SSM command {command_id} did not complete within five minutes')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--profile', default='terraform-admin')
    parser.add_argument('--region', default='ap-northeast-1')
    parser.add_argument('--account', required=True, help='Expected 12-digit AWS account ID')
    parser.add_argument('--instance', required=True)
    parser.add_argument('--endpoint', required=True, type=ipaddress.IPv4Address)
    parser.add_argument('--name', required=True)
    parser.add_argument('--slot', type=int, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    if not re.fullmatch(r'[a-z][a-z0-9-]{0,31}', args.name) or not 2 <= args.slot <= 253:
        parser.error('Use a lowercase device name and unique slot 2..253')
    identity = aws(args.profile, args.region, 'sts', 'get-caller-identity')
    if identity['Account'] != args.account:
        parser.error('AWS account mismatch')
    # Ensure this instance and endpoint belong to this deployment before enrolling.
    reservation = aws(args.profile, args.region, 'ec2', 'describe-instances', '--instance-ids', args.instance)
    instance = reservation['Reservations'][0]['Instances'][0]
    tags = {t['Key']: t['Value'] for t in instance.get('Tags', [])}
    if tags.get('Project') != 'home-server-vpn' or instance.get('PublicIpAddress') != str(args.endpoint):
        parser.error('Instance tag or public IP does not match the requested VPN')
    server_public = command(args.profile, args.region, args.instance, [
        'systemctl is-active --quiet wg-quick@wg0', 'cat /etc/wireguard/server.pub'])
    if len(base64.b64decode(server_public, validate=True)) != 32:
        parser.error('Invalid server public key')
    os.umask(0o077)
    args.output.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    if args.output.exists():
        if args.output.is_symlink() or args.output.stat().st_mode & 0o077:
            parser.error('Existing output must be a private regular file with mode 600')
        config = args.output.read_text()
        expected = [f'Address = 10.66.66.{args.slot}/32, fd42:66:66::{args.slot:x}/128',
                    f'PublicKey = {server_public}', f'Endpoint = {args.endpoint}:51820']
        if not all(line in config.splitlines() for line in expected):
            parser.error('Existing config differs from this server/device; choose another output or revoke/rotate explicitly')
        match = re.search(r'^PrivateKey = (.+)$', config, re.M)
        private = X25519PrivateKey.from_private_bytes(base64.b64decode(match.group(1), validate=True))
    else:
        private = X25519PrivateKey.generate()
        private_text = base64.b64encode(private.private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption())).decode()
        config = f'''[Interface]
PrivateKey = {private_text}
Address = 10.66.66.{args.slot}/32, fd42:66:66::{args.slot:x}/128
DNS = 1.1.1.1
MTU = 1280

[Peer]
PublicKey = {server_public}
Endpoint = {args.endpoint}:51820
AllowedIPs = 0.0.0.0/0, ::/0
PersistentKeepalive = 25
'''
        with os.fdopen(os.open(args.output, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600), 'w') as output:
            output.write(config)
    public = base64.b64encode(private.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)).decode()
    # The remote script contains public material only; no private key is sent to AWS.
    registration = f'''
import fcntl, pathlib, subprocess
root = pathlib.Path('/etc/wireguard')
name, public, slot = {args.name!r}, {public!r}, {args.slot!r}
with (root / '.clients.lock').open('w') as lock:
    fcntl.flock(lock, fcntl.LOCK_EX)
    path = root / 'wg0.conf'
    config = path.read_text()
    peer = '\\n# BEGIN ' + name + '\\n[Peer]\\nPublicKey = ' + public + '\\nAllowedIPs = 10.66.66.' + str(slot) + '/32, fd42:66:66::' + format(slot, 'x') + '/128\\n# END ' + name + '\\n'
    if '# BEGIN ' + name + '\\n' in config:
        if peer not in config:
            raise RuntimeError('Name belongs to another key or address; revoke first')
    else:
        if 'AllowedIPs = 10.66.66.' + str(slot) + '/32,' in config or public in config:
            raise RuntimeError('Address/key already registered')
        temporary = root / 'wg0.conf.new'
        temporary.touch(mode=0o600, exist_ok=True)
        temporary.chmod(0o600)
        temporary.write_text(config + peer)
        temporary.replace(path)
    subprocess.run(['wg', 'set', 'wg0', 'peer', public, 'allowed-ips', '10.66.66.' + str(slot) + '/32,fd42:66:66::' + format(slot, 'x') + '/128'], check=True)
    assert public in subprocess.check_output(['wg', 'show', 'wg0', 'peers'], text=True).splitlines()
print('Public key enrolled in persistent and live configuration')
'''
    encoded = base64.b64encode(registration.encode()).decode()
    command(args.profile, args.region, args.instance, [f"printf '%s' '{encoded}' | base64 --decode | python3"])
    print(f'Ready to import: {args.output.resolve()} (mode 600). Private key was generated locally and was not sent to SSM.')


if __name__ == '__main__':
    main()
