#!/usr/bin/env python3
"""Root-only enrollment on the VPN host. Private keys never enter Terraform."""
import argparse
import fcntl
import ipaddress
import os
from pathlib import Path
import re
import subprocess
import sys

ROOT = Path('/etc/wireguard')


def wg(*args, input=None):
    return subprocess.check_output(['wg', *args], input=input, text=True).strip()


def validate_name(value):
    if not re.fullmatch(r'[a-z][a-z0-9-]{0,31}', value):
        raise argparse.ArgumentTypeError('Use 1-32 lowercase letters, digits or hyphens, starting with a letter')
    return value


def validate_slot(value):
    number = int(value)
    if not 2 <= number <= 254:
        raise argparse.ArgumentTypeError('Device number must be 2..254')
    return number


def render_client(private, public, slot, endpoint):
    return f'''[Interface]
PrivateKey = {private}
Address = 10.66.66.{slot}/32, fd42:66:66::{slot:x}/128
DNS = 1.1.1.1
MTU = 1280

[Peer]
PublicKey = {public}
Endpoint = {endpoint}:51820
AllowedIPs = 0.0.0.0/0, ::/0
PersistentKeepalive = 25
'''


def render_peer(name, public, slot):
    return f'''\n# BEGIN {name}
[Peer]
PublicKey = {public}
AllowedIPs = 10.66.66.{slot}/32, fd42:66:66::{slot:x}/128
# END {name}
'''


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    actions = parser.add_subparsers(dest='action', required=True)
    add = actions.add_parser('add')
    add.add_argument('name', type=validate_name)
    add.add_argument('slot', type=validate_slot)
    add.add_argument('endpoint', type=ipaddress.IPv4Address, help='Terraform public_ip output')
    remove = actions.add_parser('remove')
    remove.add_argument('name', type=validate_name)
    args = parser.parse_args()
    if os.geteuid() != 0:
        parser.error('Run with sudo on the VPN server')
    os.umask(0o077)
    with (ROOT / '.clients.lock').open('w') as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        config_path = ROOT / 'wg0.conf'
        config = config_path.read_text()
        client_path = ROOT / 'clients' / f'{args.name}.conf'
        marker = f'# BEGIN {args.name}\n'
        if args.action == 'add':
            if marker in config or client_path.exists():
                parser.error('Name already exists; remove it first to rotate its key')
            if f'AllowedIPs = 10.66.66.{args.slot}/32,' in config:
                parser.error('Device number already in use')
            private = wg('genkey')
            public = wg('pubkey', input=private + '\n')
            client = render_client(private, (ROOT / 'server.pub').read_text().strip(), args.slot, args.endpoint)
            config += render_peer(args.name, public, args.slot)
            # Exclusive creation prevents accidental replacement of a stored credential.
            with client_path.open('x') as output:
                output.write(client)
        else:
            if marker not in config:
                parser.error('Unknown device')
            config = re.sub(r'\n# BEGIN ' + re.escape(args.name) + r'\n.*?# END ' + re.escape(args.name) + r'\n', '', config, flags=re.S)
        temporary = ROOT / 'wg0.conf.new'
        temporary.write_text(config)
        temporary.replace(config_path)
        # Apply without restarting the interface or dropping other device sessions.
        stripped = subprocess.check_output(['wg-quick', 'strip', 'wg0'], text=True)
        with (ROOT / '.sync.conf').open('w') as sync:
            sync.write(stripped)
        try:
            subprocess.run(['wg', 'syncconf', 'wg0', str(ROOT / '.sync.conf')], check=True)
        finally:
            (ROOT / '.sync.conf').unlink(missing_ok=True)
        if args.action == 'remove':
            client_path.unlink(missing_ok=True)
            print('Device revoked in persistent and live configuration.')
        else:
            print(f'Created {client_path}. Display securely with: sudo cat {client_path}')


if __name__ == '__main__':
    try:
        main()
    except (OSError, subprocess.CalledProcessError) as error:
        # Do not print command input or any key-bearing configuration.
        sys.exit(f'Enrollment failed ({type(error).__name__}); inspect server configuration before retrying.')
