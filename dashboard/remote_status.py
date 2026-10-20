"""Executed through SSM. Emit public peer metadata and counters only."""
import json
from pathlib import Path
import subprocess


def output(*args):
    return subprocess.check_output(args, text=True).strip()


names = {}
current = None
for line in Path('/etc/wireguard/wg0.conf').read_text().splitlines():
    if line.startswith('# BEGIN '):
        current = line[8:].strip()
    elif line.startswith('# END '):
        current = None
    elif current and line.startswith('PublicKey = '):
        names[line.split(' = ', 1)[1]] = current
peers = output('wg', 'show', 'wg0', 'peers').splitlines()
transfers = {s[0]: s[1:] for line in output('wg', 'show', 'wg0', 'transfer').splitlines() if (s := line.split())}
handshakes = dict(line.split() for line in output('wg', 'show', 'wg0', 'latest-handshakes').splitlines())
addresses = {s[0]: ' '.join(s[1:]) for line in output('wg', 'show', 'wg0', 'allowed-ips').splitlines() if (s := line.split())}
print(json.dumps({
    'active': subprocess.run(['systemctl', 'is-active', '--quiet', 'wg-quick@wg0']).returncode == 0,
    'public_key': output('wg', 'show', 'wg0', 'public-key'),
    'boot_id': Path('/proc/sys/kernel/random/boot_id').read_text().strip(),
    'uptime': float(Path('/proc/uptime').read_text().split()[0]),
    'peers': [{'public_key': p, 'name': names.get(p), 'allowed_ips': addresses[p],
               'rx': int(transfers[p][0]), 'tx': int(transfers[p][1]), 'handshake': int(handshakes[p])} for p in peers]
}))
