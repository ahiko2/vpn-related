"""Offline checks of enrollment, revocation, routes, and credential permissions."""
import importlib.util
import ipaddress
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

spec = importlib.util.spec_from_file_location('vpn_client', Path(__file__).parents[1] / 'scripts/vpn-client.py')
vpn = importlib.util.module_from_spec(spec)
spec.loader.exec_module(vpn)


class Clients(unittest.TestCase):
    def test_full_tunnel_includes_ipv6_and_unique_addresses(self):
        text = vpn.render_client('PRIVATE', 'PUBLIC', 254, ipaddress.IPv4Address('203.0.113.1'))
        self.assertIn('AllowedIPs = 0.0.0.0/0, ::/0', text)
        self.assertIn('10.66.66.254/32, fd42:66:66::fe/128', text)
        self.assertIn('Endpoint = 203.0.113.1:51820', text)
        self.assertIn('DNS = 1.1.1.1', text)

    def test_names_prevent_path_and_config_injection(self):
        for value in ['../secret', 'phone\n[Peer]', '', '-x', 'a' * 33]:
            with self.subTest(value=value), self.assertRaises(Exception):
                vpn.validate_name(value)

    def test_reserved_addresses_rejected(self):
        for value in ['0', '1', '255', '-1']:
            with self.subTest(value=value), self.assertRaises(Exception):
                vpn.validate_slot(value)

    def test_enroll_conflict_and_revoke_preserves_other_peers(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / 'clients').mkdir()
            (root / 'server.pub').write_text('SERVER_PUBLIC\n')
            original = '[Interface]\nPrivateKey = SERVER_PRIVATE\n'
            (root / 'wg0.conf').write_text(original)
            with patch.object(vpn, 'ROOT', root), patch.object(vpn.os, 'geteuid', return_value=0), patch.object(vpn, 'wg', side_effect=lambda *a, **k: 'CLIENT_PRIVATE' if a[0] == 'genkey' else 'CLIENT_PUBLIC'), patch.object(vpn.subprocess, 'check_output', return_value='stripped'), patch.object(vpn.subprocess, 'run') as apply:
                def run(*arguments):
                    with patch('sys.argv', ['vpn-client', *arguments]):
                        vpn.main()
                run('add', 'phone', '2', '203.0.113.1')
                self.assertEqual((root / 'clients/phone.conf').stat().st_mode & 0o777, 0o600)
                self.assertNotIn('CLIENT_PRIVATE', (root / 'wg0.conf').read_text())
                self.assertIn('CLIENT_PUBLIC', (root / 'wg0.conf').read_text())
                with self.assertRaises(SystemExit):
                    run('add', 'laptop', '2', '203.0.113.1')
                run('add', 'laptop', '3', '203.0.113.1')
                run('remove', 'phone')
                self.assertFalse((root / 'clients/phone.conf').exists())
                self.assertIn('# BEGIN laptop', (root / 'wg0.conf').read_text())
                self.assertNotIn('# BEGIN phone', (root / 'wg0.conf').read_text())
                self.assertFalse((root / '.sync.conf').exists())
                self.assertEqual(apply.call_count, 3)

    def test_non_root_cannot_enroll(self):
        with patch.object(vpn.os, 'geteuid', return_value=1000), patch('sys.argv', ['vpn-client', 'add', 'phone', '2', '203.0.113.1']):
            with self.assertRaises(SystemExit):
                vpn.main()


if __name__ == '__main__':
    unittest.main()
