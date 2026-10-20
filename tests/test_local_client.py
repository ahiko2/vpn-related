import base64
import importlib.util
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

spec = importlib.util.spec_from_file_location('local_client', Path(__file__).parents[1] / 'scripts/create-client.py')
client = importlib.util.module_from_spec(spec)
spec.loader.exec_module(client)


class LocalClient(unittest.TestCase):
    def test_local_secret_never_sent_to_ssm_and_resume_reuses_it(self):
        server = base64.b64encode(X25519PrivateKey.generate().public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)).decode()
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / 'windows.conf'
            def aws(profile, region, *args):
                if args[0] == 'sts':
                    return {'Account': '123456789012'}
                return {'Reservations': [{'Instances': [{'Tags': [{'Key': 'Project', 'Value': 'home-server-vpn'}], 'PublicIpAddress': '203.0.113.1'}]}]}
            argv = ['create-client', '--account', '123456789012', '--instance', 'i-test', '--endpoint', '203.0.113.1', '--name', 'windows', '--slot', '2', '--output', str(output)]
            with patch.object(client, 'aws', side_effect=aws), patch.object(client, 'command', side_effect=[server, 'enrolled', server, 'enrolled']) as remote, patch('sys.argv', argv):
                client.main()
                original = output.read_text()
                client.main()
                self.assertEqual(output.read_text(), original)
                self.assertEqual(output.stat().st_mode & 0o777, 0o600)
                private = next(line.split(' = ')[1] for line in original.splitlines() if line.startswith('PrivateKey'))
                for call in remote.call_args_list:
                    self.assertNotIn(private, str(call))
                    for command in call.args[3]:
                        if 'base64 --decode' in command:
                            encoded = command.split("'")[3]
                            decoded = base64.b64decode(encoded).decode()
                            self.assertNotIn(private, decoded)
                            compile(decoded, '<remote-public-enrollment>', 'exec')
                self.assertIn('AllowedIPs = 0.0.0.0/0, ::/0', original)

    def test_account_must_be_explicit(self):
        with patch.object(client, 'aws', side_effect=AssertionError('AWS must not be called without an explicit account')), patch('sys.argv', ['create-client', '--instance', 'i-test', '--endpoint', '203.0.113.1', '--name', 'phone', '--slot', '2', '--output', '/tmp/unused.conf']):
            with self.assertRaises(SystemExit):
                client.main()

    def test_account_mismatch_prevents_file_creation(self):
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / 'client.conf'
            with patch.object(client, 'aws', return_value={'Account': '999999999999'}), patch('sys.argv', ['create-client', '--account', '123456789012', '--instance', 'i-test', '--endpoint', '203.0.113.1', '--name', 'windows', '--slot', '2', '--output', str(output)]):
                with self.assertRaises(SystemExit):
                    client.main()
            self.assertFalse(output.exists())


if __name__ == '__main__':
    unittest.main()
