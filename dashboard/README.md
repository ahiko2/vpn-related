# Home VPN control room

A local administrator dashboard for the existing Terraform WireGuard server. It manages **devices**, not separate AWS accounts or website logins. Give each person's phone/computer its own device name and export; never share one profile between concurrent devices.

From the project root:

```sh
python3 -m venv .venv
.venv/bin/pip install -r dashboard/requirements.txt
.venv/bin/python -m dashboard.app
```

Open the **private URL printed in the terminal**, including its `#...` fragment. The address is bound to `127.0.0.1:8765`; only browsers on this computer can reach it. It is not hosted on EC2 or publicly accessible. The token changes on every launch and is stored only for that browser tab's session. If another dashboard occupies the port, use `--port 8766`. Ctrl+C stops it. Keep the terminal link private; anyone using it locally can administer devices and download their keys.

The dashboard reads the instance ID and account guard from `terraform/server` outputs. After deployment, those outputs must be available; no deployment state is included in Git. You can also supply `--instance INSTANCE_ID --account ACCOUNT_ID --profile PROFILE --region REGION` explicitly. AWS requests use the configured `terraform-admin` profile and guard the account ID supplied in Terraform outputs (or explicitly with `--account`). The AWS CLI and a valid login must be available. No AWS credentials are sent to the browser. This process is a trusted local admin tool, not a public web service; do not proxy or expose it to the internet. Nothing changes instance type, credit mode, Terraform infrastructure or AWS budgets.

## Available controls

- **Refresh** retrieves public WireGuard metadata and byte counters through SSM, checks the AWS identity, and displays instance type and current CPU credit mode. Ten-second cache; no automatic polling. A request can take several seconds, or longer when SSM is unavailable.
- **Add device** assigns the first unused address from 2..253 and uses the existing local enrollment CLI. A private key is generated locally; only the public key goes to SSM. New exports are mode 600 inside ignored `.dashboard/clients/`. Names are lowercase letters, numbers and hyphens. A name with a pre-existing local export is reserved; use a new name to generate a new key.
- **Config / QR** checks the local private key's public key against the live peer, server public key and endpoint before serving it. Existing root files `home-vpn-windows.conf` and `home-vpn-iphone.conf` are recognized without changing them. Missing local exports cannot be reconstructed from the server's public key. Downloaded files and QR images are credentials: keep them private.
- **Revoke** removes only the selected device from persistent and live WireGuard configuration through the existing server helper. Other peers remain connected. Local exports/downloads remain on disk but no longer authenticate. The UI asks for confirmation before revocation. Devices without a recognized persistent name are shown as unmanaged and cannot be revoked here.

## What usage means

Upload is bytes **received by the server from the device**; download is bytes **sent by the server to the device**. Totals include current peers only and reset when the interface or peer restarts. Revoked peers no longer contribute. These are not monthly history, billed AWS internet transfer, or cost estimates. For billing use AWS Billing/Cost Explorer separately. No CloudWatch publishing, monitoring service or extra EC2 instance is created. Normal AWS API/SSM usage follows your account's pricing.

A recent handshake indicates activity, not a continuous connection session. An idle device may still have VPN enabled. The dashboard does not activate clients or change your local network routes.

## Recovery and limitations

If an operation fails, check AWS CLI login, SSM access and server readiness from the root README. A partial enrollment may leave a private file on disk or a persistent peer before the live sync succeeds; inspect the enrollment CLI before retrying. Do not infer successful revocation from a failed request. The UI never automatically destroys or rebuilds infrastructure to recover.

The dashboard's data directory, downloaded profile copies and screenshots are ignored by Git. The HTTP API requires a per-launch bearer token, checks Host/Origin, disables browser caching, and rejects remote origins. Private keys are never returned by the status API, printed in server logs or submitted to remote QR services. This does not replace operating-system account security on the machine running it.

## Checks

```sh
.venv/bin/pip install coverage playwright
.venv/bin/python -m coverage run --branch --source=dashboard -m unittest discover -s tests -p test_dashboard.py
.venv/bin/python -m coverage report --fail-under=80
.venv/bin/python -m unittest discover -s tests -v
```

The live browser check in `tests/e2e_dashboard.py` requires Google Chrome and the terminal's private dashboard URL as its argument. It temporarily enrolls its own `ui-check-...` device, exercises config download and QR display, revokes it, verifies Windows/iPhone remain, and removes its test export. Its `finally` block attempts cleanup after a failure. Do not run it against an unrelated deployment.
