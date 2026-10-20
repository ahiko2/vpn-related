# Home VPN: WireGuard + Terraform + local dashboard

A reusable personal VPN on AWS, with a local web interface for managing devices and checking traffic.

```text
Phone / laptop → WireGuard on EC2 in Tokyo → Elastic IP → internet
                      ↑
             AWS Systems Manager
                      ↑
             Local admin dashboard
```

The source includes infrastructure, first-boot configuration, client enrollment, QR exports, device revocation, traffic counters, and tests. Credentials, client profiles, QR images, deployment state and local deployment history are excluded from Git.

## What is included

| Folder | Purpose |
| --- | --- |
| `terraform/ip` | Independently managed Elastic IP allocation |
| `terraform/server` | Dedicated VPC, subnet, internet route, security group, EC2, encrypted disk, SSM role and EIP association |
| `dashboard` | Local-only admin UI for devices, downloads, QR codes and usage |
| `scripts/create-client.py` | Local private-key generation and public-key-only enrollment over SSM |
| `scripts/vpn-client.py` | Root-only server enrollment/revocation helper, installed by bootstrap |
| `scripts/smoke-test.sh` | Temporary isolated WireGuard client for server-side routing/DNS/isolation checks |
| `tests` | Offline unit/integration tests and an explicitly invoked live browser test |

Defaults: Tokyo (`ap-northeast-1`), Ubuntu 24.04, `t3.micro` x86_64, 8 GiB encrypted gp3, UDP 51820, and **standard CPU credits**. Unlimited credits are disabled. Supported T4g alternatives use ARM images; an AMI architecture check prevents mixing ARM images with T3. There is no NAT Gateway, inbound SSH rule or public admin web port.

## Prerequisites and account guard

Install Terraform >=1.7 and <2, AWS CLI, Python 3.11+, and the AWS Session Manager plugin. The provider lock files pin the downloaded AWS provider version. Configure a named AWS profile called `terraform-admin` with permission to manage this deployment's EC2/VPC/EBS/EIP/IAM resources and pass its instance role. The instance itself receives only `AmazonSSMManagedInstanceCore` for management; it does not receive your Terraform credentials.

Verify the account before deploying:

```sh
aws --profile terraform-admin --region ap-northeast-1 sts get-caller-identity
cp terraform/ip/terraform.tfvars.example terraform/ip/terraform.tfvars
cp terraform/server/terraform.tfvars.example terraform/server/terraform.tfvars
```

Edit **both** copied files: replace example `expected_account_id = "123456789012"` with your actual verified account ID. Both stacks must use the same account and region. The account ID is required; providers reject a caller from another account. The dashboard reads the configured account from Terraform outputs and independently checks the caller. Never put access keys in the source or `.tfvars` files.

## Create the VPN

These commands create billable AWS resources. Review each saved plan before applying:

```sh
terraform -chdir=terraform/ip init
terraform -chdir=terraform/ip plan -out=ip.tfplan
terraform -chdir=terraform/ip apply ip.tfplan

terraform -chdir=terraform/server init
terraform -chdir=terraform/server plan -out=server.tfplan
terraform -chdir=terraform/server apply server.tfplan
terraform -chdir=terraform/server output
```

The server stack reads `../ip/terraform.tfstate`. Preserve this layout and back up local state securely. State, backups, plans, `.terraform/` and real `.tfvars` files are ignored by Git; do not delete state as a substitute for destruction. For shared operation, migrate the stacks to separate encrypted, locked remote backends before collaborating.

The default image lookup selects the latest Canonical Ubuntu 24.04 image matching the instance architecture. Set `ami_id` in the server's ignored `.tfvars` to pin a reviewed regional image. A newer image, bootstrap/helper changes, or a family change can replace the instance: inspect every plan. AWS may lack capacity in an AZ; `availability_zone` can select another AZ. The default WireGuard source CIDR is `0.0.0.0/0` so roaming phones can reach the authenticated UDP service. Restrict it if clients have stable source networks.

EC2 creation completing does not prove first boot is finished. Bootstrap retries package installation while the EIP is attached, configures forwarding and nftables NAT/isolation, generates the server key on disk, enables WireGuard, and enables unattended security updates. Keep standard credits even if initial setup takes longer.

Use the instance ID from Terraform outputs:

```sh
aws --profile terraform-admin --region ap-northeast-1 ssm start-session --target INSTANCE_ID
# Inside the instance:
sudo cloud-init status --wait
sudo systemctl is-active nftables wg-quick@wg0
sudo wg show wg0
```

If first boot fails, inspect `/var/log/cloud-init-output.log` and EC2 health, route, EIP, SSM role and agent status. Terraform apply does not automatically replay a failed cloud-init script. Correct the cause and repair deliberately through SSM or replace the instance. Review `/var/run/reboot-required` after kernel updates and schedule a reboot; automatic reboots are not configured.

## Start the local dashboard

On macOS/Linux, from the repository root:

```sh
python3 -m venv .venv
.venv/bin/pip install -r dashboard/requirements.txt
.venv/bin/python -m dashboard.app
```

On Windows PowerShell, use `py -m venv .venv`, then `.venv\Scripts\python -m pip install -r dashboard/requirements.txt` and `.venv\Scripts\python -m dashboard.app`.

Open the full private URL printed by the process, including its `#...` access token. Keep the terminal running; Ctrl+C stops the UI. The token changes on each launch. `--port 8766` selects another port. The dashboard binds **only to `127.0.0.1` on the computer running it**. A browser on a different computer cannot use that loopback address; enabling the VPN does not change this. Chrome and Codex have separate tab sessions, so each needs the complete private link. `ERR_CONNECTION_REFUSED` means no dashboard is listening at that address.

The dashboard uses your local AWS CLI credentials; they are not sent to the browser. Keep its private link secret and do not expose or proxy the dashboard publicly. It supports:

- Adding a device with a unique name and automatically assigned address.
- Downloading its configuration or displaying/downloading a locally generated QR code.
- Checking server status, CPU credit mode, last handshakes, upload/download and totals.
- Revoking only the selected device, after a confirmation.

Private keys are generated locally; only public keys are enrolled through SSM. New exports are stored in ignored `.dashboard/clients/` with mode 600. Existing root files named `home-vpn-NAME.conf` are recognized if their permissions and keys match. Downloads reject stale files after a server identity or endpoint change. Use one profile per device, including separate profiles for a person's phone and laptop. Revocation removes server trust; old downloaded/local exports remain on disk but cease to authenticate. To create a fresh key after revocation, choose a new name rather than reusing an existing local export.

See [dashboard/README.md](dashboard/README.md) for its security checks, recovery and live browser test.

## Traffic usage and costs

**The UI does not report monthly AWS billing usage.** Upload means bytes received by the server from a device; download means bytes sent by the server to that device. WireGuard counters reset when the interface or peer restarts. Totals include currently enrolled peers only and lose a revoked peer's contribution. Refresh is manual, with a ten-second cache; there is no automatic polling or paid monitoring service provisioned. A recent handshake indicates activity, not a continuous session; an idle device may still have its tunnel enabled.

EC2, gp3, public IPv4, API usage and internet data transfer follow AWS pricing and account allowances. **A retained Elastic IP continues billing even when the server is destroyed or stopped.** Standard credits prevent ongoing Unlimited surplus CPU charges by throttling sustained CPU usage. The code does not create budgets or impose a total spending cap. Use AWS Billing separately for actual charges and monthly transfer.

## Create a profile through the CLI

If the dashboard dependencies are installed, its Python environment can also run enrollment:

```sh
.venv/bin/python scripts/create-client.py \
  --profile terraform-admin --region ap-northeast-1 \
  --account YOUR_ACCOUNT_ID --instance INSTANCE_ID --endpoint ELASTIC_IP \
  --name iphone --slot 3 --output /private/path/home-vpn-iphone.conf
```

Use a unique lowercase name and slot 2..253 for each device; slot 254 is reserved for the smoke test. The script verifies the account, instance project tag/IP and server public key, writes an exclusive mode-600 file, and enrolls its public key in persistent and live WireGuard configuration. Rerunning with the same file reconciles enrollment using that file's existing key. A failed operation can leave a partial local export or persistent registration; inspect the reported SSM command and CLI state before retrying.

Only Python `cryptography` is required for the standalone CLI (`scripts/requirements.txt`). The server also has `sudo vpn-client add NAME SLOT ELASTIC_IP`, but that alternative generates client keys on the server. Prefer local generation. Never retrieve private profiles through SSM Run Command: AWS retains command output. Interactive Session Manager logging, if enabled, can also record secrets displayed there.

## Import and connection behavior

- **Windows:** WireGuard → Add Tunnel → Import tunnel(s) from file → Activate. With a single peer and both `/0` routes, retain Block untunneled traffic. Deactivating the tunnel removes its tunnel-associated firewall protection.
- **iPhone/iPad:** WireGuard → `+` → Create from file or archive, or Create from QR code. Accept iOS permission to add VPN configurations. The QR contains a private key: display and transfer it privately. The dashboard generates QR data locally and does not upload it to external QR services.
- **Android:** import into WireGuard; use Always-on VPN and Block connections without VPN when a persistent kill switch is required.
- **macOS/Linux:** use an appropriate WireGuard client. On-Demand or routing alone does not guarantee an OS-wide persistent kill switch; configure and test the OS firewall policy if strict fail-closed behavior is required.

Check that the device's visible public IPv4 matches the Elastic IP. Test Wi-Fi, cellular, DNS, unreachable-server conditions and network changes. The IPv4 DNS server `1.1.1.1` routes through the VPN. Both `0.0.0.0/0` and `::/0` are captured; **IPv6 internet is deliberately blocked** on the server. Do not remove `::/0`, which could permit native IPv6 bypass. IPv6-only access networks need functioning IPv4 translation/reachability to the endpoint.

The firewall blocks client access to host services, VPC/private ranges, peer-to-peer forwarding and EC2 metadata. It owns the entire nftables ruleset: use this instance exclusively for the VPN. This provides an internet exit, not access to a home LAN or anonymity beyond the VPN server.

For the iOS error “Reading or writing the configuration failed,” inspect WireGuard Settings → View log. `NEVPNErrorDomain Code=5 permission denied` is an iOS profile-saving permission problem. Check the system VPN permission and device-management restrictions; changing EC2 IAM or regenerating a QR does not address that error by itself.

## Revoke a device

Use Revoke in the dashboard, or inside the server's SSM session:

```sh
sudo vpn-client remove iphone
sudo wg show wg0
```

Only the selected peer is removed. If live synchronization fails after persistent configuration was changed, inspect locally and reconcile with `sudo systemctl restart wg-quick@wg0` (briefly interrupts all clients). Do not log `wg showconf`, `wg show all dump`, private key files or configuration exports.

## Rebuild while preserving the IP

```sh
terraform -chdir=terraform/server plan -destroy
terraform -chdir=terraform/server destroy
# Do not destroy terraform/ip if retaining the IP.
terraform -chdir=terraform/server plan -out=server.tfplan
terraform -chdir=terraform/server apply server.tfplan
```

The retained IP is reattached. The server's deleted disk, key and registrations are **not** preserved: re-enroll devices and replace their client configurations. If unchanged client profiles are essential, securely back up `/etc/wireguard` beforehand and restore it through a private trusted channel with restrictive ownership/permissions. The source does not place secret backups in Terraform state or automatically upload them to AWS services.

## Full teardown: stop all deployed services

Stop the local dashboard process first, then destroy the server stack and IP stack in this order:

```sh
terraform -chdir=terraform/server plan -destroy
terraform -chdir=terraform/server destroy
terraform -chdir=terraform/ip plan -destroy
terraform -chdir=terraform/ip destroy
```

Releasing the Elastic IP is permanent; rebuilding normally allocates a different address. Both old endpoint and old server identity become obsolete. Keep state until deletion is verified; deleting the files alone leaves AWS resources running. Local exports and private history can be retained outside Git, but they no longer connect after teardown.

## Validation

```sh
terraform fmt -check -recursive terraform
terraform -chdir=terraform/ip init -backend=false
terraform -chdir=terraform/server init -backend=false
terraform -chdir=terraform/ip validate
terraform -chdir=terraform/server validate
.venv/bin/python -m unittest discover -s tests -v
bash -n terraform/server/templates/bootstrap.sh.tftpl
bash -n scripts/smoke-test.sh
```

Offline tests cover authorization, origin/host checks, local secret isolation, account mismatches, peer enrollment/revocation, export permissions, stale keys, and device/address validation. Run dashboard coverage as documented in its README. They do not provision infrastructure.

`smoke-test.sh` runs as root on the dedicated server and temporarily uses slot 254 to verify encrypted forwarding/NAT, internet egress, DNS, metadata blocking and IPv6 blocking; it cleans up its peer/namespace/keys on exit. It does not prove a particular external phone carrier's UDP path. `tests/e2e_dashboard.py` is an explicitly invoked **live** browser test: it temporarily enrolls and revokes its own peer. Do not run it against an unrelated deployment.

## References

- [Terraform AWS EC2 resource](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/instance)
- [AWS SSM Agent on official AMIs](https://docs.aws.amazon.com/systems-manager/latest/userguide/ami-preinstalled-agent.html)
- [WireGuard Windows routing and firewall behavior](https://github.com/WireGuard/wireguard-windows/blob/master/docs/netquirk.md)
- [WireGuard Apple source](https://git.zx2c4.com/wireguard-apple/)
