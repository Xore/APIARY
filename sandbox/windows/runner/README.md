# Self-Hosted GitHub Actions Runner Setup

The Windows sandbox detonation job requires a **self-hosted runner** on the
host machine that runs **QEMU/KVM + libvirt** (via docker-compose) and
controls the Windows 11 analysis VM.

The standard `ubuntu-latest` GitHub-hosted runner cannot connect to a local
KVM guest or call `virsh` / `qemu-img`.

## Setup

### 1. Prerequisites on the KVM host

Ensure the host has KVM and libvirt installed and that the runner user is in
the `libvirt` and `kvm` groups:

```bash
apt install qemu-kvm libvirt-daemon-system virtinst virt-manager
usermod -aG libvirt,kvm $USER

# Verify KVM is available
virtsh list --all
```

### 2. Install the runner on your KVM host (Linux)

```bash
# Create runner directory
mkdir -p /opt/actions-runner && cd /opt/actions-runner

# Download (check https://github.com/actions/runner/releases for latest)
curl -o actions-runner-linux-x64-2.317.0.tar.gz -L \
  https://github.com/actions/runner/releases/download/v2.317.0/actions-runner-linux-x64-2.317.0.tar.gz
tar xzf ./actions-runner-linux-x64-2.317.0.tar.gz

# Configure (get token from Xore/Honeypot → Settings → Actions → Runners → New self-hosted runner)
./config.sh --url https://github.com/Xore/Honeypot \
            --token <RUNNER_TOKEN> \
            --name honeypot-kvm-host \
            --labels self-hosted,kvm,windows-sandbox

# Install as systemd service
sudo ./svc.sh install
sudo ./svc.sh start
```

### 3. Install dependencies on the runner host

```bash
pip install pywinrm python-evtx lxml requests smbprotocol
apt install smbclient libvirt-clients qemu-utils
```

### 4. Set runner environment variables

In `/opt/actions-runner/.env`:
```bash
VM_HOST=10.10.10.2
VM_USER=analyst
VM_PASS=malware
# libvirt connection URI (local KVM)
LIBVIRT_URI=qemu:///system
# libvirt domain name of the Windows 11 analysis VM
VM_DOMAIN=win11-analysis
# Snapshot name to revert to before each detonation
GOLDEN_SNAPSHOT=golden-clean
OBSERVATION_SECS=300
```

### 5. Snapshot management with virsh

Create the golden snapshot after provisioning the clean Windows 11 VM:

```bash
# Shut down the VM cleanly first
virsh shutdown win11-analysis

# Create the golden snapshot
virsh snapshot-create-as win11-analysis golden-clean \
  --description "Clean Windows 11 baseline" \
  --atomic

# Verify
virsh snapshot-list win11-analysis
```

The CI workflow reverts to this snapshot before every detonation:

```bash
# Revert
virsh snapshot-revert win11-analysis golden-clean
# Start
virsh start win11-analysis
```

### 6. Workflow label usage

In `Xore/Honeypot/.github/workflows/analyze.yml`:
```yaml
windows_sandbox:
  runs-on: [self-hosted, kvm, windows-sandbox]
```

### 7. Integration with docker-compose

The honeypot-stack uses docker-compose to orchestrate the surrounding services
(Elasticsearch, Logstash, dashboard, etc.). The KVM host is the same machine.
Ensure the runner service starts **after** docker-compose:

```ini
# /etc/systemd/system/actions-runner.service (relevant section)
[Unit]
After=network-online.target docker.service
Wants=network-online.target
```

The Windows VM sits on a **libvirt isolated network** (`virbr1`, host-only)
that is separate from the docker bridge networks, so it cannot reach the
containers directly unless you add an explicit bridge rule.

### Security Note

> ⚠️ Never expose the self-hosted runner or the analysis VMs to the
> internet. The Windows 11 KVM guest should be on an isolated libvirt
> host-only network (`virbr1`). Block all outbound traffic from the
> guest at the libvirt network level except the WinRM port (5985/5986)
> used by the runner, and GitHub API (for workflow reporting) from the
> host.
