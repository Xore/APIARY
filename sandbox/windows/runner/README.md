# Self-Hosted GitHub Actions Runner Setup

The Windows sandbox detonation job requires a **self-hosted runner** on the
host machine that has VMware Workstation installed and controls the Windows
11 analysis VM.

The standard `ubuntu-latest` GitHub-hosted runner cannot connect to a local
VMware VM or call `vmrun`.

## Setup

### 1. Install the runner on your VMware host (Linux)

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
            --name honeypot-vmware-host \
            --labels self-hosted,vmware,windows-sandbox

# Install as systemd service
sudo ./svc.sh install
sudo ./svc.sh start
```

### 2. Install dependencies on the runner host

```bash
pip install pywinrm python-evtx lxml requests smbprotocol
apt install smbclient
```

### 3. Set runner environment variables

In `/opt/actions-runner/.env`:
```bash
VM_HOST=10.10.10.2
VM_USER=analyst
VM_PASS=malware
VMRUN_PATH=/usr/bin/vmrun
VMX_PATH=/vms/win11-analysis/win11.vmx
GOLDEN_SNAPSHOT=SNAPSHOT_3_GOLDEN
OBSERVATION_SECS=300
```

### 4. Workflow label usage

In `Xore/Honeypot/.github/workflows/analyze.yml`:
```yaml
windows_sandbox:
  runs-on: [self-hosted, vmware, windows-sandbox]
```

### Security Note

> ⚠️ Never expose the self-hosted runner or the analysis VMs to the
> internet. The runner host should be on the same isolated network as
> the VMware host-only adapter. Block all outbound traffic from the
> runner host except GitHub API (for workflow reporting).
