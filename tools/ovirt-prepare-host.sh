#!/bin/bash
# Prepare an oVirt host for hypervisor use in CI.
#
# This script runs on the oVirt target node (not the CI runner). It:
#   1. Restarts ovirt-engine and waits for it to be healthy
#   2. Enables root SSH login for VDSM deployment
#   3. Verifies KVM is available for nested virtualization
#   4. Creates the local storage directory
#   5. Installs the oVirt Python SDK and netaddr

set -xe
export PS4='=======================\n+ '

# Restart ovirt-engine so SSO works (engine-setup says to do this).
# Then wait for the engine's health endpoint to respond, which
# indicates the JBoss/WildFly application server has fully started
# and deployed the engine.ear application. We use the health
# endpoint rather than the SSO token endpoint because Keycloak
# (oVirt 4.5) uses a different auth flow that the internal SSO
# endpoint doesn't support.
sudo systemctl restart ovirt-engine
echo 'Waiting for oVirt engine to become ready...'
engine_ready=0
for i in $(seq 1 60); do
    resp=$(curl -sk \
        https://localhost/ovirt-engine/services/health \
        2>/dev/null) || true
    if echo "$resp" | grep -q 'DB Up'; then
        echo 'oVirt engine is ready'
        engine_ready=1
        break
    fi
    echo "  Attempt $i/60: engine not ready, waiting 10s..."
    sleep 10
done
if [ $engine_ready -ne 1 ]; then
    echo 'ERROR: oVirt engine never became ready. Dumping diagnostics...'
    sudo systemctl status ovirt-engine || true
    echo '--- Last 50 lines of engine.log ---'
    sudo tail -50 /var/log/ovirt-engine/engine.log 2>/dev/null || true
    echo '--- Last 50 lines of server.log ---'
    sudo tail -50 /var/log/ovirt-engine/server.log 2>/dev/null || true
    exit 1
fi

# Enable root SSH login so oVirt engine can deploy VDSM.
# Use a drop-in file if sshd_config.d exists (Rocky 9+), or
# modify sshd_config directly (Rocky 8). Either way, ensure
# root login and password auth are enabled.
echo 'root:foobar' | sudo chpasswd
sudo passwd -u root 2>/dev/null || true
if [ -d /etc/ssh/sshd_config.d ]; then
    printf 'PermitRootLogin yes\nPasswordAuthentication yes\n' \
        | sudo tee /etc/ssh/sshd_config.d/00-ovirt-ci.conf > /dev/null
else
    sudo sed -i 's/^#*PermitRootLogin.*/PermitRootLogin yes/' /etc/ssh/sshd_config
    sudo sed -i 's/^#*PasswordAuthentication.*/PasswordAuthentication yes/' /etc/ssh/sshd_config
fi
sudo systemctl restart sshd
echo '--- SSH config verification ---'
sudo sshd -T 2>/dev/null | grep -iE 'permitrootlogin|passwordauthentication'

# Verify KVM is available for nested virtualization
echo '--- KVM availability ---'
ls -la /dev/kvm 2>/dev/null || echo 'WARNING: /dev/kvm not found'
lsmod | grep kvm || echo 'WARNING: no kvm modules loaded'
cat /proc/cpuinfo | grep -c vmx || cat /proc/cpuinfo | grep -c svm \
    || echo 'WARNING: no hardware virt extensions'

# Create local storage directory (uid 36 = vdsm on RHEL-based)
sudo mkdir -p /srv/ovirt-storage
sudo chown 36:36 /srv/ovirt-storage

# Install oVirt Python SDK and netaddr (needed by the host-deploy
# Ansible role's ipaddr filter in the OVN configuration task)
sudo dnf install -y python3-ovirt-engine-sdk4 python3-netaddr
