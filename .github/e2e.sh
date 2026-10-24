#!/usr/bin/env bash
# End-to-end test on a Linux CI runner: the one-command installer with a
# real Wazuh agent, the systemd service, an idempotent re-run, uninstall.
# Usage: e2e.sh DIST_DIR WAZUH_VERSION
set -euxo pipefail
dist=$(realpath "$1")
version=$2

(cd "$dist" && sha256sum harrier-* >SHA256SUMS)
one_command() { sudo HARRIER_BASE_URL="file://$dist" sh install.sh "$@"; }

one_command --manager 127.0.0.1 --group default --wazuh-version "$version"
systemctl is-active --quiet harrier
name=$(sudo /opt/harrier/harrier name)
[[ $name =~ -[0-9a-f]{12}-[0-9a-f]{12}$ ]]
sudo grep -q "<agent_name>$name</agent_name>" /var/ossec/etc/ossec.conf
sudo grep -q '<label key="harrier_hwid">' /var/ossec/etc/ossec.conf

if one_command --wazuh-version 5.0.0; then
	echo "Wazuh agent 5.x was accepted"
	exit 1
fi
one_command --wazuh-version "$version" # same version again: no-op
systemctl is-active --quiet harrier
sudo systemctl restart harrier
systemctl is-active --quiet harrier
sudo /opt/harrier/harrier status

sudo /opt/harrier/harrier uninstall
if systemctl is-active --quiet harrier; then
	echo "harrier is still running after uninstall"
	exit 1
fi
