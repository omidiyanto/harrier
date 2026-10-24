#!/bin/sh
# Harrier one-command installer for Linux (x86_64 / i686). Run as root:
#
#   curl -fsSL https://github.com/omidiyanto/harrier/releases/latest/download/install.sh \
#     | sudo sh -s -- --manager 10.0.0.5 --group linux --wazuh-version 4.14.9
#
# Downloads Harrier (verified against SHA256SUMS) and, when needed, the official
# Wazuh agent package, then runs `harrier setup` with the remaining arguments.
# Re-running it is safe: it installs, upgrades or does nothing.
#
# --wazuh-version V   Wazuh agent to install/upgrade to: 4.x up to 4.14, not
#                     newer than the manager; optional when it is installed.
# Any other option is passed to `harrier setup` (see `harrier --help`).
#
# Environment: WAZUH_REGISTRATION_PASSWORD (enrollment password),
# HARRIER_BASE_URL (mirror of the release files), WAZUH_PACKAGES_URL (mirror
# of packages.wazuh.com, same layout).
set -eu

BASE=${HARRIER_BASE_URL:-https://github.com/omidiyanto/harrier/releases/latest/download}
WAZUH=${WAZUH_PACKAGES_URL:-https://packages.wazuh.com}

die() {
	echo "harrier install: $*" >&2
	exit 1
}

[ "$(id -u)" -eq 0 ] || die "run as root (sudo)"

version=
n=$#
while [ "$n" -gt 0 ]; do
	arg=$1
	shift
	n=$((n - 1))
	case $arg in
	--wazuh-version)
		[ "$n" -gt 0 ] || die "--wazuh-version needs a value"
		version=$1
		shift
		n=$((n - 1))
		;;
	--wazuh-version=*) version=${arg#*=} ;;
	*) set -- "$@" "$arg" ;;
	esac
done

case $version in
"" | 4.[0-9].[0-9]* | 4.1[0-4].[0-9]*) ;;
*) die "unsupported --wazuh-version $version: use a full 4.x version up to 4.14, e.g. 4.14.9 (5.x is untested)" ;;
esac
case $version in
*[!0-9.-]*) die "invalid --wazuh-version $version" ;;
esac

case $(uname -m) in
x86_64 | amd64) asset=linux-x86_64 deb_arch=amd64 rpm_arch=x86_64 ;;
i386 | i486 | i586 | i686) asset=linux-i686 deb_arch=i386 rpm_arch=i386 ;;
*) die "unsupported architecture $(uname -m) (x86_64 and i686 only)" ;;
esac

fetch() {
	if command -v curl >/dev/null 2>&1; then
		curl -fsSL --proto '=https,file' --retry 3 -o "$2" "$1"
	elif command -v wget >/dev/null 2>&1; then
		wget -q -O "$2" "$1"
	else
		die "curl or wget is required"
	fi || die "download failed: $1"
}

tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT

fetch "$BASE/SHA256SUMS" "$tmp/SHA256SUMS"
fetch "$BASE/harrier-$asset" "$tmp/harrier-$asset"
(cd "$tmp" && grep " harrier-$asset\$" SHA256SUMS | sha256sum -c - >/dev/null) ||
	die "harrier-$asset does not match SHA256SUMS"
chmod 755 "$tmp/harrier-$asset"

if [ -n "$version" ]; then
	case $version in
	*-*) full=$version ;;
	*) full=$version-1 ;;
	esac
	major=${full%%.*}
	if command -v dpkg >/dev/null 2>&1 && [ -f /etc/debian_version ]; then
		pkg=wazuh-agent_${full}_${deb_arch}.deb
		url=$WAZUH/$major.x/apt/pool/main/w/wazuh-agent/$pkg
	elif command -v rpm >/dev/null 2>&1; then
		pkg=wazuh-agent-$full.$rpm_arch.rpm
		url=$WAZUH/$major.x/yum/$pkg
	else
		die "neither dpkg (Debian/Ubuntu) nor rpm (RHEL/SUSE) found"
	fi
	echo "harrier install: downloading $url"
	fetch "$url" "$tmp/$pkg"
	set -- "$@" --package "$tmp/$pkg"
fi

"$tmp/harrier-$asset" setup "$@"
