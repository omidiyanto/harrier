#!/usr/bin/env bash
# Integration test against a real Wazuh single-node stack (the official
# wazuh-docker compose: manager, indexer, dashboard) on a Linux CI runner.
# The agent and Harrier run on the runner itself, under systemd.
# Usage: integration.sh DIST_DIR WAZUH_VERSION
set -euo pipefail
dist=$(realpath "$1")
version=$2
bin=$dist/harrier-linux-x86_64
harrier=/opt/harrier/harrier
work=${RUNNER_TEMP:-/tmp}/harrier-it
stack=$work/wazuh-docker/single-node
API=https://127.0.0.1:55000
ADMIN='wazuh-wui:MyS3cr37P450r.*-' # wazuh-docker defaults
INDEXER='admin:SecretPassword'
API_PASSWORD='Harrier.CI-2026'

step() { printf '\n== %s\n' "$*"; }
fail() {
	echo "FAIL: $*" >&2
	exit 1
}
# wait_for SECONDS CMD...: retry CMD every 5 s until it succeeds.
wait_for() {
	local end=$((SECONDS + $1))
	shift
	until "$@"; do
		((SECONDS < end)) || fail "timed out: $*"
		sleep 5
	done
}
dc() { docker compose -f "$stack/docker-compose.yml" "$@"; }

# Wazuh API as the built-in admin (token refreshed before it expires).
token='' token_at=-1000
api() {
	if ((SECONDS - token_at > 600)); then
		token=$(curl -fsSk -u "$ADMIN" -X POST "$API/security/user/authenticate?raw=true") || return 1
		token_at=$SECONDS
	fi
	local method=$1 path=$2
	shift 2
	curl -fsSk -X "$method" -H "Authorization: Bearer $token" \
		-H 'Content-Type: application/json' "$API$path" "$@"
}
id_of() { jq -r '.data.affected_items[0].id' <<<"$1"; }
agent() { api GET "/agents?name=$1&select=id,status,group" | jq -c '.data.affected_items[0] // empty'; }
is_status() { [ "$(agent "$1" | jq -r '.status // empty')" = "$2" ]; }
gone() { [ -z "$(agent "$1")" ]; }
add_agent() { api POST /agents -d "{\"name\":\"$1\"}" | jq -r .data.id; }

step "Wazuh $version single-node stack (official docker compose)"
rm -rf "$work" && mkdir -p "$work"
git clone -q --depth 1 -b "v$version" https://github.com/wazuh/wazuh-docker "$work/wazuh-docker"
# Disconnected after 1 minute instead of 10, so the test does not idle.
conf=$stack/config/wazuh_cluster/wazuh_manager.conf
sed -i 's|<agents_disconnection_time>10m<|<agents_disconnection_time>1m<|' "$conf"
grep -q '<agents_disconnection_time>1m<' "$conf"
sudo sysctl -q -w vm.max_map_count=262144
docker compose -f "$stack/generate-indexer-certs.yml" run --rm generator >/dev/null
dc up -d --quiet-pull
wait_for 600 api GET '/agents?limit=1' -o /dev/null

step "One-command install against the real manager"
(cd "$dist" && sha256sum harrier-* >SHA256SUMS)
sudo HARRIER_BASE_URL="file://$dist" sh install.sh --manager 127.0.0.1 --group default --wazuh-version "$version"
name=$(sudo "$harrier" name)
hash=$(sudo "$harrier" status | sed -n 's/^hardware id *: \([0-9a-f]*\).*/\1/p')
[[ $name =~ -[0-9a-f]{12}-[0-9a-f]{12}$ && $hash =~ ^[0-9a-f]{64}$ ]]
wait_for 300 is_status "$name" active
# The scenarios below run `harrier check` themselves.
sudo systemctl stop harrier

step "Alerts reach the indexer carrying the harrier_hwid label"
labelled_alert() {
	curl -fsSk -u "$INDEXER" -G 'https://127.0.0.1:9200/wazuh-alerts-*/_search' \
		--data-urlencode "q=agent.name:\"$name\"" --data-urlencode size=100 | grep -q "$hash"
}
wait_for 600 labelled_alert

step "Least-privilege API user, exactly as the README describes"
api POST /groups -d '{"group_id":"finance"}' >/dev/null
user=$(id_of "$(api POST /security/users -d "{\"username\":\"harrier\",\"password\":\"$API_PASSWORD\"}")")
p1=$(id_of "$(api POST /security/policies -d '{"name":"harrier-agents","policy":{"actions":["agent:read","agent:delete","agent:modify_group"],"resources":["agent:id:*"],"effect":"allow"}}')")
p2=$(id_of "$(api POST /security/policies -d '{"name":"harrier-groups","policy":{"actions":["group:modify_assignments"],"resources":["group:id:*"],"effect":"allow"}}')")
role=$(id_of "$(api POST /security/roles -d '{"name":"harrier"}')")
[[ "$user $p1 $p2 $role" =~ ^[0-9]+\ [0-9]+\ [0-9]+\ [0-9]+$ ]]
api POST "/security/roles/$role/policies?policy_ids=$p1,$p2" >/dev/null
api POST "/security/users/$user/roles?role_ids=$role" >/dev/null
sleep 2

server() { sudo HARRIER_API_PASSWORD="$API_PASSWORD" "$bin" setup-server --api-url "$API" --api-user harrier "$@"; }
step "setup-server refuses a certificate that does not match the pin"
if server --api-pin "sha256//$(head -c 32 /dev/urandom | base64)"; then
	fail "a wrong pin was accepted"
fi

step "setup-server with the pinned API certificate"
dc exec -T wazuh.manager cat /var/ossec/api/configuration/ssl/server.crt >"$work/api.crt"
server --api-cert "$work/api.crt"
systemctl is-active --quiet harrier-reconcile
# The scenarios below apply the plans themselves.
sudo systemctl stop harrier-reconcile

step "Inventory hygiene: twins, new network cards, legacy names"
host=${name%-*-*} fw=${name##*-} rest=${name%-*}
hw=${rest##*-}
twin=old-$host-$hw-$fw nic=$host-0a1b2c3d4e5f-$fw other=other-0a1b2c3d4e5f-0a1b2c3d4e5f
api PUT "/agents/$(add_agent "$twin")/group/finance?force_single_group=true" >/dev/null
for n in "$nic" "$host" "$other"; do add_agent "$n" >/dev/null; done

plan=$(sudo "$harrier" reconcile)
echo "$plan"
grep -qE "REGROUP +[0-9]+ $name: groups finance " <<<"$plan"
grep -qE "DELETE +[0-9]+ $twin: duplicate of $name " <<<"$plan"
grep -qE "DELETE +[0-9]+ $nic: network cards changed, now $name " <<<"$plan"
grep -qE "DELETE +[0-9]+ $host: legacy name, now $name " <<<"$plan"
if grep -q "$other" <<<"$plan"; then fail "unrelated agent planned"; fi
[ -n "$(agent "$twin")" ] || fail "dry-run changed the inventory"

sudo sh -c 'umask 077; sed "s/^max_delete *=.*/max_delete = 1/" /etc/harrier/server.conf >/etc/harrier/strict.conf'
if sudo "$harrier" reconcile --apply --config /etc/harrier/strict.conf; then
	fail "max_delete = 1 did not stop a 3-agent cleanup"
fi
sudo rm /etc/harrier/strict.conf
[ -n "$(agent "$twin")" ] || fail "max_delete guard deleted agents"

sudo "$harrier" reconcile --apply
for n in "$twin" "$nic" "$host"; do gone "$n" || fail "$n was not deleted"; done
[ -n "$(agent "$other")" ] || fail "unrelated agent deleted"
agent "$name" | jq -e '.status == "active" and .group == ["finance"]'

step "Case F: a tampered agent name is repaired"
sudo sed -i "s|<agent_name>$name</agent_name>|<agent_name>tampered</agent_name>|" /var/ossec/etc/ossec.conf
sudo "$harrier" check
sudo grep -q "<agent_name>$name</agent_name>" /var/ossec/etc/ossec.conf
wait_for 180 is_status "$name" active

step "Case E: a new hostname re-enrolls, the server drops the old record"
sudo hostnamectl set-hostname harrier-ci-renamed
new=$(sudo "$harrier" name)
[[ $new != "$name" && ${new: -25} == "${name: -25}" ]] || fail "unexpected new name $new"
sudo "$harrier" check
wait_for 300 is_status "$new" active
wait_for 300 is_status "$name" disconnected
plan=$(sudo "$harrier" reconcile --apply)
echo "$plan"
grep -qE "DELETE +[0-9]+ $name: duplicate of $new " <<<"$plan"
gone "$name" || fail "old record kept"
agent "$new" | jq -e '.status == "active" and .group == ["finance"]'

step "Case C: an agent deleted on the server comes back under its name"
old_id=$(agent "$new" | jq -r .id)
api DELETE "/agents?agents_list=$old_id&status=all&older_than=0s" >/dev/null
back() { agent "$new" | jq -e --arg old "$old_id" '.status == "active" and .id != $old' >/dev/null; }
wait_for 600 back

sudo systemctl start harrier harrier-reconcile
systemctl is-active --quiet harrier
systemctl is-active --quiet harrier-reconcile
step "All integration scenarios passed"
