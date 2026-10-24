#!/usr/bin/env bash
# Run a command; if it fails, show its last output lines as an annotation on
# the workflow run page, so the error is readable without opening raw logs.
log=$(mktemp)
"$@" 2>&1 | tee "$log"
status=${PIPESTATUS[0]}
if [ "$status" -ne 0 ]; then
	msg=$(tail -n 40 "$log" | tr -d '\r' | sed 's/%/%25/g' | awk '{ printf "%s%%0A", $0 }')
	# Annotation titles must not contain ':' or ','; keep it to the tool name.
	echo "::error title=${RUNNER_OS:-local} ${1##*/} failed::$msg"
fi
exit "$status"
