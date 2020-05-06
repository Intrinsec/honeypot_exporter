#!/usr/bin/env bash

set -euf -o pipefail

enabled_collectors=$(cat << COLLECTORS
  honeypot
COLLECTORS
)
disabled_collectors=$(cat << COLLECTORS
COLLECTORS
)
cd "$(dirname $0)"

port="$((10000 + (RANDOM % 10000)))"
tmpdir=$(mktemp -d /tmp/honeypot_exporter_e2e_test.XXXXXX)

arch="$(uname -m)"

case "${arch}" in
  *) fixture='collector/fixtures/e2e-output.txt' ;;
esac

keep=0; update=0; verbose=0
while getopts 'hkuv' opt
do
  case "$opt" in
    k)
      keep=1
      ;;
    u)
      update=1
      ;;
    v)
      verbose=1
      set -x
      ;;
    *)
      echo "Usage: $0 [-k] [-u] [-v]"
      echo "  -k: keep temporary files and leave honeypot_exporter running"
      echo "  -u: update fixture"
      echo "  -v: verbose output"
      exit 1
      ;;
  esac
done

if [ ! -x ./honeypot_exporter ]
then
    echo './honeypot_exporter not found. Consider running `go build` first.' >&2
    exit 1
fi

./honeypot_exporter \
  $(for c in ${enabled_collectors}; do echo --collector.${c}  ; done) \
  $(for c in ${disabled_collectors}; do echo --no-collector.${c}  ; done) \
  --web.listen-address "127.0.0.1:${port}" \
  --log.level="debug" > "${tmpdir}/honeypot_exporter.log" 2>&1 &

echo $! > "${tmpdir}/honeypot_exporter.pid"

finish() {
  if [ $? -ne 0 -o ${verbose} -ne 0 ]
  then
    cat << EOF >&2
LOG =====================
$(cat "${tmpdir}/honeypot_exporter.log")
=========================
EOF
  fi

  if [ ${update} -ne 0 ]
  then
    cp "${tmpdir}/e2e-output.txt" "${fixture}"
  fi

  if [ ${keep} -eq 0 ]
  then
    kill -9 "$(cat ${tmpdir}/honeypot_exporter.pid)"
    # This silences the "Killed" message
    set +e
    wait "$(cat ${tmpdir}/honeypot_exporter.pid)" > /dev/null 2>&1
    rm -rf "${tmpdir}"
  fi
}

trap finish EXIT

get() {
  if command -v curl > /dev/null 2>&1
  then
    curl -s -f "$@"
  elif command -v wget > /dev/null 2>&1
  then
    wget -O - "$@"
  else
    echo "Neither curl nor wget found"
    exit 1
  fi
}

sleep 1



get "127.0.0.1:${port}/metrics" | sed \
  -e 's/ [0-9.e+-]\+$/ 0/' \
  -e 's/^node_exporter_build_info.*/node_exporter_build_info 0/' \
  -e 's/^go_info.*/go_info 0/' > "${tmpdir}/e2e-output.txt"

diff -u \
  "${fixture}" \
  "${tmpdir}/e2e-output.txt"
