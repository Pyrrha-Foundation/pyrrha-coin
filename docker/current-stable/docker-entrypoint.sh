#!/bin/bash
set -e

if [[ "$1" == "pyrrha-cli" || "$1" == "pyrrha-tx" || "$1" == "pyrrhad" || "$1" == "test_pyrrha" ]]; then
  mkdir -p "$PYRRHA_DATA"

  if [[ ! -s "$PYRRHA_DATA/pyrrha.conf" ]]; then
    cat <<EOF > "$PYRRHA_DATA/pyrrha.conf"
    printtoconsole=1
    rpcallowip=::/0
    rpcpassword=${PYRRHA_RPC_PASSWORD:-password}
    rpcuser=${PYRRHA_RPC_USER:-pyrrha}
EOF
    chown pyrrha:pyrrha "$PYRRHA_DATA/pyrrha.conf"
  fi

  # ensure correct ownership and linking of data directory
  # we do not update group ownership here, in case users want to mount
  # a host directory and still retain access to it
  chown -R pyrrha "$PYRRHA_DATA"
  ln -sfn "$PYRRHA_DATA" /home/pyrrha/.pyrrha
  chown -h pyrrha:pyrrha /home/pyrrha/.pyrrha

  exec gosu pyrrha "$@"
fi

exec "$@"
