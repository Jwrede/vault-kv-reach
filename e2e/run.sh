#!/usr/bin/env bash
# Runs the e2e tests against a fresh dev server in Docker.
#   IMAGE=hashicorp/vault:2.2.2 e2e/run.sh
#   IMAGE=openbao/openbao:2.7.2 e2e/run.sh
set -euo pipefail
IMAGE=${IMAGE:-hashicorp/vault:latest}
PORT=${PORT:-18200}
NAME=vkr-e2e-$$
case "$IMAGE" in
  *openbao*) ENVV=(-e BAO_DEV_ROOT_TOKEN_ID=root); CMD=(server -dev -dev-listen-address=0.0.0.0:8200) ;;
  *)         ENVV=(-e VAULT_DEV_ROOT_TOKEN_ID=root -e VAULT_DEV_LISTEN_ADDRESS=0.0.0.0:8200); CMD=() ;;
esac
docker run -d --name "$NAME" --cap-add=IPC_LOCK "${ENVV[@]}" -p "127.0.0.1:$PORT:8200" "$IMAGE" "${CMD[@]}" >/dev/null
trap 'docker rm -f "$NAME" >/dev/null 2>&1 || true' EXIT
for _ in $(seq 1 60); do
  if curl -fsS "http://127.0.0.1:$PORT/v1/sys/health" >/dev/null 2>&1; then break; fi
  sleep 1
done
curl -fsS "http://127.0.0.1:$PORT/v1/sys/health" | head -c 300; echo
VKR_E2E_ADDR="http://127.0.0.1:$PORT" VKR_E2E_TOKEN=root go test -count=1 -v ./e2e/
