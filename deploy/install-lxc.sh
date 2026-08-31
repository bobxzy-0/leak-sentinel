#!/usr/bin/env bash
set -euo pipefail

if [[ "${EUID}" -ne 0 ]]; then
  echo "请使用 root 运行：sudo bash deploy/install-lxc.sh"
  exit 1
fi

APP_DIR="/opt/leak-sentinel"
CONFIG_DIR="/etc/leak-sentinel"
DATA_DIR="/var/lib/leak-sentinel"
SERVICE_USER="leak-sentinel"
SOURCE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

apt-get update
apt-get install -y python3 python3-venv python3-pip rsync ca-certificates

if ! id "${SERVICE_USER}" >/dev/null 2>&1; then
  useradd --system --home-dir "${APP_DIR}" --shell /usr/sbin/nologin "${SERVICE_USER}"
fi

install -d -o "${SERVICE_USER}" -g "${SERVICE_USER}" "${APP_DIR}" "${DATA_DIR}"
install -d -m 0750 -o root -g "${SERVICE_USER}" "${CONFIG_DIR}"
rsync -a --delete --exclude '.git' --exclude '.env' --exclude '.venv' "${SOURCE_DIR}/" "${APP_DIR}/"

python3 -m venv "${APP_DIR}/.venv"
"${APP_DIR}/.venv/bin/pip" install --upgrade pip
"${APP_DIR}/.venv/bin/pip" install -r "${APP_DIR}/requirements.txt"
chown -R "${SERVICE_USER}:${SERVICE_USER}" "${APP_DIR}" "${DATA_DIR}"

if [[ ! -f "${CONFIG_DIR}/leak-sentinel.env" ]]; then
  install -m 0640 -o root -g "${SERVICE_USER}" "${APP_DIR}/deploy/leak-sentinel.env.example" "${CONFIG_DIR}/leak-sentinel.env"
fi

install -m 0644 "${APP_DIR}/deploy/leak-sentinel.service" /etc/systemd/system/leak-sentinel.service
systemctl daemon-reload

echo
echo "安装完成。下一步："
echo "1. 编辑 ${CONFIG_DIR}/leak-sentinel.env，替换所有 CHANGE_ME"
echo "2. systemctl enable --now leak-sentinel"
echo "3. systemctl status leak-sentinel"
