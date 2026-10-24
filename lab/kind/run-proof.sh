#!/usr/bin/env bash
# =============================================================================
# lab/kind/run-proof.sh — KIND 实证：hostNetwork Pod 绕过 NetworkPolicy（可实跑）
#
# 依据：Trident 设计 设计基线 5.6「主机网络层：hostNetwork/hostDevice 绕过 CNI 与
#       NetworkPolicy」；验收标准 12「hostNetwork 绕过 NetworkPolicy 实证」。
#
# 对照实验设计（自包含可重复）：
#   1. kind 建群（disableDefaultCNI）并安装 Calico —— kindnet 不执行 NetworkPolicy
#      （kubernetes-sigs/kind#3705），不装策略 CNI 则实证无效；
#   2. namespace trident-proof 应用全量 default-deny（Ingress+Egress）；
#   3. 部署 target（nginx）+ 普通 Pod 探测 → 预期被拒（策略生效对照组）；
#   4. hostNetwork Pod（hostnetwork-bypass.yaml）探测同目标 → 预期连通（旁路成立）；
#   5. 结果矩阵写入 lab/kind/PROOF-hostnetwork-bypass.md（环境/命令/结果/判定方式）。
#
# 判定（自校验，防环境假阳性）：
#   - 普通 Pod 未被拒 → environment-invalid（策略未被执行，常见于 CNI 未就绪）；
#   - 普通 Pod 被拒 + hostNetwork Pod 连通 → bypass-confirmed（退出码 0）；
#   - 普通 Pod 被拒 + hostNetwork Pod 也被拒 → bypass-not-observed（退出码 1）。
#
# 用法（WSL Ubuntu 实验室，需 docker + kind + kubectl + curl）：
#   bash lab/kind/run-proof.sh             # 全流程，结束自动删群（可重复）
#   bash lab/kind/run-proof.sh --keep      # 保留现场便于人工检查
# 环境变量：CLUSTER_NAME / KIND_NODE_IMAGE / KIND_POD_CIDR / CALICO_MANIFEST /
#           TARGET_IMAGE / PROBE_IMAGE / PROBE_TIMEOUT_S / WAIT_TIMEOUT_S / OUT
#
# 实验室边界：本仓库 Windows 宿主 WSL2 不可用（HCS_E_HYPERV_NOT_INSTALLED），
# 本脚本按 WSL 实验室环境设计交付；PROOF-hostnetwork-bypass.md 由脚本实跑时生成。
# =============================================================================
set -euo pipefail

CLUSTER_NAME="${CLUSTER_NAME:-trident-proof}"
NAMESPACE="${NAMESPACE:-trident-proof}"
KIND_NODE_IMAGE="${KIND_NODE_IMAGE:-}"       # 缺省用 kind 内置节点镜像
KIND_POD_CIDR="${KIND_POD_CIDR:-10.244.0.0/16}"
CALICO_MANIFEST="${CALICO_MANIFEST:-https://raw.githubusercontent.com/projectcalico/calico/v3.28.2/manifests/calico.yaml}"
TARGET_IMAGE="${TARGET_IMAGE:-nginx:1.27-alpine}"
PROBE_IMAGE="${PROBE_IMAGE:-curlimages/curl:8.11.1}"
PROBE_TIMEOUT_S="${PROBE_TIMEOUT_S:-5}"
WAIT_TIMEOUT_S="${WAIT_TIMEOUT_S:-420}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
OUT="${OUT:-$SCRIPT_DIR/PROOF-hostnetwork-bypass.md}"
KEEP=0
[ "${1:-}" = "--keep" ] && KEEP=1

log() { printf '[run-proof] %s\n' "$*" >&2; }
die() { printf '[run-proof] ERROR: %s\n' "$*" >&2; exit 1; }

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

KIND_VERSION="$(kind version 2>/dev/null | head -1 || echo '?')"
KERNEL="$(uname -r 2>/dev/null || echo '?')"
CALICO_SRC="$CALICO_MANIFEST"
K8S_VERSION='?'

capture_k8s_version() {
  K8S_VERSION="$(kubectl version -o json 2>/dev/null | python3 -c \
    'import json,sys; print(json.load(sys.stdin)["serverVersion"]["gitVersion"])' 2>/dev/null || echo '?')"
}

write_conclusion() {  # write_conclusion <verdict> <notes...>
  local verdict="$1"; shift
  local notes="${*:-}"
  capture_k8s_version
  cat > "$OUT" <<EOF
# KIND 实证结论 — hostNetwork Pod 绕过 NetworkPolicy

- 日期（UTC）：$(date -u +%Y-%m-%dT%H:%M:%SZ)
- 判定方式：主动实测（KIND + Calico；非 fixture 推演）
- 结论：**${verdict}**
- 网络层级：主机网络层（设计基线七层网络模型）；旁路原语：hostNetwork Pod 共享宿主网络栈

## 实验环境

| 项 | 值 |
|---|---|
| kind | ${KIND_VERSION} |
| Kubernetes | ${K8S_VERSION} |
| CNI | Calico（disableDefaultCNI 建群后安装，源：${CALICO_SRC}） |
| Pod CIDR | ${KIND_POD_CIDR} |
| 内核（WSL） | ${KERNEL} |
| 集群名 / 命名空间 | ${CLUSTER_NAME} / ${NAMESPACE} |

## 实验步骤（可复现命令）

1. \`kind create cluster\`（config：disableDefaultCNI: true + podSubnet ${KIND_POD_CIDR}）
2. 安装 Calico：\`kubectl apply -f ${CALICO_SRC}\`（IPPool 改 ${KIND_POD_CIDR}），等待 calico-node 就绪
3. \`kubectl apply -f lab/kind/default-deny-netpol.yaml\`（命名空间 + Ingress/Egress 全量 default-deny）
4. 部署 target（${TARGET_IMAGE}）并暴露 Service
5. 普通 Pod（${PROBE_IMAGE}）curl 探测 target Pod IP 与 ClusterIP（预期：被拒/超时）
6. \`kubectl apply -f lab/kind/hostnetwork-bypass.yaml\`，hostNetwork Pod 同探测（预期：连通）
7. 汇总矩阵并写入本文件；\`--keep\` 保留现场，否则删除集群

## 结果矩阵

| 探测方 | 目标 | curl 退出码 | HTTP 码 | 预期 | 判定 |
|---|---|---|---|---|---|
| 普通 Pod（policy 生效面） | target Pod IP（${TARGET_POD_IP:-?}） | ${NORMAL_POD_RC:-?} | ${NORMAL_POD_CODE:-?} | 被拒 | ${NORMAL_POD_JUDGE:-?} |
| 普通 Pod（policy 生效面） | Service ClusterIP（${TARGET_SVC_IP:-?}） | ${NORMAL_SVC_RC:-?} | ${NORMAL_SVC_CODE:-?} | 被拒 | ${NORMAL_SVC_JUDGE:-?} |
| hostNetwork Pod | target Pod IP（${TARGET_POD_IP:-?}） | ${HOSTNET_POD_RC:-?} | ${HOSTNET_POD_CODE:-?} | 连通 | ${HOSTNET_POD_JUDGE:-?} |
| hostNetwork Pod | Service ClusterIP（${TARGET_SVC_IP:-?}） | ${HOSTNET_SVC_RC:-?} | ${HOSTNET_SVC_CODE:-?} | 连通 | ${HOSTNET_SVC_JUDGE:-?} |

（curl 退出码 28 = 超时被拒；HTTP 000 = 未获得响应；200 = 连通。）

## 结论与 Ruling

- ${verdict}
- 说明：hostNetwork 流量不走 Pod veth/overlay，K8s NetworkPolicy 不覆盖宿主网络路径
 （设计基线 5.6 主机网络层）。防御侧须靠准入禁令（Kyverno/Gatekeeper 拒绝 hostNetwork
 Pod 创建，或 PSS + 例外通道）与主机侧 ACL/Calico host endpoint 收敛，不能依赖
 NetworkPolicy。
- 备注：${notes:-无}

## 复现

\`\`\`bash
bash lab/kind/run-proof.sh            # 自动建群→实证→删群→写本文件
bash lab/kind/run-proof.sh --keep     # 保留现场（kubectl -n ${NAMESPACE} ...检查）
\`\`\`

## 清理

\`\`\`bash
kind delete cluster --name ${CLUSTER_NAME}
\`\`\`
EOF
  printf '[run-proof] 结论已写入 %s（%s）\n' "$OUT" "$verdict" >&2
}

on_error() {
  local rc=$?
  write_conclusion "script-failed（步骤中断，rc=${rc}）" "脚本在实证中途失败；检查 docker/kind/网络后重跑"
  if [ "$KEEP" != "1" ]; then kind delete cluster --name "$CLUSTER_NAME" >/dev/null 2>&1 || true; fi
  exit "$rc"
}
trap on_error ERR

require_tools() {
  local t
  for t in kind kubectl docker curl; do
    command -v "$t" >/dev/null 2>&1 || die "缺少工具: $t（请在 WSL Ubuntu 实验室安装）"
  done
  log "工具就绪：${KIND_VERSION}；内核 ${KERNEL}"
}

create_cluster() {
  log "删除同名旧群（保证可重复）：kind delete cluster --name $CLUSTER_NAME"
  kind delete cluster --name "$CLUSTER_NAME" >/dev/null 2>&1 || true
  cat > "$WORK/kind-config.yaml" <<EOF
kind: Cluster
apiVersion: kind.x-k8s.io/v1alpha4
name: ${CLUSTER_NAME}
networking:
  disableDefaultCNI: true
  podSubnet: "${KIND_POD_CIDR}"
EOF
  if [ -n "$KIND_NODE_IMAGE" ]; then
    printf 'nodes:\n- role: control-plane\n  image: %s\n' "$KIND_NODE_IMAGE" >> "$WORK/kind-config.yaml"
  fi
  log "建群（disableDefaultCNI，策略 CNI 由后续步骤安装）"
  kind create cluster --config "$WORK/kind-config.yaml" --wait "${WAIT_TIMEOUT_S}s" >/dev/null
}

install_calico() {
  log "安装 Calico（NetworkPolicy 执行前提）：$CALICO_MANIFEST"
  if [ -f "$CALICO_MANIFEST" ]; then
    cp "$CALICO_MANIFEST" "$WORK/calico.yaml"     # 支持离线/镜像本地清单
  else
    curl -fsSL "$CALICO_MANIFEST" -o "$WORK/calico.yaml"
  fi
  sed -i "s#192.168.0.0/16#${KIND_POD_CIDR}#" "$WORK/calico.yaml"
  kubectl apply -f "$WORK/calico.yaml" >/dev/null
  kubectl -n kube-system rollout status daemonset/calico-node --timeout="${WAIT_TIMEOUT_S}s" >/dev/null
  kubectl wait --for=condition=Ready node --all --timeout="${WAIT_TIMEOUT_S}s" >/dev/null
  log "Calico 就绪，全部节点 Ready"
}

deploy_fixtures() {
  log "应用 default-deny（命名空间 + 全量拒绝）与靶标/探测 Pod"
  kubectl apply -f "$SCRIPT_DIR/default-deny-netpol.yaml" >/dev/null
  kubectl -n "$NAMESPACE" run proof-target --image="$TARGET_IMAGE" --restart=Never >/dev/null
  kubectl -n "$NAMESPACE" wait --for=condition=Ready pod/proof-target --timeout="${WAIT_TIMEOUT_S}s" >/dev/null
  kubectl -n "$NAMESPACE" expose pod proof-target --port=80 --name=proof-target >/dev/null
  kubectl -n "$NAMESPACE" run proof-normal --image="$PROBE_IMAGE" --restart=Never \
    --labels=app=proof-normal,trident.dev/proof=hostnetwork-bypass --command -- sleep infinity >/dev/null
  kubectl apply -f "$SCRIPT_DIR/hostnetwork-bypass.yaml" >/dev/null
  kubectl -n "$NAMESPACE" wait --for=condition=Ready pod/proof-normal --timeout="${WAIT_TIMEOUT_S}s" >/dev/null
  kubectl -n "$NAMESPACE" wait --for=condition=Ready pod/proof-hostnet --timeout="${WAIT_TIMEOUT_S}s" >/dev/null
  TARGET_POD_IP="$(kubectl -n "$NAMESPACE" get pod proof-target -o jsonpath='{.status.podIP}')"
  TARGET_SVC_IP="$(kubectl -n "$NAMESPACE" get svc proof-target -o jsonpath='{.spec.clusterIP}')"
  export TARGET_POD_IP TARGET_SVC_IP
  log "target 就绪：Pod IP=$TARGET_POD_IP ClusterIP=$TARGET_SVC_IP"
}

probe() {  # probe <pod> <url> → 设置 PROBE_RC / PROBE_CODE
  local pod="$1" url="$2" out rc
  set +e
  out="$(kubectl -n "$NAMESPACE" exec "$pod" -- \
    curl -sS -o /dev/null -m "$PROBE_TIMEOUT_S" -w '%{http_code}' "$url" 2>/dev/null)"
  rc=$?
  set -e
  PROBE_RC="$rc"
  PROBE_CODE="${out:-000}"
}

judge() {  # judge <rc> <code> → blocked|connected
  if [ "$1" = "0" ] && [ "$2" = "200" ]; then printf 'connected'; else printf 'blocked'; fi
}

run_probes() {
  local prefix
  for prefix in NORMAL_POD NORMAL_SVC HOSTNET_POD HOSTNET_SVC; do
    local pod url
    case "$prefix" in
      NORMAL_POD)  pod=proof-normal;  url="http://${TARGET_POD_IP}/" ;;
      NORMAL_SVC)  pod=proof-normal;  url="http://${TARGET_SVC_IP}/" ;;
      HOSTNET_POD) pod=proof-hostnet; url="http://${TARGET_POD_IP}/" ;;
      HOSTNET_SVC) pod=proof-hostnet; url="http://${TARGET_SVC_IP}/" ;;
    esac
    probe "$pod" "$url"
    export "${prefix}_RC=$PROBE_RC" "${prefix}_CODE=$PROBE_CODE" "${prefix}_JUDGE=$(judge "$PROBE_RC" "$PROBE_CODE")"
    log "探测 $pod -> $url : rc=$PROBE_RC http=$PROBE_CODE ($(judge "$PROBE_RC" "$PROBE_CODE"))"
  done
}

verdict_of() {
  local normal_blocked=0 hostnet_ok=0
  [ "$NORMAL_POD_JUDGE" = "blocked" ] || [ "$NORMAL_SVC_JUDGE" = "blocked" ] || normal_blocked=1
  { [ "$HOSTNET_POD_JUDGE" = "connected" ] || [ "$HOSTNET_SVC_JUDGE" = "connected" ]; } && hostnet_ok=1
  if [ "$normal_blocked" = "1" ]; then
    printf 'environment-invalid（普通 Pod 仍连通：NetworkPolicy 未被执行——检查 Calico 就绪与 kube-proxy 模式）'
    return 2
  fi
  if [ "$hostnet_ok" = "1" ]; then
    printf 'bypass-confirmed（普通 Pod 被 default-deny 拒绝，hostNetwork Pod 连通：旁路成立）'
    return 0
  fi
  printf 'bypass-not-observed（两类 Pod 均被拒：该 CNI 版本对宿主路径也执行了策略；记录现象并复核 CNI 语义）'
  return 1
}

main() {
  require_tools
  create_cluster
  install_calico
  deploy_fixtures
  run_probes
  local verdict rc notes="无"
  verdict="$(verdict_of)" && rc=0 || rc=$?
  if [ "$rc" = "2" ]; then notes="对照组失败优先视为环境无效，不算旁路证伪"; fi
  write_conclusion "$verdict" "$notes"
  if [ "$KEEP" != "1" ]; then
    log "清理集群（--keep 可保留现场）"
    kind delete cluster --name "$CLUSTER_NAME" >/dev/null 2>&1 || true
  else
    log "保留现场：kubectl -n $NAMESPACE get pods -o wide"
  fi
  exit "$rc"
}

main
