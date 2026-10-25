# Trident 提权检测覆盖（Purple Replay）

- 向量：47；命中：47；漏过：0
- 判定：PASS

| 向量 | 规则 | 引擎 | 紫队重放 | 检测点 |
|---|---|---|---|---|
| `rbac-escalate-verb` | `sigma-privesc-rbac-escalate-verb` | sigma | 命中 | K8s audit：update/patch clusterroles/roles 且新 rules.verbs 含 * |
| `rbac-bind-verb` | `sigma-privesc-rbac-bind-verb` | sigma | 命中 | K8s audit：创建/更新 roleRef=cluster-admin 的绑定 |
| `rbac-impersonate` | `sigma-privesc-rbac-impersonate` | sigma | 命中 | K8s audit：impersonatedUser 字段非空且执行敏感动作 |
| `rbac-sa-token-request` | `sigma-privesc-rbac-sa-token-request` | sigma | 命中 | K8s audit：create serviceaccounts/token 子资源 |
| `rbac-pods-exec` | `sigma-privesc-rbac-pods-exec` | sigma | 命中 | K8s audit：create pods/exec |
| `rbac-rolebinding-cluster-admin` | `sigma-privesc-rbac-rolebinding-cluster-admin` | sigma | 命中 | K8s audit：create rolebindings/clusterrolebindings |
| `rbac-aggregated-clusterrole` | `sigma-privesc-rbac-aggregated-clusterrole` | sigma | 命中 | K8s audit：创建/更新带 aggregationRule 的 ClusterRole |
| `rbac-admission-webhook-write` | `sigma-privesc-rbac-admission-webhook-write` | sigma | 命中 | K8s audit：创建/更新 admission webhook 配置 |
| `rbac-apiservice-hijack` | `sigma-privesc-rbac-apiservice-hijack` | sigma | 命中 | K8s audit：创建/更新 APIService 且 insecureSkipTLSVerify=true |
| `rbac-crd-conversion-webhook` | `sigma-privesc-rbac-crd-conversion-webhook` | sigma | 命中 | K8s audit：CRD 创建/更新且 conversion.strategy=Webhook |
| `workload-privileged-pod` | `sigma-privesc-workload-privileged-pod` | sigma | 命中 | K8s audit：create pod 且 privileged=true；Falco 亦覆盖 privileged 容器启动 |
| `workload-hostpath-hostroot` | `sigma-privesc-workload-hostpath-hostroot` | sigma | 命中 | K8s audit：create pod 且 hostPath 为 / 或敏感前缀 |
| `workload-hostpid-hostnetwork` | `sigma-privesc-workload-hostpid-hostnetwork` | sigma | 命中 | K8s audit：create pod 且 hostPID/hostNetwork/hostIPC=true |
| `workload-dangerous-caps` | `sigma-privesc-workload-dangerous-caps` | sigma | 命中 | K8s audit：create pod 且 capabilities 含 SYS_ADMIN/SYS_PTRACE/SYS_MODULE |
| `workload-ephemeral-container` | `sigma-privesc-workload-ephemeral-container` | sigma | 命中 | K8s audit：update pods/ephemeralcontainers |
| `workload-init-container-override` | `sigma-privesc-workload-init-container-override` | sigma | 命中 | K8s audit：create pod 且 initContainers 含 privileged/hostPath |
| `workload-hostpath-kubelet` | `sigma-privesc-workload-hostpath-kubelet` | sigma | 命中 | K8s audit：create pod 且 hostPath 指向 kubelet/kubernetes 目录 |
| `workload-hostpath-runtime-socket` | `falco-privesc-workload-hostpath-runtime-socket` | falco | 命中 | Falco：容器内进程打开容器运行时 socket |
| `workload-static-pod-write` | `falco-privesc-workload-static-pod-write` | falco | 命中 | Falco：写入 kubelet 静态 Pod 目录 |
| `cred-sa-token-automount` | `falco-privesc-cred-sa-token-automount` | falco | 命中 | Falco：容器读取 automount SA token |
| `cred-projected-token` | `sigma-privesc-cred-projected-token` | sigma | 命中 | K8s audit：create pod 且 volume 使用 projected serviceAccountToken |
| `cred-legacy-sa-secret` | `sigma-privesc-cred-legacy-sa-secret` | sigma | 命中 | K8s audit：读取 legacy SA token Secret |
| `cred-image-pull-secret` | `sigma-privesc-cred-image-pull-secret` | sigma | 命中 | K8s audit：读取 dockerconfigjson Secret |
| `cred-git-ci-token` | `falco-privesc-cred-git-ci-token` | falco | 命中 | Falco：容器/CI 读取 git 凭据文件 |
| `cred-ml-platform-token` | `sigma-privesc-cred-ml-platform-token` | sigma | 命中 | K8s audit：读取标注 ml-platform-token 的 Secret；平台侧审计 token 写入 |
| `cred-cloud-imds` | `falco-privesc-cred-cloud-imds` | falco | 命中 | Falco：容器连接云 metadata 地址 |
| `cred-cloud-federation` | `sigma-privesc-cred-cloud-federation` | sigma | 命中 | CloudTrail：跨账户 AssumeRole 且 trust policy 含通配 |
| `node-kubelet-10250-exec` | `falco-privesc-node-kubelet-10250-exec` | falco | 命中 | Falco/eBPF：非 kube-apiserver 主体连接 kubelet 10250 |
| `node-kubelet-10250-run` | `falco-privesc-node-kubelet-10250-run` | falco | 命中 | Falco：kubelet /run 端点访问 |
| `node-etcd-direct` | `falco-privesc-node-etcd-direct` | falco | 命中 | Falco/eBPF：非控制面进程连接 etcd 2379 |
| `node-proxy` | `sigma-privesc-node-proxy` | sigma | 命中 | K8s audit：get nodes/proxy |
| `node-runtime-socket` | `falco-privesc-node-runtime-socket` | falco | 命中 | Falco：容器内打开 docker/containerd socket |
| `node-kernel-runc` | `falco-privesc-node-kernel-runc` | falco | 命中 | Falco：runc 异常执行/文件描述符泄漏行为 |
| `node-host-root-kubeconfig` | `falco-privesc-node-host-root-kubeconfig` | falco | 命中 | Falco：容器/宿主进程读取 admin kubeconfig |
| `cred-privileged-sa-token-use` | `sigma-privesc-cred-privileged-sa-token-use` | sigma | 命中 | K8s audit：高权 SA 主体创建敏感绑定 |
| `platform-gpu-operator-driver` | `sigma-privesc-platform-gpu-operator-driver` | sigma | 命中 | K8s audit：更新 daemonset 且模板 privileged |
| `platform-device-plugin` | `sigma-privesc-platform-device-plugin` | sigma | 命中 | K8s audit：device plugin DaemonSet hostPath 变更 |
| `platform-cni-plugin` | `sigma-privesc-platform-cni-plugin` | sigma | 命中 | K8s audit：CNI DaemonSet hostPath /opt/cni/bin 变更 |
| `platform-csi-node-plugin` | `sigma-privesc-platform-csi-node-plugin` | sigma | 命中 | K8s audit：CSI node DaemonSet 特权/宿主挂载变更 |
| `platform-ingress-secret` | `sigma-privesc-platform-ingress-secret` | sigma | 命中 | K8s audit：Ingress 创建/更新含危险 annotation |
| `platform-cert-manager` | `sigma-privesc-platform-cert-manager` | sigma | 命中 | K8s audit：CSR approval 子资源更新 |
| `platform-argocd-flux` | `sigma-privesc-platform-argocd-flux` | sigma | 命中 | K8s audit：ArgoCD Application/Flux Kustomization 变更 |
| `platform-kueue-volcano` | `sigma-privesc-platform-kueue-volcano` | sigma | 命中 | K8s audit：队列/配额对象变更 |
| `platform-ray-kuberay-autoscaler` | `sigma-privesc-platform-ray-kuberay-autoscaler` | sigma | 命中 | K8s audit：创建 RayJob/RayCluster 且使用高权 SA |
| `platform-lws-operator` | `sigma-privesc-platform-lws-operator` | sigma | 命中 | K8s audit：LeaderWorkerSet 创建/更新 |
| `platform-jupyter-notebook` | `sigma-privesc-platform-jupyter-notebook` | sigma | 命中 | K8s audit：Jupyter SA 发起 pods/exec |
| `platform-mlflow-tracking` | `falco-privesc-platform-mlflow-tracking` | falco | 命中 | Falco：写入 MLflow artifact/模型目录 |
