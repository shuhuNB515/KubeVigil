package k8s

import (
	"context"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
)

// PodInfo Pod 信息
type PodInfo struct {
	Namespace string
	Name      string
	UID       string
	Container string
}

// Resolver 将 PID 映射到 K8s Pod
type Resolver struct {
	clientset     *kubernetes.Clientset
	pidToPod      map[uint32]*PodInfo
	cgroupToPod   map[uint32]*PodInfo
	containerUIDs map[string]string // containerID -> podUID 映射
	mu            sync.RWMutex
	nodeName      string
}

// NewResolver 创建 Resolver
func NewResolver() (*Resolver, error) {
	config, err := rest.InClusterConfig()
	if err != nil {
		// 尝试使用 kubeconfig
		kubeconfig := filepath.Join(os.Getenv("HOME"), ".kube", "config")
		config, err = clientcmd.BuildConfigFromFlags("", kubeconfig)
		if err != nil {
			return nil, fmt.Errorf("无法创建 K8s 客户端配置: %w", err)
		}
	}

	clientset, err := kubernetes.NewForConfig(config)
	if err != nil {
		return nil, fmt.Errorf("无法创建 K8s 客户端: %w", err)
	}

	nodeName := os.Getenv("NODE_NAME")
	if nodeName == "" {
		hostname, _ := os.Hostname()
		nodeName = hostname
	}

	r := &Resolver{
		clientset:     clientset,
		pidToPod:      make(map[uint32]*PodInfo),
		cgroupToPod:   make(map[uint32]*PodInfo),
		containerUIDs: make(map[string]string),
		nodeName:      nodeName,
	}

	return r, nil
}

// Start 启动 Resolver，定期同步 Pod 信息
func (r *Resolver) Start(ctx context.Context) {
	// 首次同步
	r.syncPods(ctx)

	// 定期同步
	ticker := time.NewTicker(10 * time.Second)
	go func() {
		for {
			select {
			case <-ctx.Done():
				ticker.Stop()
				return
			case <-ticker.C:
				r.syncPods(ctx)
			}
		}
	}()
}

// syncPods 同步当前节点上的 Pod 信息
func (r *Resolver) syncPods(ctx context.Context) {
	pods, err := r.clientset.CoreV1().Pods("").List(ctx, metav1.ListOptions{
		FieldSelector: fmt.Sprintf("spec.nodeName=%s", r.nodeName),
	})
	if err != nil {
		log.Printf("[K8s] 同步 Pod 信息失败: %v", err)
		return
	}

	r.mu.Lock()
	defer r.mu.Unlock()

	// 清空旧映射
	newPidToPod := make(map[uint32]*PodInfo)
	newCgroupToPod := make(map[uint32]*PodInfo)
	newContainerUIDs := make(map[string]string)

	for i := range pods.Items {
		pod := &pods.Items[i]
		podInfo := &PodInfo{
			Namespace: pod.Namespace,
			Name:      pod.Name,
			UID:       string(pod.UID),
		}

		// 遍历容器状态，获取 PID 和 cgroup 映射
		for _, cs := range pod.Status.ContainerStatuses {
			if cs.State.Running != nil {
				containerID := extractContainerID(cs.ContainerID)
				if containerID != "" {
					// 记录 containerID -> podUID 映射
					newContainerUIDs[containerID] = string(pod.UID)

					// 从 cgroup ID 映射
					newCgroupToPod[uint32(hashContainerID(containerID))] = podInfo

					// 从 cgroup 读取容器内进程 PID
					pids := r.findPidsForContainer(containerID, string(pod.UID))
					for _, pid := range pids {
						newPidToPod[pid] = podInfo
					}
				}
			}
		}
	}

	r.pidToPod = newPidToPod
	r.cgroupToPod = newCgroupToPod
	r.containerUIDs = newContainerUIDs
}

// findPidsForContainer 从 cgroup proc 文件中读取容器内所有 PID
func (r *Resolver) findPidsForContainer(containerID string, podUID string) []uint32 {
	pidSet := make(map[uint32]struct{})

	// 尝试多种 cgroup 路径模式（覆盖 cgroup v1/v2 + 不同运行时）
	cgroupPaths := []string{
		// cgroup v1: kubepods
		fmt.Sprintf("/sys/fs/cgroup/cpu/kubepods/pod%s/%s/cgroup.procs", podUID, containerID),
		fmt.Sprintf("/sys/fs/cgroup/cpu/kubepods.slice/pod%s.slice/%s/cgroup.procs", podUID, containerID),
		// cgroup v2: unified hierarchy
		fmt.Sprintf("/sys/fs/cgroup/kubepods/pod%s/%s/cgroup.procs", podUID, containerID),
		fmt.Sprintf("/sys/fs/cgroup/kubepods.slice/pod%s.slice/%s/cgroup.procs", podUID, containerID),
		// containerd 风格
		fmt.Sprintf("/sys/fs/cgroup/cpu/kubepods/pod%s/cri-containerd-%s/cgroup.procs", podUID, containerID),
		// cgroup v2 system.slice
		fmt.Sprintf("/sys/fs/cgroup/system.slice/containerd.service/%s/cgroup.procs", containerID),
	}

	for _, path := range cgroupPaths {
		data, err := os.ReadFile(path)
		if err != nil {
			continue
		}
		for _, line := range strings.Split(string(data), "\n") {
			line = strings.TrimSpace(line)
			if line == "" {
				continue
			}
			var pid uint32
			if _, err := fmt.Sscanf(line, "%d", &pid); err == nil && pid > 0 {
				pidSet[pid] = struct{}{}
			}
		}
	}

	pids := make([]uint32, 0, len(pidSet))
	for pid := range pidSet {
		pids = append(pids, pid)
	}
	return pids
}

// getPodUIDForContainer 根据 containerID 查找 Pod UID
func (r *Resolver) getPodUIDForContainer(containerID string) string {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.containerUIDs[containerID]
}

// ResolveByPID 通过 PID 解析 Pod 信息
func (r *Resolver) ResolveByPID(pid uint32) *PodInfo {
	r.mu.RLock()
	defer r.mu.RUnlock()

	if pod, ok := r.pidToPod[pid]; ok {
		return pod
	}
	return nil
}

// ResolveByCgroup 通过 cgroup ID 解析 Pod 信息
func (r *Resolver) ResolveByCgroup(cgroupID uint32) *PodInfo {
	r.mu.RLock()
	defer r.mu.RUnlock()

	if pod, ok := r.cgroupToPod[cgroupID]; ok {
		return pod
	}
	return nil
}

// IsolatePod 隔离 Pod（打标签）
func (r *Resolver) IsolatePod(ctx context.Context, namespace, podName, labelKey, labelValue string) error {
	pod, err := r.clientset.CoreV1().Pods(namespace).Get(ctx, podName, metav1.GetOptions{})
	if err != nil {
		return fmt.Errorf("获取 Pod 失败: %w", err)
	}

	if pod.Labels == nil {
		pod.Labels = make(map[string]string)
	}
	pod.Labels[labelKey] = labelValue

	_, err = r.clientset.CoreV1().Pods(namespace).Update(ctx, pod, metav1.UpdateOptions{})
	if err != nil {
		return fmt.Errorf("更新 Pod 标签失败: %w", err)
	}

	log.Printf("[K8s] 已隔离 Pod: %s/%s (标签: %s=%s)", namespace, podName, labelKey, labelValue)
	return nil
}

// KillPod 终止 Pod
func (r *Resolver) KillPod(ctx context.Context, namespace, podName string) error {
	err := r.clientset.CoreV1().Pods(namespace).Delete(ctx, podName, metav1.DeleteOptions{
		GracePeriodSeconds: int64Ptr(0),
	})
	if err != nil {
		return fmt.Errorf("删除 Pod 失败: %w", err)
	}

	log.Printf("[K8s] 已终止 Pod: %s/%s", namespace, podName)
	return nil
}

// extractContainerID 从 containerID 字符串中提取 ID
// 例如: containerd://abc123 -> abc123
func extractContainerID(containerID string) string {
	// 去掉 runtime 前缀
	for i := len(containerID) - 1; i >= 0; i-- {
		if containerID[i] == '/' {
			return containerID[i+1:]
		}
	}
	return containerID
}

// hashContainerID 使用 FNV-1a 哈希将 containerID 映射到 uint32
func hashContainerID(id string) uint32 {
	h := uint32(2166136261)
	for _, c := range id {
		h ^= uint32(c)
		h *= 16777619
	}
	return h
}

func int64Ptr(i int64) *int64 {
	return &i
}
