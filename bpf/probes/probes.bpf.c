// +build ignore

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

char LICENSE[] SEC("license") = "Dual BSD/GPL";

#define MAX_COMM_LEN 64
#define MAX_ARGS_LEN 256
#define MAX_FILENAME_LEN 256
#define MAX_PATH_LEN 256
#define MAX_IP_LEN 16
#define MAX_EVENT_TYPE 32

// 事件类型
enum event_type {
    EVENT_EXECVE    = 1,
    EVENT_OPEN      = 2,
    EVENT_CONNECT   = 3,
};

// execve 事件结构（显式填充确保跨语言内存布局一致）
struct execve_event {
    u32 type;       // event_type
    u32 pid;
    u32 ppid;
    u32 tid;
    u64 timestamp;
    char comm[MAX_COMM_LEN];
    char filename[MAX_FILENAME_LEN];
    char args[MAX_ARGS_LEN];
    u32 cgroup_id;
    u32 _pad;       // 对齐到 8 字节边界
};

// open 事件结构（显式填充确保跨语言内存布局一致）
struct open_event {
    u32 type;       // event_type
    u32 pid;
    u32 ppid;
    u32 tid;
    u64 timestamp;
    char comm[MAX_COMM_LEN];
    char path[MAX_PATH_LEN];
    s32 flags;
    u32 cgroup_id;
    u32 _pad;       // 对齐到 8 字节边界
};

// connect 事件结构（显式填充确保跨语言内存布局一致）
struct connect_event {
    u32 type;       // event_type
    u32 pid;
    u32 ppid;
    u32 tid;
    u64 timestamp;
    char comm[MAX_COMM_LEN];
    u8 ip_version;  // 4=IPv4, 6=IPv6
    u8 _pad1[3];    // 对齐 IP 字段到 4 字节边界
    u8 ip[MAX_IP_LEN];
    u16 port;
    u16 _pad2;      // 对齐 cgroup_id 到 4 字节边界
    u32 cgroup_id;
};

// Ring Buffer 用于发送事件到用户态
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 24); // 16MB
} events SEC(".maps");

// ==================== execve 监控 ====================

SEC("tracepoint/syscalls/sys_enter_execve")
int trace_execve(struct trace_event_raw_sys_enter *ctx)
{
    struct execve_event *e;
    e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e)
        return 0;

    e->type = EVENT_EXECVE;
    e->pid = bpf_get_current_pid_tgid() >> 32;
    e->ppid = 0;
    e->tid = (u32)bpf_get_current_pid_tgid();
    e->timestamp = bpf_ktime_get_ns();
    e->cgroup_id = bpf_get_current_cgroup_id();

    bpf_get_current_comm(&e->comm, sizeof(e->comm));

    // 读取 filename 参数
    const char *filename = (const char *)ctx->args[0];
    bpf_probe_read_user_str(e->filename, sizeof(e->filename), filename);

    // 读取 argv[0]
    const char *const *argv = (const char *const *)ctx->args[1];
    const char *arg0 = NULL;
    bpf_probe_read_user(&arg0, sizeof(arg0), argv);
    if (arg0)
        bpf_probe_read_user_str(e->args, sizeof(e->args), arg0);

    bpf_ringbuf_submit(e, 0);
    return 0;
}

// ==================== open 监控 ====================

SEC("tracepoint/syscalls/sys_enter_openat")
int trace_openat(struct trace_event_raw_sys_enter *ctx)
{
    struct open_event *e;
    e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e)
        return 0;

    e->type = EVENT_OPEN;
    e->pid = bpf_get_current_pid_tgid() >> 32;
    e->ppid = 0;
    e->tid = (u32)bpf_get_current_pid_tgid();
    e->timestamp = bpf_ktime_get_ns();
    e->cgroup_id = bpf_get_current_cgroup_id();
    e->flags = (s32)ctx->args[2];

    bpf_get_current_comm(&e->comm, sizeof(e->comm));

    // 读取路径参数
    const char *pathname = (const char *)ctx->args[1];
    bpf_probe_read_user_str(e->path, sizeof(e->path), pathname);

    bpf_ringbuf_submit(e, 0);
    return 0;
}

// ==================== connect 监控 ====================

SEC("tracepoint/syscalls/sys_enter_connect")
int trace_connect(struct trace_event_raw_sys_enter *ctx)
{
    struct connect_event *e;
    struct sockaddr *addr = (struct sockaddr *)ctx->args[1];

    // 先读取 sa_family 判断是否为 IPv4/IPv6
    sa_family_t family;
    bpf_probe_read_user(&family, sizeof(family), &addr->sa_family);

    if (family != AF_INET && family != AF_INET6) {
        return 0;
    }

    e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e)
        return 0;

    e->type = EVENT_CONNECT;
    e->pid = bpf_get_current_pid_tgid() >> 32;
    e->ppid = 0;
    e->tid = (u32)bpf_get_current_pid_tgid();
    e->timestamp = bpf_ktime_get_ns();
    e->cgroup_id = bpf_get_current_cgroup_id();

    bpf_get_current_comm(&e->comm, sizeof(e->comm));

    if (family == AF_INET) {
        e->ip_version = 4;
        struct sockaddr_in *sin = (struct sockaddr_in *)addr;
        bpf_probe_read_user(&e->port, sizeof(e->port), &sin->sin_port);
        bpf_probe_read_user(e->ip, 4, &sin->sin_addr);
    } else {
        e->ip_version = 6;
        struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *)addr;
        bpf_probe_read_user(&e->port, sizeof(e->port), &sin6->sin6_port);
        bpf_probe_read_user(e->ip, 16, &sin6->sin6_addr);
    }

    bpf_ringbuf_submit(e, 0);
    return 0;
}
