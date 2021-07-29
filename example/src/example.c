#include "uapi/linux/bpf.h"
#include "bpf_helpers.h"

#define SEC(NAME) __attribute__((section(NAME), used))

#define PRINT(fmt, ...)                                                \
	(                                                                  \
		{                                                              \
			char ____fmt[] = fmt;                                      \
			bpf_trace_printk(____fmt, sizeof(____fmt), ##__VA_ARGS__); \
		})

struct sys_enter_args
{
	unsigned long long unused; // syscall preemble
	long id;
	unsigned long args[6];
};

SEC("tracepoint/on_sys_enter")
int on_sys_enter(struct sys_enter_args *ctx)
{
	uint64_t pid = bpf_get_current_pid_tgid() >> 32;

	PRINT("process %d executed syscall %d", pid, ctx->id);

	return 0;
}

char _license[] SEC("license") = "GPL";

unsigned int _version SEC("version") = 0xFFFFFFFE;