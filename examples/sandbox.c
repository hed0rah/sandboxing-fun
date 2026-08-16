/* sandbox.c -- defense in depth from inside your own process.
 *
 * Demonstrates the three self-restriction primitives, in the order they must be
 * applied:
 *
 *   1. PR_SET_NO_NEW_PRIVS   must come first. landlock and unprivileged seccomp
 *                            both refuse to install without it, because without
 *                            it a setuid binary could execve away the whole
 *                            sandbox.
 *   2. landlock              path-based filesystem policy. expresses what seccomp
 *                            cannot: seccomp sees syscall numbers and scalar args
 *                            and may not deref a pointer (TOCTOU), so "deny
 *                            open(/etc/shadow)" is not a seccomp rule.
 *   3. seccomp-bpf           syscall surface reduction. checks arch FIRST, see below.
 *
 * Then execv. Restrictions survive exec, which is the point: the target binary is
 * born already confined.
 *
 * This is the "restrict myself" model. It composes with, and does not replace,
 * the namespace model (bwrap) -- this program has no mount/pid/net isolation.
 * Real confinement is usually both.
 *
 *   cc -Wall -O2 sandbox.c -o sandbox
 *   ./sandbox /usr /usr/bin/whoami          # works
 *   ./sandbox /usr /usr/bin/cat /etc/shadow # landlock denies the read
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <stddef.h>
#include <stdint.h>
#include <sys/prctl.h>
#include <sys/syscall.h>
#include <linux/filter.h>
#include <linux/seccomp.h>
#include <linux/audit.h>

#if __has_include(<linux/landlock.h>)
#  include <linux/landlock.h>
#  define HAVE_LANDLOCK 1
#endif

/* landlock has no glibc wrappers; call through syscall(2). */
#ifdef HAVE_LANDLOCK
static inline int ll_create_ruleset(const struct landlock_ruleset_attr *attr,
                                    size_t size, uint32_t flags) {
	return (int)syscall(__NR_landlock_create_ruleset, attr, size, flags);
}
static inline int ll_add_rule(int fd, enum landlock_rule_type type,
                              const void *attr, uint32_t flags) {
	return (int)syscall(__NR_landlock_add_rule, fd, type, attr, flags);
}
static inline int ll_restrict_self(int fd, uint32_t flags) {
	return (int)syscall(__NR_landlock_restrict_self, fd, flags);
}
#endif

/* 1. no_new_privs: execve can never gain privileges from here on. */
static int step_no_new_privs(void) {
	if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) < 0) {
		perror("prctl(PR_SET_NO_NEW_PRIVS)");
		return -1;
	}
	puts("[+] no_new_privs set");
	return 0;
}

/* 2. landlock: allow read+execute beneath one directory, deny the rest of the fs.
 *
 * The handled_access_fs set is what we take responsibility for; anything listed
 * there is DENIED unless a rule re-permits it. Access rights not listed are
 * untouched, which is why this program cannot restrict writes it never named.
 *
 * ABI versions matter: each kernel added rights, and asking for a right the
 * running kernel does not know is an error. Query the version and mask down.
 */
static int step_landlock(const char *allowed_path) {
#ifndef HAVE_LANDLOCK
	fputs("[!] built without linux/landlock.h, skipping\n", stderr);
	(void)allowed_path;
	return 0;
#else
	int abi = ll_create_ruleset(NULL, 0, LANDLOCK_CREATE_RULESET_VERSION);
	if (abi < 0) {
		if (errno == ENOSYS || errno == EOPNOTSUPP) {
			fputs("[!] landlock unsupported by this kernel, skipping\n", stderr);
			return 0;   /* soft-fail: seccomp + no_new_privs still apply */
		}
		perror("landlock_create_ruleset(version)");
		return -1;
	}
	printf("[+] landlock ABI v%d\n", abi);

	uint64_t rights = LANDLOCK_ACCESS_FS_READ_FILE |
	                  LANDLOCK_ACCESS_FS_READ_DIR  |
	                  LANDLOCK_ACCESS_FS_EXECUTE;

	struct landlock_ruleset_attr rs = { .handled_access_fs = rights };
	int rfd = ll_create_ruleset(&rs, sizeof(rs), 0);
	if (rfd < 0) { perror("landlock_create_ruleset"); return -1; }

	int pfd = open(allowed_path, O_PATH | O_CLOEXEC);
	if (pfd < 0) { perror("open(allowed_path)"); close(rfd); return -1; }

	struct landlock_path_beneath_attr pb = {
		.allowed_access = rights,
		.parent_fd      = pfd,
	};
	if (ll_add_rule(rfd, LANDLOCK_RULE_PATH_BENEATH, &pb, 0) < 0) {
		perror("landlock_add_rule"); close(pfd); close(rfd); return -1;
	}
	close(pfd);

	if (ll_restrict_self(rfd, 0) < 0) {
		perror("landlock_restrict_self"); close(rfd); return -1;
	}
	close(rfd);
	printf("[+] landlock: read+exec allowed only beneath %s\n", allowed_path);
	return 0;
#endif
}

/* 3. seccomp: a hand-written cBPF program.
 *
 * THE ARCH CHECK IS NOT OPTIONAL. x86_64 kernels also accept i386 syscalls via
 * int 0x80, where the numbers mean different things -- __NR_ptrace on x86_64 is
 * some unrelated call on i386. A filter that does not verify arch first can be
 * walked straight around by issuing 32-bit syscalls. libseccomp inserts this
 * check for you; hand-rolled filters must do it themselves, and forgetting is
 * the classic seccomp bug.
 *
 * Denylist here for brevity. A real policy is an allowlist with a default of
 * ERRNO(EPERM) rather than KILL: killing on an unlisted syscall means the next
 * glibc update that calls something new turns into a crash instead of a
 * degraded path.
 */
static int step_seccomp(void) {
	struct sock_filter filter[] = {
		/* arch must match, or kill */
		BPF_STMT(BPF_LD  | BPF_W | BPF_ABS, offsetof(struct seccomp_data, arch)),
		BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, AUDIT_ARCH_X86_64, 1, 0),
		BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_KILL_PROCESS),

		BPF_STMT(BPF_LD  | BPF_W | BPF_ABS, offsetof(struct seccomp_data, nr)),

		/* process inspection / injection */
		BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_ptrace,            0, 1),
		BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_KILL_PROCESS),
		BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_process_vm_readv,  0, 1),
		BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_KILL_PROCESS),
		BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_process_vm_writev, 0, 1),
		BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_KILL_PROCESS),

		/* large, historically bug-dense kernel surfaces */
		BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_bpf,               0, 1),
		BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_KILL_PROCESS),
		BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_userfaultfd,       0, 1),
		BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_KILL_PROCESS),
#ifdef __NR_io_uring_setup
		BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_io_uring_setup,    0, 1),
		BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_KILL_PROCESS),
#endif

		BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
	};
	struct sock_fprog prog = {
		.len    = (unsigned short)(sizeof(filter) / sizeof(filter[0])),
		.filter = filter,
	};
	if (prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &prog) < 0) {
		perror("prctl(PR_SET_SECCOMP)");
		return -1;
	}
	puts("[+] seccomp: arch pinned; ptrace/process_vm_*/bpf/userfaultfd/io_uring killed");
	return 0;
}

int main(int argc, char *argv[]) {
	if (argc < 3) {
		fprintf(stderr,
		        "usage: %s <allowed-dir> <binary> [args...]\n"
		        "  e.g. %s /usr /usr/bin/whoami\n", argv[0], argv[0]);
		return EXIT_FAILURE;
	}
	const char *allowed = argv[1];
	char **child = &argv[2];

	if (step_no_new_privs() < 0) return EXIT_FAILURE;   /* order matters */
	if (step_landlock(allowed) < 0) return EXIT_FAILURE;
	if (step_seccomp() < 0) return EXIT_FAILURE;

	printf("[*] exec %s\n\n", child[0]);
	execv(child[0], child);
	perror("execv");                                     /* only on failure */
	return EXIT_FAILURE;
}
