# sandboxing-fun

Tools and reference for Linux process isolation. Distro-agnostic, primitives first.

**[Sandboxing Deep Dive](sandboxing-overview.html)** -- the reference page.
Mirrored at [hed0rah.github.io/sandboxing/sandboxing_deep-dive.html](https://hed0rah.github.io/sandboxing/sandboxing_deep-dive.html).

## the one idea

Linux has no sandbox syscall, no sandbox object, no sandbox subsystem. It has **five
independent primitives**, none of which was designed as a security boundary on its own:

| primitive | controls | since |
|---|---|---|
| namespaces | what a process can **see** | 2.4-4.6 |
| capabilities | which of root's **powers** it holds | 2.2 |
| seccomp-bpf | which **syscalls** it may issue | 3.5 |
| cgroups v2 | how much **resource** it consumes | 4.5 |
| Landlock | which **files** it may touch, unprivileged (TCP ports too, since 6.7) | 5.13 |

`bwrap`, `firejail`, `nsjail`, `podman` and `systemd` each wire some subset of those five
together with different defaults. Read a `docker run` flag, a firejail profile line or a
bwrap argument and it resolves to one of the five. Learn them in that order and the tools
document themselves.

## tools

### `check`

What can this kernel actually sandbox, and what is blocking you?

```sh
./check
```

Reports every primitive's availability, and when something is unavailable, **names the
cause and the fix**. Written because unprivileged user namespaces are gated differently on
every distribution and the error message names none of the responsible subsystems:

```
bwrap:   setting up uid map: Permission denied
unshare: write failed /proc/self/uid_map: Operation not permitted
```

That can be an LSM policy, a global sysctl, a zeroed quota, SELinux, or an outer container's
seccomp profile. `check` probes the capability directly rather than guessing from one knob,
then explains what it found.

### `escape-test`

Runs assertions **inside** a sandbox and reports what leaked.

```sh
./escape-test                              # grade the built-in bwrap default
./escape-test -- <your sandbox cmd> /bin/sh
./escape-test --profile net-agent -- ...   # network required, everything else denied
./escape-test -- /bin/sh                   # negative control: no sandbox at all
```

Feeds a probe script to a shell inside your sandbox and grades the results against a
profile, because "no network" is a pass for a file analyser and a failure for an agent.
Exit status is nonzero when anything leaked, so it drops into a pre-commit hook or CI.

Run the negative control first. On an ordinary desktop shell it reports the session bus
and the docker socket, both of which are host takeover in one command, and both of which
survive a sandbox that only unshares namespaces.

Three deliberate design decisions, each of which came from the tool getting it wrong:

- **Probes use shell builtins and `/proc`, nothing else.** A sandbox is a minimal
  filesystem by definition. The first version parsed `/proc/self/status` with `awk`, and
  `awk` on Debian and Ubuntu is a symlink through `/etc/alternatives`, so in a sandbox
  without `/etc` bound it disappears. The probe read an empty string and reported a
  `no_new_privs` leak that did not exist. A security tool that invents findings when its
  own helper is missing is worse than one that does not run.
- **A probe that cannot run reports `unknown`, never `no`.** Absence of evidence gets its
  own state and never counts as a pass.
- **Writable is only a leak if the directory is the host's.** `--ro-bind /etc/resolv.conf`
  makes bwrap create `/etc` as a writable tmpfs to hang the bind on, and `/` under bwrap
  is an ephemeral tmpfs too. Both are writable, neither is an escape. Each write probe
  checks a sentinel (`/etc/passwd`, `/usr/bin`) to tell the host copy from the scaffold.

### `nsview`

Which namespaces is a process in, and are they its own?

```sh
./nsview                      # this process
./nsview 1
./nsview --compare 1 self
bwrap ... /path/to/nsview     # run it INSIDE a sandbox to prove isolation
```

`/proc/<pid>/ns/<type>` reads `type:[inode]`, and two processes share a namespace exactly
when the inode matches. The part that makes this a tool rather than a `readlink` is that
the kernel gives each **initial** namespace a fixed, documented inode
(`include/linux/ns_common.h`, `MNT_NS_INIT_INO` through `IPC_NS_INIT_INO`, `0xEFFFFFF8` to
`0xEFFFFFFF`). A process can therefore decide entirely on its own, with nothing to compare
against, whether it sits in the host's original namespace or one created for it.

That matters because counting entries in `/proc` is a guess and an inode comparison is a
fact. Pointed at a `bwrap --unshare-all` sandbox it reports 7 of 8 unshared, and names the
one that is not: **`--unshare-all` does not include the time namespace.**

### `capdecode`

Decode a process's capability sets without libcap.

```sh
./capdecode            # this process
./capdecode 1
./capdecode --hex 00000000a80425fb     # docker's default set
./capdecode --all      # every pid holding a capability
```

`capsh --decode` does this, but it ships in `libcap2-bin` / `libcap-progs` / `libcap` and is
absent from exactly the minimal images where you are squinting at a raw `CapEff`. Output is
byte-identical to `capsh` and runs under busybox ash.

It prints all five sets, because the two that get quoted are the two that matter least:

| set | meaning |
|---|---|
| `CapEff` | what the kernel checks right now |
| `CapPrm` | what may be moved into Eff unaided |
| `CapBnd` | the ceiling on `execve`. **This is what makes a drop stick** |
| `CapInh` | what survives `execve` of a non-setuid binary |
| `CapAmb` | Inh raised automatically, so it crosses a non-setuid exec |

A sandbox reporting `CapEff=0` with a full bounding set has dropped nothing durable: a
setuid binary or one carrying file capabilities raises them back on the next `execve`
unless `no_new_privs` is also set. `capdecode` says so explicitly when it sees that shape,
and flags the escape-grade capabilities (`sys_admin`, `sys_module`, `sys_rawio`,
`sys_ptrace`, `dac_read_search`, `bpf`, `mknod`, and the rest) rather than printing forty
names flat.

### `01_namespaces_by_hand.sh`

The five namespaces, one at a time, with nothing but `util-linux`. No bwrap, no daemons, no
config. Run it once and every sandbox tool becomes legible, because they are all presets
over exactly this.

## examples

### `examples/sandbox.c`

Self-restriction in C: `no_new_privs` -> Landlock -> seccomp -> `execv`. The order is
load-bearing; Landlock and unprivileged seccomp both refuse to install without
`no_new_privs` already set.

```sh
cd examples && make
./sandbox /usr /usr/bin/whoami
./sandbox /usr /usr/bin/cat /etc/shadow      # denied
```

Read the first result carefully: `whoami` fails with
`cannot find name for user ID 1000: Permission denied`, because it wants `/etc/passwd`,
which is not beneath `/usr`. Landlock is working exactly as instructed. That is the real
cost of path policy, and the same incompleteness that makes observation-derived seccomp
profiles unreliable.

Then try a binary that *is* beneath the allowed path but dynamically linked. It still fails
`execv: Permission denied`, because Landlock gates the **ELF interpreter** as well, and
`/lib64/ld-linux-x86-64.so.2` is not under `/usr`. Static binaries run; dynamic ones need
their loader and libraries inside the scope. This surprises people the first time and is
the same lesson as `whoami` above, one layer down.

The seccomp filter **pins the architecture before reading the syscall number**. Omit that
and a 32-bit `int 0x80` call walks straight around a 64-bit filter. It is the classic
hand-rolled seccomp bug.

Pinning the arch is still not sufficient on x86_64, which is the subtler half. The **x32
ABI reports the same `AUDIT_ARCH_X86_64`** but sets bit 30 (`__X32_SYSCALL_BIT`) in the
syscall number, so x32 `ptrace` arrives as `0x40000065`, matches none of the numbers in the
denylist, falls through every comparison and lands on `RET_ALLOW`. This file had that bug.
The filter now rejects any `nr >= 0x40000000` outright. It is unreachable on kernels built
without `CONFIG_X86_X32_ABI`, which is most of them now, and a complete bypass on the rest.

### `examples/agent-box.example`

The inverted threat model. Most sandboxing assumes you want to stop a process reaching the
network. An LLM agent **must** reach the network, so the goal flips: you cannot stop it
talking out, so make sure nothing worth stealing is in reach.

```
--unshare-all --share-net     isolate everything EXCEPT the network
--bind /home/agent            the only writable path
--ro-bind /etc/ssl            tls trust store, or every api call fails
--cap-drop ALL --new-session
```

Run it as a **separate uid** as well. Two independent layers, so a full sandbox bypass
still lands somewhere with nothing in it.

## the three escapes worth knowing

None involve a kernel bug. All three defeat an otherwise correct sandbox.

1. **D-Bus.** Bind the session bus in for compatibility and the sandbox can call
   `org.freedesktop.Flatpak.Development.HostCommand` to run a process **on the host**.
   That is what `flatpak-spawn --host` uses (cf. CVE-2019-10063). Namespaces, caps and
   seccomp all intact and all irrelevant. Note this is not the same as
   `org.freedesktop.portal.Flatpak.Spawn`, which by default spawns into another sandbox.
   Use `xdg-dbus-proxy` or do not mount the bus.
2. **TIOCSTI.** A process sharing your pty can inject characters into the parent shell's
   input buffer, which run as you afterwards. Fix: a fresh session (`--new-session`,
   which bwrap's man page ties to CVE-2017-5226). Since 6.2 the `dev.tty.legacy_tiocsti`
   sysctl gates the ioctl behind `CAP_SYS_ADMIN`, and mainstream distros now ship it off,
   so on a current kernel this is already dead. Keep `--new-session` for the older ones.
3. **`/proc` without a pid namespace.** A fresh `/proc` alone still lists host processes,
   so the sandbox reads `/proc/<pid>/environ` for secrets. The two flags are a pair.

## test the negative case

A sandbox you have not tried to break is a hope, not a control. That is what `escape-test`
is for: point it at whatever you built and read the LEAK lines.

Grade against intent. The same result is a pass or a failure depending on the job, which is
why the tool takes a profile rather than a fixed list.

## license

MIT.
