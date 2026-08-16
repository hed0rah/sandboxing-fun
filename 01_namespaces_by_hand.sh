#!/usr/bin/env bash
# 01 -- the five namespaces, one at a time, with nothing but util-linux.
#
# No bwrap, no docker, no config files. Every "sandbox" tool is a preset over
# what this script does by hand. Run it once and the rest of the field becomes
# readable.
#
#   ./01_namespaces_by_hand.sh
#
# On ubuntu 23.10+ unprivileged user namespaces are restricted by apparmor
# (kernel.apparmor_restrict_unprivileged_userns=1) and the unshare calls below
# will fail with "Operation not permitted" on /proc/self/uid_map. See 00_check.sh.

set -u
say(){ printf '\n\033[1m== %s ==\033[0m\n' "$1"; }
try(){ printf '  $ %s\n' "$*"; "$@" 2>&1 | sed 's/^/    /'; }

say "who am i, outside"
try id -u
try hostname

say "USER ns -- become root without being root"
# the keystone. inside, uid 0 with a full capability set; outside, still you.
# this is what makes every other unprivileged namespace possible.
try unshare --user --map-root-user id
echo "    ^ uid 0 inside. check 'ps -o uid' from another terminal: still your uid outside."

say "UTS ns -- your own hostname"
try unshare --user --map-root-user --uts sh -c 'hostname sandbox; hostname'
try hostname
echo "    ^ the host's hostname is untouched."

say "NET ns -- the cheapest strong isolation there is"
# an empty net namespace has exactly one interface: lo, and it is down.
# for analysing hostile input this is the whole ballgame: the process cannot
# phone home because there is no route, no interface, nothing to configure.
try unshare --user --map-root-user --net ip addr
echo "    ^ no eth0, no wifi. nothing to exfiltrate through."

say "PID ns -- your process tree starts at 1"
# needs --fork (the new ns applies to a CHILD) and --mount-proc, or ps still
# reads the host's /proc and you see everything.
try unshare --user --map-root-user --pid --fork --mount-proc sh -c 'ps -e | head -5; echo "    total: $(ps -e | wc -l) processes"'
echo "    ^ compare: this host has $(ps -e | wc -l) processes."

say "MOUNT ns -- a filesystem nobody else sees"
try unshare --user --map-root-user --mount sh -c 'mkdir -p /tmp/nsdemo && mount -t tmpfs none /tmp/nsdemo && touch /tmp/nsdemo/ghost && ls /tmp/nsdemo'
try ls /tmp/nsdemo
echo "    ^ the file vanished with the namespace. the mount was never visible outside."

say "IPC ns -- separate shared memory and message queues"
try unshare --user --map-root-user --ipc ipcs -q

say "all of them at once -- this is 'a sandbox'"
cat <<'EOF'
    $ unshare --user --map-root-user --net --pid --fork --mount-proc --uts --ipc bash

    That single line is the core of what bwrap, firejail, nsjail and podman do.
    Everything else those tools add is: which paths get bind-mounted in, which
    capabilities get dropped, and which syscalls get filtered.
EOF

say "what is still NOT protected"
cat <<'EOF'
    Namespaces control what a process can SEE. They do not control which kernel
    APIs it may CALL. Inside all six namespaces above, a process can still issue
    every syscall on the system, including the buggy ones.

    That is seccomp's job -- see 03, and examples/sandbox.c.
EOF
