# Linux Kernel Crash Dump Forensics: Malicious Kernel Module Investigation

Memory forensics investigation of a crashed Ubuntu 22.04 server, using the `crash` utility to analyze a `kdump` vmcore. The goal: find out what crashed the kernel, which module was responsible, who triggered it, and when.

## Overview

| Item | Value |
|---|---|
| Evidence | `ubuntu22_04-5_15_0-25-generic-202511032103.kdump` |
| OS / Kernel | Ubuntu 22.04, Linux 5.15.0-25-generic |
| Tool | [`crash`](https://github.com/crash-utility/crash) (kernel dump analysis) |
| Result | Kernel panic caused by a malicious kernel module (`core_helper`) via `/proc/jiffies_ext` |

## Summary of Findings

A malicious kernel module named **`core_helper`** registered a proc entry at **`/proc/jiffies_ext`**. When the file was read with `cat` by a process running under `sudo`, the module's read handler `core_helper_read` triggered a kernel oops (`Oops: 0002 [#1] SMP PTI`), crashing the server `ubuntu-2204` on **2025-11-04 at 03:03:29 UTC**.

## Investigation Q&A

### 1. Which proc entry belongs to the malicious kernel module?
**`jiffies_ext`**

This entry looks like a legitimate kernel timing file (`/proc/jiffies`-style), which makes it a good disguise.

### 2. What is the base memory address of the module?
**`ffffffffc0a94000`**

Resolved by looking up the module's symbols:

```
crash> sym core_helper_read
ffffffffc0a94000 (t) core_helper_read [core_helper]
```

### 3. What function in the malicious module performs cleanup?
**`core_helper_exit`**

This is the module's exit routine (the `module_exit` handler).

### 4. What suspicious process was running with sudo privileges before the panic?
**`bt`**

### 5. What function is at the top of the kernel call stack at the time of the crash?
**`core_helper_read`**

The faulting instruction is inside the malicious module's read handler, which confirms the module as the crash source.

### 6. What is the absolute path of the malicious file that caused the crash?
**`/proc/jiffies_ext`**

### 7. What was the fatal kernel panic message?
```
Oops: 0002 [#1] SMP PTI
```

### 8. Which command-line utility was used to trigger the crash?
**`cat`**

Simply reading the proc file was enough to invoke the faulty `core_helper_read` handler.

### 9. What was the PID of the process that caused the panic?
**`9236`**

### 10. When did the server crash (UTC)?
**`2025-11-04 03:03:29`**

### 11. What was the server's IP address at the time of crash?
**`192.168.1.135`**

### 12. What is the hostname of the crashed server?
**`ubuntu-2204`**

## Attack Chain Reconstruction

1. A malicious kernel module (`core_helper`) is loaded on `ubuntu-2204` (`192.168.1.135`).
2. The module creates `/proc/jiffies_ext`, disguised as a harmless timing file.
3. A process (`bt`) running with `sudo` privileges runs `cat /proc/jiffies_ext` (PID `9236`).
4. The kernel calls `core_helper_read`, which faults and produces `Oops: 0002 [#1] SMP PTI`.
5. The kernel panics at **2025-11-04 03:03:29 UTC** and kdump writes the vmcore.

## Crash Commands Used

Typical `crash` commands for this type of investigation:

| Command | Purpose |
|---|---|
| `sys` | Kernel version, hostname, panic string, crash time |
| `log` | Kernel ring buffer: oops message, registers, call trace, network info |
| `bt` | Backtrace of the crashing task: top function and PID |
| `ps` | Process list at crash time |
| `mod` | Loaded kernel modules (spot `core_helper`) |
| `sym <name>` | Resolve symbol addresses (e.g. `core_helper_read`) |
| `dis <func>` | Disassemble a function |

## Skills Demonstrated

- Linux kernel memory forensics with `crash` and `kdump`
- Kernel module and rootkit-style persistence analysis
- Reading oops messages and call stacks
- Timeline and artifact reconstruction (host, IP, PID, timestamp)
- Mapping findings into an incident narrative

## Disclaimer

This project was performed on a training/lab forensic image for educational purposes.
