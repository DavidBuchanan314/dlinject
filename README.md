# dlinject.py
Inject a shared library (i.e. arbitrary code) into a live linux process, without ptrace. Inspired by [Cexigua](https://github.com/AonCyberLabs/Cexigua) and [linux-inject](https://github.com/gaffe23/linux-inject), among other things.

[![asciicast](https://asciinema.org/a/290906.svg)](https://asciinema.org/a/290906)

# Usage

```
    .___.__  .__            __               __
  __| _/|  | |__| ____     |__| ____   _____/  |_  ______ ___.__.
 / __ | |  | |  |/    \    |  |/ __ \_/ ___\   __\ \____ <   |  |
/ /_/ | |  |_|  |   |  \   |  \  ___/\  \___|  |   |  |_> >___  |
\____ | |____/__|___|  /\__|  |\___  >\___  >__| /\|   __// ____|
     \/              \/\______|    \/     \/     \/|__|   \/

source: https://github.com/DavidBuchanan314/dlinject

usage: dlinject.py [-h] [--stopmethod {sigstop,cgroup_freeze,none}]
                   pid /path/to/lib.so

Inject a shared library into a live process.

positional arguments:
  pid                   The pid of the target process
  /path/to/lib.so       Path of the shared library to load (note: must be
                        relative to the target process's cwd, or absolute)

optional arguments:
  -h, --help            show this help message and exit
  --stopmethod {sigstop,cgroup_freeze,none}
                        How to stop the target process prior to shellcode
                        injection. SIGSTOP (default) can have side-effects.
                        cgroup freeze requires root. 'none' is likely to cause
                        race conditions.

```

# Why?

- Because I can.

- There are various [anti-ptrace techniques](https://www.aldeid.com/wiki/Ptrace-anti-debugging), which this evades by simply not using ptrace.

- I don't like ptrace.

- Using `LD_PRELOAD` can sometimes be fiddly or impossible, if the process you want to inject into is spawned by another process with a clean environment.

# How it Works

- Send the stop signal to the target process. (optional)

- Locate the `_dl_open()` symbol.

- Retreive `RIP` and `RSP` via `/proc/[pid]/syscall`.

- Make a backup of part of the stack, and the code we're about to overwrite with our shellcode, by reading from `/proc/[pid]/mem`.

- Generate primary and secondary shellcode buffers.

- Insert primary shellcode at `RIP`, by writing to `/proc/[pid]/mem`.

- The primary shellcode:

  - Pushes common registers to the stack.
  - Loads the secondary shellcode via `mmap()`.
  - Jumps to the secondary shellcode.

- The secondary shellcode:

  - Restores the stack and program code to their original states.
  - Pivots the stack (so we don't touch the original one at all).
  - Calls `_dl_open()` to load the user-specified library. Any constructors will be executed on load, as usual.
  - Restores register state, un-pivots the stack, and jumps back to where it was at the time of the original `SIGSTOP`.
 
# Limitations:

- Sending `SIGSTOP` may cause unwanted side-effects, for example if another thread is waiting on `waitpid()`. The `--stopmethod=cgroup_freeze` option avoids this, but requires root (on most distros, at least).

- I'm not entirely sure how this will interact with complex multi-threaded applications. There's certainly potential for breakage.

- `x86-64` Linux only (for now - 32-bit support could potentially be added).

- Requires root, or relaxed YAMA configuration (`echo 0 | sudo tee /proc/sys/kernel/yama/ptrace_scope` is useful when testing).

- If the target process is sandboxed (e.g. seccomp filters), it might not have permission to `mmap()` the second stage shellcode, or to `dlopen()` the library.
