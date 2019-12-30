# dlinject.py
Inject a shared library (i.e. arbitrary code) into a live linux process, without ptrace. Inspired by [Cexigua](https://github.com/AonCyberLabs/Cexigua) and [linux-inject](https://github.com/gaffe23/linux-inject), among other things.

[![asciicast](https://asciinema.org/a/290906.svg)](https://asciinema.org/a/290906)

# Usage

```
usage: dlinject.py [-h] [--nostop] pid lib.so

Inject a shared library into a live process.

positional arguments:
  pid         target pid
  lib.so      Path of the shared library to load (note: must be relative to the target process's cwd, or absolute)

optional arguments:
  -h, --help  show this help message and exit
  --nostop    Don't stop the target process prior to injection (race condition-y, but avoids potential side-effects
              of SIGSTOP)
```

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

- Sending `SIGSTOP` may cause unwanted side-effects, for example if another thread is waiting on `waitpid()`. The `--nostop` option avoids this, but introduces race conditions.

- I'm not entirely sure how this will interact with complex multi-threaded applications. There's certainly potential for breakage.

- `x86-64` Linux only (for now - 32-bit support could potentially be added).

- Requires root, or relaxed YAMA configuration (`echo 0 | sudo tee /proc/sys/kernel/yama/ptrace_scope` is useful when testing).
