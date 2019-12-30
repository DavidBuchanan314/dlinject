import argparse
from pwn import *
context.arch = "amd64"

parser = argparse.ArgumentParser(description="Inject a shared library into a live process.")
parser.add_argument("pid", metavar="pid", type=int, help="target pid")
parser.add_argument("lib_path", metavar="lib.so", type=str, help="Path of the shared library to load (note: must be relative to the target process's cwd, or absolute)")
parser.add_argument("--nostop", action="store_true", help="Don't stop the target process prior to injection (race condition-y, but avoids potential side-effects of SIGSTOP)")
args = parser.parse_args()

pid = args.pid
lib_path = args.lib_path

STACK_BACKUP_SIZE = 8*16

for line in open(f"/proc/{pid}/maps").readlines():
	ld_path = line.split()[-1]
	if re.match(r".*/ld-.*\.so", ld_path):
		log.info("ld.so found: " + repr(ld_path))
		ld = ELF(ld_path)
		ld.address = int(line.split("-")[0], 16)
		log.info("ld.so base: " + hex(ld.address))
		log.info("_dl_open: " + hex(ld.sym["_dl_open"]))
		break
else:
	log.error("Couldn't find ld.so! (we need it for _dl_open)")

if not args.nostop:
	os.kill(pid, signal.SIGSTOP)
	
	while True:
		state = open(f"/proc/{pid}/stat").read().split(" ")[2]
		if state in ["T", "t"]:
			break
		print("Waiting for process to stop...")

syscall_vals = open(f"/proc/{pid}/syscall").read().split(" ")
rip = int(syscall_vals[-1][2:], 16)
rsp = int(syscall_vals[-2][2:], 16)

log.info(f"RIP: {hex(rip)}")
log.info(f"RSP: {hex(rsp)}")

stage2_path = f"/tmp/stage2_{os.urandom(8).hex()}.bin"

shellcode = asm(fr"""
	// push all the things
	pushf
	push rax
	push rbx
	push rcx
	push rdx
	push rbp
	push rsi
	push rdi
	push r8
	push r9
	push r10
	push r11
	push r12
	push r13
	push r14
	push r15

	// Open stage2 file
	mov rax, 2          # SYS_OPEN
	lea rdi, path[rip]  # path
	xor rsi, rsi        # flags (O_RDONLY)
	xor rdx, rdx        # mode
	syscall
	mov r14, rax  # save the fd for later

	// mmap it
	mov rax, 9       # SYS_MMAP
	xor rdi, rdi     # addr
	mov rsi, 0x8000  # len
	mov rdx, 0x7     # prot (rwx)
	mov r10, 0x2     # flags (MAP_PRIVATE)
	mov r8, r14      # fd
	xor r9, r9       # off
	syscall
	mov r15, rax     # save mmap addr

	// close the file
	mov rax, 3    # SYS_CLOSE
	mov rdi, r14  # fd
	syscall

	// delete the file (not exactly necessary)
	mov rax, 87         # SYS_UNLINK
	lea rdi, path[rip]  # path
	syscall

	// jump to stage2
	jmp r15

path:
	.ascii "{stage2_path}\0"
""")

mem = open(f"/proc/{pid}/mem", "wb+")

mem.seek(rip)
code_backup = mem.read(len(shellcode))
mem.seek(rsp-STACK_BACKUP_SIZE)
stack_backup = mem.read(STACK_BACKUP_SIZE)

mem.seek(rip)
mem.write(shellcode)

mem.close()

log.info("Wrote first stage shellcode")

stage2 = asm(fr"""
	cld

	fxsave moar_regs[rip]

	// Open /proc/self/mem
	mov rax, 2          # SYS_OPEN
	lea rdi, proc_self_mem[rip]  # path
	mov rsi, 2        # flags (O_RDWR)
	xor rdx, rdx          # mode
	syscall
	mov r15, rax  # save the fd for later

	// seek to code
	mov rax, 8      # SYS_LSEEK
	mov rdi, r15    # fd
	mov rsi, {rip}  # offset
	xor rdx, rdx    # whence (SEEK_SET)
	syscall

	// restore code
	mov rax, 1                   # SYS_WRITE
	mov rdi, r15                 # fd
	lea rsi, old_code[rip]       # buf
	mov rdx, {len(code_backup)}  # count
	syscall

	// close /proc/self/mem
	mov rax, 3    # SYS_CLOSE
	mov rdi, r15  # fd
	syscall

	// move pushed regs to our new stack
	lea rdi, new_stack_base[rip-{STACK_BACKUP_SIZE}]
	mov rsi, {rsp-STACK_BACKUP_SIZE}
	mov rcx, {STACK_BACKUP_SIZE}
	rep movsb
	
	// restore original stack
	mov rdi, {rsp-STACK_BACKUP_SIZE}
	lea rsi, old_stack[rip]
	mov rcx, {STACK_BACKUP_SIZE}
	rep movsb
	
	lea rsp, new_stack_base[rip-{STACK_BACKUP_SIZE}]
	
	// call _dl_open (https://github.com/lattera/glibc/blob/895ef79e04a953cac1493863bcae29ad85657ee1/elf/dl-open.c#L529)
	lea rdi, lib_path[rip]  # file
	mov rsi, 2              # mode (RTLD_NOW)
	xor rcx, rcx            # nsid (LM_ID_BASE) (could maybe use LM_ID_NEWLM (-1))
	mov rax, {ld.sym["_dl_open"]}
	call rax
	
	fxrstor moar_regs[rip]
	pop r15
	pop r14
	pop r13
	pop r12
	pop r11
	pop r10
	pop r9
	pop r8
	pop rdi
	pop rsi
	pop rbp
	pop rdx
	pop rcx
	pop rdx
	pop rax
	popf
	
	mov rsp, {rsp}
	jmp old_rip[rip]
	
old_rip:
	.quad {rip}
old_code:
	.byte {",".join(map(str, code_backup))}
old_stack:
	.byte {",".join(map(str, stack_backup))}
	.align 16
moar_regs:
	.space 512
lib_path:
	.ascii "{lib_path}\0"
proc_self_mem:
	.ascii "/proc/self/mem\0"
new_stack:
	.balign 0x8000
new_stack_base:
""")

with open(stage2_path, "wb") as stage2_file:
	os.chmod(stage2_path, 0o666)
	stage2_file.write(stage2)

log.info(f"Wrote stage2 to {repr(stage2_path)}")

if not args.nostop:
	os.kill(pid, signal.SIGCONT)

log.success("Done!")
