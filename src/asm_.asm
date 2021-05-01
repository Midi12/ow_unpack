.DATA
.CODE

ComputeImpl PROC
	and edx, 0FFFh
	lea r8, [rdx+rax]
	mov rax, 469EE58469EE5847h
	sar r8, 0Ch
	imul r8
	sar rdx, 3
	mov rcx, rax
	shr rcx, 3Fh
	add rcx, rax
	imul rcx, rdx, 1Dh
	sub r8, rcx
	imul r8, 100h
	mov rax, r8
	ret
ComputeImpl ENDP

END