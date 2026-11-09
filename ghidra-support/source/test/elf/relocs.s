; ELF relocation handler test: code and data relocations against local and undefined symbols
	.cpu	ARC700
	.text
	.global	_start
_start:
	bl	ext_func	; R_ARC_S25W_PCREL
	bl.d	local_func
	nop
	b	ext_func	; R_ARC_S25H_PCREL
	beq	ext_func	; R_ARC_S21H_PCREL
	bleq	ext_func	; R_ARC_S21W_PCREL
	bl_s	ext_func	; R_ARC_S13_PCREL
	mov	r0,ext_data	; R_ARC_32_ME
	add	r1,r1,local_data	; R_ARC_32_ME
	ld	r2,[pcl,ext_data@pcl]	; R_ARC_PC32
	j_s	[blink]
	.align	4
local_func:
	mov_s	r0,1
	j_s	[blink]
	.data
	.align	4
local_data:
	.word	ext_data	; R_ARC_32
	.word	local_func
	.word	ext_func+8
