ENTRY(_start)

SECTIONS {
	/* Main payload is linked for IPL_LOAD_ADDR (defined by root Makefile). */
	PROVIDE(__ipl_start = IPL_LOAD_ADDR);
	. = __ipl_start;
	.text : {
		*(.text._start);
		KEEP(*(._boot_cfg));
		KEEP(*(._ipl_version));
		*(.text*);
	}
	.data : {
		*(.data*);
		*(.rodata*);
		*(._payload_00);
		*(._payload_01);
	}
	__ldr_end = .;
	. = ALIGN(0x10);
	__ipl_end = .;
}
