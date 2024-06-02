ENTRY(_start)

SECTIONS {
	// Define the starting address of the IPL
	PROVIDE(__ipl_start = LDR_LOAD_ADDR);
	. = __ipl_start;

	// Text section, including the entry point and IPL metadata
	.text : {
		*(.text._start);      // Include the entry point
		KEEP(*(._boot_cfg));  // Keep the boot configuration
		KEEP(*(._ipl_version)); // Keep the IPL version
		*(.text*);            // Include all other text sections
	}

	// Data section, including read-only data and payloads
	.data : {
		*(.data*);    // Include all data sections
		*(.rodata*);  // Include all read-only data sections
		*(._payload_00); // Include the first payload
		*(._payload_01); // Include the second payload
	}

	// Mark the end of the loader
	__ldr_end = .;

	// Align to a 16-byte boundary to ensure proper memory organization
	. = ALIGN(0x10);

	// Mark the end of the IPL
	__ipl_end = .;
}
