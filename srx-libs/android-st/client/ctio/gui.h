#ifndef _EPT_GUI_H
#define _EPT_GUI_H

#include <stddef.h>

struct ui_input {
	void *data;
	size_t size;
};

struct ui_output {
	void *data; // unused along with size
	size_t size;
	char pin[16]; // arbitrary choice of 16
};

/**
 * Displays the input in a GUI and fills in the output on success.
 * Returns zero on success, non-zero otherwise.
 */
int display_ui(struct ui_input *input, struct ui_output *output);

#endif
