#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#include "qrc.h"
#include "gui.h"

#include "ctio.h"

int exchange_strings(const char *str_in, char **str_out)
// int exchange_strings(const void *data_in, size_t size, char **str_out)
{
	struct ui_input input = {
		.data = NULL,
		.size = 0
	};
	struct ui_output output = {
		.data = NULL,
		.size = 0,
		.pin = {0}
	};

	//TEMP test witout BASE 64:
	// if (bytes_to_qrc_png(&input.data, &input.size, data_in, size)) {
	// 	//TODO log failure here: Error building PNG QRC from string
	// 	return 1;
	// }
	if (string_to_qrc_png(str_in, (char **) &input.data, &input.size)) {
		//TODO log failure here: Error building PNG QRC from string
		return 1;
	}

	if (display_ui(&input, &output)) {
		//TODO log failure here: Error displaying QRC
		free(input.data);
		return 2;
	}

	*str_out = malloc(strlen(output.pin) + 1);
	strcpy(*str_out, output.pin);

	free(input.data);
	free(output.data);

	//TODO if pin comes empty, add error pin or string like ERR:NoPin or something...

	return 0;
}
