/**
* Manipulation of QR codes.
*
* Functions writePNG and fillRow are taken and adapted
* from qrenc.c in libqrencode (LGPL) of Kentaro Fukuchi.
*/
#define _POSIX_C_SOURCE 200809L
#include <stdio.h>
#include <png.h>
#include <qrencode.h>
#include <stdlib.h>
#include <string.h>
#include <getopt.h>
#include <errno.h>

#include "qrc.h"

#define INCHES_PER_METER (100.0/2.54)

enum imageType {
	PNG_TYPE,
	PNG32_TYPE
};

static enum imageType image_type = PNG_TYPE;

static void fillRow(unsigned char *row, int num, const unsigned char color[])
{
	int i;

	for(i = 0; i < num; i++) {
		memcpy(row, color, 4);
		row += 4;
	}
}

/**
 * Transforms a QR code into a PNG image.
 */
static int writePNG(const QRcode *qrcode, char **outfile, size_t *sizeloc,
		enum imageType type)
{
	static int size = 12;
	static int margin = 4;
	static int dpi = 72;
	static unsigned char fg_color[4] = {0, 0, 0, 255};
	static unsigned char bg_color[4] = {255, 255, 255, 255};

	static FILE *fp; // avoid clobbering by setjmp.
	png_structp png_ptr;
	png_infop info_ptr;
	png_byte alpha_values[2];
	unsigned char *row, *p, *q;
	int x, y, xx, yy, bit;
	int realwidth;

	realwidth = (qrcode->width + margin * 2) * size;
	if(type == PNG_TYPE) {
		row = (unsigned char *)malloc((realwidth + 7) / 8);
	} else if(type == PNG32_TYPE) {
		row = (unsigned char *)malloc(realwidth * 4);
	} else {
		fprintf(stderr, "Internal error.\n");
		return -1;
	}
	if(row == NULL) {
		fprintf(stderr, "Failed to allocate memory.\n");
		return -1;
	}

	//fp = fopen(outfile, "wb");
	fp = open_memstream(outfile, sizeloc);//bytes
	if(fp == NULL) {
		fprintf(stderr, "Failed to create file: %s\n", *outfile);
		perror(NULL);
		return -1;
	}

	png_ptr = png_create_write_struct(PNG_LIBPNG_VER_STRING, NULL, NULL, NULL);
	if(png_ptr == NULL) {
		fprintf(stderr, "Failed to initialize PNG writer.\n");
		return -1;
	}

	info_ptr = png_create_info_struct(png_ptr);
	if(info_ptr == NULL) {
		fprintf(stderr, "Failed to initialize PNG write.\n");
		return -1;
	}

	if(setjmp(png_jmpbuf(png_ptr))) {
		png_destroy_write_struct(&png_ptr, &info_ptr);
		fprintf(stderr, "Failed to write PNG image.\n");
		return -1;
	}

	png_colorp palette = NULL;

	if(type == PNG_TYPE) {
		palette = (png_colorp) malloc(sizeof(png_color) * 2);
		if(palette == NULL) {
			fprintf(stderr, "Failed to allocate memory.\n");
			return -1;
		}
		palette[0].red   = fg_color[0];
		palette[0].green = fg_color[1];
		palette[0].blue  = fg_color[2];
		palette[1].red   = bg_color[0];
		palette[1].green = bg_color[1];
		palette[1].blue  = bg_color[2];
		alpha_values[0] = fg_color[3];
		alpha_values[1] = bg_color[3];
		png_set_PLTE(png_ptr, info_ptr, palette, 2);
		png_set_tRNS(png_ptr, info_ptr, alpha_values, 2, NULL);
	}

	png_init_io(png_ptr, fp);
	if(type == PNG_TYPE) {
		png_set_IHDR(png_ptr, info_ptr,
				realwidth, realwidth,
				1,
				PNG_COLOR_TYPE_PALETTE,
				PNG_INTERLACE_NONE,
				PNG_COMPRESSION_TYPE_DEFAULT,
				PNG_FILTER_TYPE_DEFAULT);
	} else {
		png_set_IHDR(png_ptr, info_ptr,
				realwidth, realwidth,
				8,
				PNG_COLOR_TYPE_RGB_ALPHA,
				PNG_INTERLACE_NONE,
				PNG_COMPRESSION_TYPE_DEFAULT,
				PNG_FILTER_TYPE_DEFAULT);
	}
	png_set_pHYs(png_ptr, info_ptr,
			dpi * INCHES_PER_METER,
			dpi * INCHES_PER_METER,
			PNG_RESOLUTION_METER);
	png_write_info(png_ptr, info_ptr);

	if(type == PNG_TYPE) {
		/* top margin */
		memset(row, 0xff, (realwidth + 7) / 8);
		for(y = 0; y < margin * size; y++) {
			png_write_row(png_ptr, row);
		}

		/* data */
		p = qrcode->data;
		for(y = 0; y < qrcode->width; y++) {
			memset(row, 0xff, (realwidth + 7) / 8);
			q = row;
			q += margin * size / 8;
			bit = 7 - (margin * size % 8);
			for(x = 0; x < qrcode->width; x++) {
				for(xx = 0; xx < size; xx++) {
					*q ^= (*p & 1) << bit;
					bit--;
					if(bit < 0) {
						q++;
						bit = 7;
					}
				}
				p++;
			}
			for(yy = 0; yy < size; yy++) {
				png_write_row(png_ptr, row);
			}
		}

		/* bottom margin */
		memset(row, 0xff, (realwidth + 7) / 8);
		for(y = 0; y < margin * size; y++) {
			png_write_row(png_ptr, row);
		}
	} else {
		/* top margin */
		fillRow(row, realwidth, bg_color);
		for(y = 0; y < margin * size; y++) {
			png_write_row(png_ptr, row);
		}

		/* data */
		p = qrcode->data;
		for(y = 0; y < qrcode->width; y++) {
			fillRow(row, realwidth, bg_color);
			for(x = 0; x < qrcode->width; x++) {
				for(xx = 0; xx < size; xx++) {
					if(*p & 1) {
						memcpy(&row[((margin + x) * size + xx) * 4], fg_color, 4);
					}
				}
				p++;
			}
			for(yy = 0; yy < size; yy++) {
				png_write_row(png_ptr, row);
			}
		}

		/* bottom margin */
		fillRow(row, realwidth, bg_color);
		for(y = 0; y < margin * size; y++) {
			png_write_row(png_ptr, row);
		}
	}

	png_write_end(png_ptr, info_ptr);
	png_destroy_write_struct(&png_ptr, &info_ptr);

	fclose(fp);
	free(row);
	free(palette);

	return 0;
}

int string_to_qrc_png(const char *str, char **buf, size_t *size)
{
	QRcode *qr = QRcode_encodeString(str, 0, QR_ECLEVEL_H, QR_MODE_8, 1);
	if (qr == NULL) {
		perror("Could not encode string");
		return 1;
	}

	int ret = writePNG(qr, buf, size, image_type);
	QRcode_free(qr);

	return ret;
}

//NOTE:  open_memstream does not add ending NUL

// int bytes_to_qrc_png(char **buf, size_t *size, const unsigned char *data_in, int size_in)
// {
// 	QRcode *qr = QRcode_encodeData(size_in, data_in, 0, QR_ECLEVEL_H);
// 	if (!qr) {
// 		perror("Could not encode buffer (QRC)");
// 		return 1;
// 	}
// 	int ret = writePNG(qr, buf, size, image_type);
// 	QRcode_free(qr);
//
// 	return ret;
// }

//TODO test me.... (might be btter let caller handle base64 or similar)
// int buffer_to_qrc_png(const unsigned char *data, int n, char **buf, size_t *size)
// {
// 	//QRcode *qr = QRcode_encodeString(str, 0, QR_ECLEVEL_H, QR_MODE_8, 1);
// 	QRcode *qr = QRcode_encodeData(n, data, 0, QR_ECLEVEL_H);
// 	int ret = writePNG(qr, buf, size, image_type);
// 	QRcode_free(qr);
//
// 	return ret;
// }
