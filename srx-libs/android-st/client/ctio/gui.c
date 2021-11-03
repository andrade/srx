#include <stdio.h>
#include <stdlib.h>
#include <gtk/gtk.h>

#include "gui.h"

#define MAX_PIN_SIZE 8192

static struct ui_input *ui_input;
static struct ui_output *ui_output;

static GtkWidget *text_pin;

static void shutdown(GtkApplication __attribute__((unused)) *application,
		gpointer __attribute__((unused)) user_data)
{
	printf("Shutting down now\n");
}

// static void verify_pin(GtkButton *button, gpointer null_data)
// {
// 	const gchar *s = gtk_entry_get_text(text_pin);
// 	fprintf(stdout, "PIN: %s\n", s);
//
// 	ui_output->size = sizeof(gchar) * strlen(s);
// 	if (ui_output->size > MAX_PIN_SIZE)
// 		ui_output->size = MAX_PIN_SIZE; // prevent long PINs (arbitrary value)
// 	ui_output->data = malloc(ui_output->size);
// 	strncpy(ui_output->data, s, ui_output->size);
// }
static void process_pin(GtkButton __attribute__((unused)) *button,
		gpointer null_data)
{
	//FIXME  Cast; use button? acho melhor pass pin cá para dentro em vez de adquiri-lo aqui.
	GtkEntry *data_src = null_data;
	const gchar *s = gtk_entry_get_text(data_src);
	fprintf(stdout, "PIN: %s\n", s);

	// ui_output->size = sizeof(gchar) * strlen(s);
	// if (ui_output->size > MAX_PIN_SIZE)
	// 	ui_output->size = MAX_PIN_SIZE; // prevent long PINs (arbitrary value)
	// ui_output->data = malloc(ui_output->size);
	// strncpy(ui_output->data, s, ui_output->size);
	//TODO make check for max size, if larger issue message, truncate, and warn, or abort right away....
	snprintf(ui_output->pin,
			sizeof(ui_output->pin)/sizeof(ui_output->pin[0]),
			"%s", s);
}

static void activate(GtkApplication *app,
		gpointer __attribute__((unused)) null_data)
{
	GtkWidget *window;
	GtkWidget *grid;
	GError *error = NULL;
	GInputStream *stream;
	GdkPixbuf *pixbuf;
	GtkWidget *image;
	GtkWidget *button_verify;
	GtkWidget *button_cancel;
	GtkWidget *text_view;
	//GtkTextBuffer *text_buffer;

	window = gtk_application_window_new(app);
	gtk_window_set_title(GTK_WINDOW(window), "Dummy Window");
	gtk_container_set_border_width(GTK_CONTAINER(window), 0);
	gtk_window_set_default_size(GTK_WINDOW(window), 6, 4);
	gtk_window_set_position(GTK_WINDOW(window), GTK_WIN_POS_CENTER);

	grid = gtk_grid_new();
	gtk_container_add(GTK_CONTAINER(window), grid);
	gtk_grid_set_row_spacing(GTK_GRID(grid), 20);
	//gtk_grid_set_column_spacing(GTK_GRID(grid), 2);
	//gtk_grid_set_column_homogeneous(GTK_GRID(grid), TRUE);
	//gtk_grid_set_row_homogeneous(GTK_GRID(grid), TRUE);

	printf("Image size is %zd, pointer is NULL=%d\n",
			ui_input->size, ui_input->data == NULL);

	stream = g_memory_input_stream_new_from_data(ui_input->data,
			ui_input->size, NULL);
	pixbuf = gdk_pixbuf_new_from_stream(stream, NULL, &error);
	if (pixbuf == NULL) {
		fprintf(stderr, "Failed to load image from stream: %s\n",
				error->message);
		g_error_free(error);
		error = NULL;
		return;
	}
	// Image too large (larger than computer screen) in some cases, scale down:
	GdkPixbuf *pixbuf_scaled = gdk_pixbuf_scale_simple(pixbuf, 320, 320, GDK_INTERP_BILINEAR);
	if (!pixbuf_scaled) {
		fprintf(stderr, "Could not scale pixbuf image\n");
		return;
	}
	// image = gtk_image_new_from_pixbuf(pixbuf);
	image = gtk_image_new_from_pixbuf(pixbuf_scaled);
	// place  in grid cell (0,0) and fill only one cell horizontally and one cell vertically, i.e. no spanning
	gtk_grid_attach(GTK_GRID(grid), image, 0, 0, 6, 1);
	g_object_unref(pixbuf);

	//button_box = gtk_button_box_new(GTK_ORIENTATION_HORIZONTAL);
	//gtk_container_add(GTK_CONTAINER(window), button_box);

	text_pin = gtk_entry_new();
	gtk_grid_attach(GTK_GRID(grid), text_pin, 1, 2, 2, 1);

	button_verify = gtk_button_new_with_label("Verify");
	// g_signal_connect(button_verify, "clicked", G_CALLBACK(verify_pin), NULL);
	g_signal_connect(button_verify, "clicked",
			G_CALLBACK(process_pin), text_pin);
	g_signal_connect_swapped(button_verify, "clicked",
			G_CALLBACK(gtk_widget_destroy), window); // close window after click
	//g_signal_connect_swapped(button, "clicked", G_CALLBACK(gtk_widget_destroy), window);
	//gtk_container_add(GTK_CONTAINER(button_box), button);
	gtk_grid_attach(GTK_GRID(grid), button_verify, 4, 2, 1, 1);

	button_cancel = gtk_button_new_with_label("Cancel");
	g_signal_connect_swapped(button_cancel, "clicked", G_CALLBACK(gtk_widget_destroy), window);
	gtk_grid_attach(GTK_GRID(grid), button_cancel, 5, 2, 1, 1);

	//gtk_widget_set_margin_bottom(text_pin, 10);
	//gtk_widget_set_margin_start(text_pin, 10);
	//gtk_widget_set_margin_end(text_pin, 10);

	text_view = gtk_text_view_new();
	//text_buffer = gtk_text_view_get_buffer(GTK_TEXT_VIEW(text_view));
	//gtk_text_buffer_set_text(text_buffer, "hello world", -1);
	//gtk_text_view_set_editable(GTK_TEXT_VIEW(text_view), FALSE);
	gtk_widget_set_can_focus(text_view, FALSE);
	gtk_grid_attach(GTK_GRID(grid), text_view, 0, 3, 6, 1);
	// no focus, but could be used for progress bar when changing at bottom. text progress bar would load stars/circles/dots/vertical bars, whatever, and could simply use progress bar, maybe GTK+ has some of these. When bar is full, QR code changes. Necessary for proof of concept?

	gtk_widget_show_all(window);
}

/** The input parameter contains an image and the output contains text. */
int display_ui(struct ui_input *input, struct ui_output *output)
{
	ui_input = input;
	ui_output = output;

	GtkApplication *app;
	int status;

	app = gtk_application_new("fake.domain.andrade.ept",
			G_APPLICATION_FLAGS_NONE);
	if (g_signal_connect(app, "activate", G_CALLBACK(activate), NULL) <= 0) {
		fprintf(stderr, "Failed to connect callback function\n");
		return -1;
	}
	//g_object_set_data(G_OBJECT(app), "out_struct", output);
	if (g_signal_connect(app, "shutdown", G_CALLBACK(shutdown), NULL) <= 0) {
		fprintf(stderr, "Failed to connect callback function\n");
		return -1;
	}
	status = g_application_run(G_APPLICATION(app), 0, NULL);
	g_object_unref(app);

	//g_print("foo: %s\n", output->data);//FIXME delete
	//TODO consider making static global of output pointer, issue solved easy

	return status;
}
