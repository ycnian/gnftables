/*
 * Copyright (c) 2014  Yanchuan Nian <ycnian@gmail.com>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
 * or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License
 * for more details.
 *
 * You should have received a copy of the GNU General Public License along with
 * this program. You may also obtain a copy of the GNU General Public License
 * from the Free Software Foundation by visiting their web site 
 * (http://www.fsf.org/) or by writing to the Free Software Foundation, Inc.,
 * 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
 */


#include <gtkcellrendererpixbufclicked.h>

G_DEFINE_TYPE (GtkCellRendererPixbufClicked, gtk_cell_renderer_pixbuf_clicked, GTK_TYPE_CELL_RENDERER_PIXBUF)
enum {
	CLICKED,
	LAST_SIGNAL
};
static guint pixbufclk_cell_signals[LAST_SIGNAL] = { 0 };

static gint
gtk_cell_renderer_pixbuf_clicked_activate(GtkCellRenderer	*cell,
				GdkEvent             *event,
				GtkWidget            *widget,
				const gchar          *path,
				const GdkRectangle   *background_area,
				const GdkRectangle   *cell_area,
				GtkCellRendererState  flags)
{
	g_signal_emit(cell, pixbufclk_cell_signals[CLICKED], 0, path);
	return TRUE;
}


static void
gtk_cell_renderer_pixbuf_clicked_init(GtkCellRendererPixbufClicked *cellpixbufclk)
{

}

static void
gtk_cell_renderer_pixbuf_clicked_class_init (GtkCellRendererPixbufClickedClass *class)
{
	GObjectClass *object_class = G_OBJECT_CLASS (class);
	GtkCellRendererClass *cell_class = GTK_CELL_RENDERER_CLASS (class);
	cell_class->activate = gtk_cell_renderer_pixbuf_clicked_activate;


	pixbufclk_cell_signals[CLICKED] =
		g_signal_new("clicked",
			G_OBJECT_CLASS_TYPE (object_class),
			G_SIGNAL_RUN_LAST,
			G_STRUCT_OFFSET(GtkCellRendererPixbufClickedClass, clicked),
			NULL, NULL,
			g_cclosure_marshal_VOID__STRING,
			G_TYPE_NONE, 1,
			G_TYPE_STRING);

	g_type_class_add_private(object_class, sizeof (GtkCellRendererPixbufClickedPrivate));
}


GtkCellRenderer *
gtk_cell_renderer_pixbuf_clicked_new (void)
{
  return g_object_new (GTK_TYPE_CELL_RENDERER_PIXBUF_CLICKED, NULL);
}
