#ifndef GTK_CELL_RENDERER_PIXBUF_CLICKED_H
#define GTK_CELL_RENDERER_PIXBUF_CLICKED_H

#include <gtk/gtk.h>

#define GTK_TYPE_CELL_RENDERER_PIXBUF_CLICKED	(gtk_cell_renderer_pixbuf_clicked_get_type ())
#define GTK_CELL_RENDERER_PIXBUF_CLICKED(obj)	\
	(G_TYPE_CHECK_INSTANCE_CAST ((obj), GTK_TYPE_CELL_RENDERER_PIXBUF_CLICKED, GtkCellRendererPixbufClicked))

typedef struct _GtkCellRendererPixbufClickedPrivate	GtkCellRendererPixbufClickedPrivate;

struct _GtkCellRendererPixbufClickedPrivate
{
	gint indicator_size;
	guint active       : 1;
	guint activatable  : 1;
	guint inconsistent : 1;
	guint radio        : 1;
};

typedef struct _GtkCellRendererPixbufClicked	GtkCellRendererPixbufClicked;
typedef struct _GtkCellRendererPixbufClickedClass	GtkCellRendererPixbufClickedClass;

struct _GtkCellRendererPixbufClickedClass
{
	GtkCellRendererPixbufClass parent_class;

	void (*clicked)(GtkCellRendererPixbufClicked *cell_renderer_pixbufclk,
				const gchar *path);

	void (*_gtk_reserved1) (void);
	void (*_gtk_reserved2) (void);
	void (*_gtk_reserved3) (void);
	void (*_gtk_reserved4) (void);
};

struct _GtkCellRendererPixbufClicked
{
	GtkCellRendererPixbuf	parent;
	GtkCellRendererPixbufClickedPrivate	*priv;
};


GType	gtk_cell_renderer_pixbuf_clicked_get_type (void) G_GNUC_CONST;
GtkCellRenderer *gtk_cell_renderer_pixbuf_clicked_new(void);


#endif
