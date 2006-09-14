/* $Id$ */

#include <gtk/gtk.h>
#include <gdk-pixbuf/gdk-pixbuf.h>
#include <gpgme.h>
#include <glib.h>
#include "internal.h"
#include "conversation.h"
#include "grypt.h"
#include "gtkplugin.h"
#include "gtkutils.h"

#define GAIM_STOCK_GRYPT "gaim-grypt"

static struct {
	const char *name;
	const char *dir;
	const char *filename;
} const grypt_stock_icon = {
	GAIM_STOCK_GRYPT, "buttons", "grypt.png"
};

/* Register the fucking icon in an icon factory */
void
grypt_gui_add_icon(void)
{
	GtkIconFactory *icons;
	GtkIconSet *set;
	GdkPixbuf *buf;
	gchar *file;

	if ((file = g_build_filename(DATADIR, "pixmaps", "gaim",
	    grypt_stock_icon.dir, grypt_stock_icon.filename, NULL)) == NULL) {
		bark("g_build_filename() returned NULL for icon");
		return;
	}
	if ((icons = gtk_icon_factory_new()) == NULL) {
		bark("gtk_icon_factory_new() return NULL");
		return;
	}
	buf = gdk_pixbuf_new_from_file(file, NULL);
	g_free(file);
	set = gtk_icon_set_new_from_pixbuf(buf);
	gtk_icon_factory_add(icons, grypt_stock_icon.name, set);
	gtk_icon_set_unref(set);
	gtk_icon_factory_add_default(icons);
	g_object_unref(G_OBJECT(icons));
}

GtkWidget *
grypt_gui_config(GaimPlugin *p)
{
	GtkWidget *ret, *vbox, *frame;
	GtkListStore *store;
	GtkWidget *win, *list;
	GtkTreeViewColumn *col;
	GtkCellRenderer *r;
	GtkTreeSelection *sel;

	ret = gtk_vbox_new(FALSE, 18);
	gtk_container_set_border_width(GTK_CONTAINER(ret), 12);

	frame = gaim_gtk_make_frame(ret, _("Select an Identity"));
	vbox = gtk_vbox_new(FALSE, 5);
	gtk_container_add(GTK_CONTAINER(frame), vbox);

	store = gtk_list_store_new(COL_CNT, G_TYPE_STRING,
	    G_TYPE_STRING, G_TYPE_STRING);

	/* Gather GPG keys */
	grypt_gui_gather_ids(store);

	win = gtk_scrolled_window_new(NULL, NULL);
	gtk_scrolled_window_set_policy(GTK_SCROLLED_WINDOW(win),
	    GTK_POLICY_NEVER, GTK_POLICY_AUTOMATIC);
	gtk_scrolled_window_set_shadow_type(GTK_SCROLLED_WINDOW(win),
	    GTK_SHADOW_IN);
	gtk_box_pack_start(GTK_BOX(ret), win, TRUE, TRUE, 0);

	list = gtk_tree_view_new_with_model(GTK_TREE_MODEL(store));
	g_object_unref(G_OBJECT(store));
	gtk_container_add(GTK_CONTAINER(win), list);

	/* Key column */
	r = gtk_cell_renderer_text_new();
	col = gtk_tree_view_column_new_with_attributes(
	    "Fingerprint", r, "text", FPR_COL, NULL);
	gtk_tree_view_column_set_resizable(col, TRUE);
	gtk_tree_view_append_column(GTK_TREE_VIEW(list), col);

	/* Name column */
	r = gtk_cell_renderer_text_new();
	col = gtk_tree_view_column_new_with_attributes(
	    "Name", r, "text", NAME_COL, NULL);
	gtk_tree_view_column_set_resizable(col, TRUE);
	gtk_tree_view_append_column(GTK_TREE_VIEW(list), col);

	/* Description/comment column */
	r = gtk_cell_renderer_text_new();
	col = gtk_tree_view_column_new_with_attributes(
	    "Description", r, "text", DESC_COL, NULL);
	gtk_tree_view_append_column(GTK_TREE_VIEW(list), col);

	/* Setup selection callback */
	sel = gtk_tree_view_get_selection(GTK_TREE_VIEW(list));
	gtk_tree_selection_set_mode(sel, GTK_SELECTION_SINGLE);
	g_signal_connect(G_OBJECT(sel), "changed",
	    G_CALLBACK(grypt_gui_id_select_cb), NULL);

	gtk_widget_show_all(ret);
	return (ret);
}

void
grypt_gui_id_select_cb(GtkTreeSelection *sel, gpointer data)
{
	char *name, *fpr;

	GtkTreeIter iter;
	GtkTreeModel *model;

/*
	if (fpr != NULL)
		g_free(fpr);
*/

	if (gtk_tree_selection_get_selected(sel, &model, &iter)) {
		gtk_tree_model_get(model, &iter, FPR_COL, (gchar *)&fpr, -1);
		strncpy(fingerprint, fpr, FPRSIZ);
		fingerprint[FPRSIZ] = '\0';
		g_free(fpr);

		gtk_tree_model_get(model, &iter, NAME_COL, (gchar *)&name, -1);
		bark("Changing identity to: %s", name);
		g_free(name);
	}
}

void
grypt_gui_gather_ids(GtkListStore *t)
{
	GtkTreeIter row;
	GValue **v, *u;

	grypt_gather_identities();

	bark("Looping through identities to add to gui config panel");
	for (v = identities; *v != NULL; v++) {
		u = *v;
		/* Create row */
		gtk_list_store_append(t, &row);

		/* Fill key */
		gtk_list_store_set_value(t, &row, FPR_COL,  u++);
		gtk_list_store_set_value(t, &row, NAME_COL, u++);
		gtk_list_store_set_value(t, &row, DESC_COL, u++);
	}
}

GtkWidget *
grypt_gui_show_button(GaimConversation *conv)
{
	GtkWidget *hbox = NULL;
	GtkWidget *vbox;
	GList *iter;
	GtkWidget *button;
	GaimGtkConversation *gtkconv;

	gtkconv = GAIM_GTK_CONVERSATION(conv);

	/* Display widget */
	bark("Displaying crypt widget");

	/* Find the fucking hbox */
	vbox = gtkconv->toolbar;
	for (iter = GTK_BOX(vbox)->children; iter != NULL; iter = g_list_next(iter))
		if (GTK_IS_BOX(hbox = ((GtkBoxChild *)iter->data)->widget))
			break;

	if (hbox == NULL)
		croak("can't find toolbar hbox");

	button = gaim_pixbuf_toolbar_button_from_stock(GAIM_STOCK_GRYPT);
	gtk_size_group_add_widget(gtkconv->sg, button);
	gtk_box_pack_start(GTK_BOX(hbox), button, FALSE, FALSE, 0);
	gtk_tooltips_set_tip(gtkconv->tooltips, button, _("Encrypt/Decrypt"), NULL);

	g_signal_connect(G_OBJECT(button), "clicked",
	    G_CALLBACK(grypt_crypto_encdec_cb), conv);
	gtk_widget_show(button);

	return (button);
}
