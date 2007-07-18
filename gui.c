/* $Id$ */

#include <gtk/gtk.h>
#include <gdk-pixbuf/gdk-pixbuf.h>
#include <gpgme.h>
#include <glib.h>
#include "internal.h"
#include "conversation.h"
#include "grypt.h"
#include "pidgin/gtkutils.h"

GtkWidget *
grypt_gui_config(PurplePlugin *p)
{
	GtkWidget *ret, *vbox, *frame;
	GtkListStore *store;
	GtkWidget *win, *list;
	GtkTreeViewColumn *col;
	GtkCellRenderer *r;
	GtkTreeSelection *sel;

	ret = gtk_vbox_new(FALSE, 18);
	gtk_container_set_border_width(GTK_CONTAINER(ret), 12);

	frame = pidgin_make_frame(ret, _("Select a GPG Identity"));
	vbox = gtk_vbox_new(FALSE, 5);
	gtk_container_add(GTK_CONTAINER(frame), vbox);

	store = gtk_list_store_new(COL_CNT - 1, G_TYPE_STRING,
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
	    "Key ID", r, "text", KEYID_COL, NULL);
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
	GtkTreeModel *model;
	GtkTreeIter iter;
	GValue **v, *u;
	char *keyid;

	if (gtk_tree_selection_get_selected(sel, &model, &iter)) {
		gtk_tree_model_get(model, &iter, KEYID_COL, &keyid, -1);
		for (v = grypt_identities; (u = *v) != NULL; v++)
			if (strcmp(keyid,
			    g_value_get_string(&u[KEYID_COL])) == 0) {
				grypt_choose(u);
				break;
			}
		g_free(keyid);
	}
}

void
grypt_gui_gather_ids(GtkListStore *t)
{
	GtkTreeIter row;
	GValue **v, *u;

	for (v = grypt_identities; *v != NULL; v++) {
		u = *v;
		/* Create row */
		gtk_list_store_append(t, &row);

		/* Fill key */
		gtk_list_store_set_value(t, &row, KEYID_COL, u++);
		gtk_list_store_set_value(t, &row, NAME_COL,  u++);
		gtk_list_store_set_value(t, &row, DESC_COL,  u++);
	}
}
