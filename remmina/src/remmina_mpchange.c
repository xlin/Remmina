/*
 * Remmina - The GTK+ Remote Desktop Client
 * Copyright (C) 2009-2011 Vic Lee
 * Copyright (C) 2014-2015 Antenore Gatta, Fabio Castelli, Giovanni Panozzo
 * Copyright (C) 2016-2017 Antenore Gatta, Giovanni Panozzo
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor,
 * Boston, MA  02110-1301, USA.
 *
 *  In addition, as a special exception, the copyright holders give
 *  permission to link the code of portions of this program with the
 *  OpenSSL library under certain conditions as described in each
 *  individual source file, and distribute linked combinations
 *  including the two.
 *  You must obey the GNU General Public License in all respects
 *  for all of the code used other than OpenSSL. *  If you modify
 *  file(s) with this exception, you may extend this exception to your
 *  version of the file(s), but you are not obligated to do so. *  If you
 *  do not wish to do so, delete this exception statement from your
 *  version. *  If you delete this exception statement from all source
 *  files in the program, then also delete it here.
 *
 */

#include <gtk/gtk.h>
#include <glib/gi18n.h>
#include "config.h"
#include "remmina_mpchange.h"
#include "remmina_file.h"
#include "remmina_file_manager.h"
#include "remmina_pref.h"
#include "remmina_public.h"
#include "remmina_main.h"
#include "remmina_plugin_manager.h"
#include "remmina/remmina_trace_calls.h"

#define GET_DIALOG_OBJECT(object_name) gtk_builder_get_object(bu, object_name)

struct mpchanger_params {
	gchar *username;	// New username
	gchar *domain;		// New domain
	gchar *password;	// New password
	gchar *group;

	GtkListStore* store;
};

enum {
	COL_F = 0,
	COL_NAME,
	COL_GROUP,
	COL_USERNAME,
	NUM_COLS
};

static void remmina_mpchange_file_list_callback(RemminaFile *remminafile, gpointer user_data)
{
	TRACE_CALL("remmina_mpchange_file_list_callback");
	GtkListStore* store;
	GtkTreeIter iter;
	const gchar *username, *domain, *group;

	gchar* s;
	gboolean sel;
	struct mpchanger_params* mpcp;

	mpcp = (struct mpchanger_params*)user_data;
	store = GTK_LIST_STORE(mpcp->store);


	username = remmina_file_get_string(remminafile, "username");
	domain = remmina_file_get_string(remminafile, "domain");
	group = remmina_file_get_string(remminafile, "group");

	if (username == NULL)
		username = "";

	if (domain == NULL)
		domain = "";

	if (group == NULL)
		group = "";


	if (strcasecmp(username, mpcp->username) != 0 ||
		strcasecmp(domain, mpcp->domain) != 0)
		return;

	if (strcasecmp(group, mpcp->group) != 0)
		sel = FALSE;
	else
		sel = TRUE;


	gtk_list_store_append(store, &iter);
	s = g_strdup_printf("%s\\%s", domain, username);

	printf("GIO: %s\\%s %s\n",mpcp->domain, mpcp->username, s);

	gtk_list_store_set(store, &iter,
		COL_F, sel,
		COL_NAME, remmina_file_get_string(remminafile, "name"),
		COL_GROUP, group,
		COL_USERNAME,   s,
		-1);
	g_free(s);

}

static void remmina_mpchange_checkbox_toggle(GtkCellRendererToggle *cell, gchar *path_string, gpointer user_data)
{
	TRACE_CALL("remmina_mpchange_checkbox_toggle");
	GtkTreeIter iter;
	GtkListStore* store = (GtkListStore*)user_data;
	GtkTreePath *path;

	gboolean a = gtk_cell_renderer_toggle_get_active(cell);
	path = gtk_tree_path_new_from_string(path_string);
	gtk_tree_model_get_iter(GTK_TREE_MODEL(store), &iter, path);
	gtk_tree_path_free (path);
	gtk_list_store_set(store, &iter, COL_F, !a, -1);
}

static void remmina_mpchange_dochange_clicked(GtkButton *btn, gpointer user_data)
{
	TRACE_CALL("remmina_mpchange_dochange_clicked");
	GtkDialog* dialog = (GtkDialog*)user_data;


	printf("GIO: remmina_mpchange_dochange_clicked\n");
}

static gboolean remmina_file_multipasswd_changer_mt(gpointer d)
{
	TRACE_CALL("remmina_file_multipasswd_changer_mt");
	struct mpchanger_params *mpcp = d;
	GtkBuilder* bu;
	GtkDialog* dialog;
	GtkWindow* mainwindow;
	GtkLabel* lbl;
	gchar* s;
	GtkListStore* lstore;
	GtkCellRendererToggle *toggle;

	printf("GIO: multipasschanger called for username = %s\n", mpcp->username);

	/* The multiple passowrd changer works only when a secret plugin is available */
	if (remmina_plugin_manager_get_secret_plugin() == NULL)
		return FALSE;

	mainwindow = remmina_main_get_window();

	bu = remmina_public_gtk_builder_new_from_file("remmina_mpc.glade");
	if (!bu)
		return FALSE;

	dialog = GTK_DIALOG(gtk_builder_get_object(bu, "MPCDialog"));
	if (mainwindow)
		gtk_window_set_transient_for(GTK_WINDOW(dialog), mainwindow);

	lstore = gtk_list_store_new(NUM_COLS, G_TYPE_BOOLEAN, G_TYPE_STRING, G_TYPE_STRING, G_TYPE_STRING);

	s = g_strdup_printf(_("Changing password for user <span weight='bold'>%s\\%s</span> in group <span weight='bold'>%s</span>"), mpcp->domain, mpcp->username, mpcp->group);
	lbl = GTK_LABEL(GET_DIALOG_OBJECT("row1Label"));
	gtk_label_set_markup(lbl, s);
	g_free(s);

	mpcp->store = lstore;
	remmina_file_manager_iterate((GFunc) remmina_mpchange_file_list_callback, (gpointer)mpcp);

	gtk_tree_view_set_model(GTK_TREE_VIEW(GET_DIALOG_OBJECT("profchangelist")), GTK_TREE_MODEL(lstore));

	toggle = GTK_CELL_RENDERER_TOGGLE(GET_DIALOG_OBJECT("cellrenderertoggle1"));
	g_signal_connect(G_OBJECT(toggle), "toggled", G_CALLBACK(remmina_mpchange_checkbox_toggle), (gpointer)lstore);

	g_signal_connect(GTK_BUTTON(GET_DIALOG_OBJECT("btnDoChange")), "clicked", G_CALLBACK(remmina_mpchange_dochange_clicked), (gpointer)dialog);
	g_signal_connect(dialog, "response", G_CALLBACK(gtk_widget_destroy), NULL);

	gtk_dialog_run(dialog);
	gtk_widget_destroy(GTK_WIDGET(dialog));

	// Free data and remove event source
	g_free(mpcp->username);
	g_free(mpcp->password);
	g_free(mpcp->domain);
	g_free(mpcp->group);
	g_free(mpcp);
	return FALSE;
}


void
remmina_mpchange_schedule(RemminaFile *remminafile, gboolean has_domain, gchar *username, gchar *domain, gchar *password)
{
	// We usually get called in a subthread after a successful connection.
	// So we just schedule the multipassword changer to be executed on
	// the main thread

	TRACE_CALL("remmina_mpchange_schedule");
	struct mpchanger_params *mpcp;

	printf("GIO: remmina_mpchange_schedule\n");


	if (remmina_pref.mpchange_enable) {
		mpcp = g_malloc0(sizeof(struct mpchanger_params));
		mpcp->username = g_strdup(username);
		mpcp->password = g_strdup(password);
		mpcp->domain = g_strdup(domain);
		mpcp->group = g_strdup(remmina_file_get_string(remminafile, "group"));
		gdk_threads_add_idle(remmina_file_multipasswd_changer_mt, (gpointer)mpcp);
	}

}

