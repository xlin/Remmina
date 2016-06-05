/*
 * Remmina - The GTK+ Remote Desktop Client
 * Copyright (C) 2016 Antenore Gatta
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

/* Some of the code is based on https://github.com/muflone/remmina-plugin-rdesktop */

#include "common/remmina_plugin.h"
#include "plugin_config.h"

#define GET_PLUGIN_DATA(gp) (RemminaPluginTerminalData*) g_object_get_data(G_OBJECT(gp), "plugin-data")

#if GTK_VERSION == 3
#   include <gtk/gtkx.h>
#endif

typedef struct _RemminaPluginData
{
	GtkWidget *socket;
	gint socket_id;
	GPid pid;
} RemminaPluginData;

/* Array of key/value pairs for Terminal Emulators */
static gpointer terminal_list[] =
{
	"st", N_("st - simple terminal"),
	"xterm", N_("xterm - terminal emulator for X"),
	"urxvt", N_("rxvt-unicode (ouR XVT, unicode)"),
	NULL
};

static RemminaPluginService *remmina_plugin_service = NULL;

static void remmina_plugin_terminal_on_plug_added(GtkSocket *socket, RemminaProtocolWidget *gp)
{
	TRACE_CALL(__func__);
	RemminaPluginData *gpdata;
	gpdata = (RemminaPluginData*) g_object_get_data(G_OBJECT(gp), "plugin-data");
	remmina_plugin_service->log_printf("[%s] Plugin plug added on socket %d\n", PLUGIN_NAME, gpdata->socket_id);
	remmina_plugin_service->protocol_plugin_emit_signal(gp, "connect");
	return;
}

static void remmina_plugin_terminal_on_plug_removed(GtkSocket *socket, RemminaProtocolWidget *gp)
{
	TRACE_CALL(__func__);
	remmina_plugin_service->log_printf("[%s] Plugin plug removed\n", PLUGIN_NAME);
	remmina_plugin_service->protocol_plugin_close_connection(gp);
}

static void remmina_plugin_terminal_init(RemminaProtocolWidget *gp)
{
	TRACE_CALL(__func__);
	remmina_plugin_service->log_printf("[%s] Plugin init\n", PLUGIN_NAME);
	RemminaPluginData *gpdata;

	gpdata = g_new0(RemminaPluginData, 1);
	g_object_set_data_full(G_OBJECT(gp), "plugin-data", gpdata, g_free);

	gpdata->socket = gtk_socket_new();
	remmina_plugin_service->protocol_plugin_register_hostkey(gp, gpdata->socket);
	gtk_widget_show(gpdata->socket);
	g_signal_connect(G_OBJECT(gpdata->socket), "plug-added", G_CALLBACK(remmina_plugin_terminal_on_plug_added), gp);
	g_signal_connect(G_OBJECT(gpdata->socket), "plug-removed", G_CALLBACK(remmina_plugin_terminal_on_plug_removed), gp);
	gtk_container_add(GTK_CONTAINER(gp), gpdata->socket);
}

static gboolean remmina_plugin_terminal_new(RemminaProtocolWidget *gp)
{
	TRACE_CALL(__func__);
#	define ADD_ARGUMENT(name, value) \
	{ \
		argv[argc] = g_strdup(name); \
		argv_debug[argc] = g_strdup(name); \
		argc++; \
		if (value != NULL) \
		{ \
			argv[argc] = value; \
			argv_debug[argc++] = g_strdup(value); \
		} \
	}


	RemminaPluginData *gpdata;
	RemminaFile *remminafile;
	gboolean ret;
	GError *error = NULL;
	gchar *term;                  // Terminal Emulator name
	gchar *embed;                 // Option name to embed window
	gchar *argv[50];              // Contains all the arguments
	gchar *argv_debug[50];        // Contains all the arguments
	gchar *command_line;          // The whole command line
	gint argc;
	gint i;

	//gchar *option_str;
	//gint option_int;

	gpdata = (RemminaPluginData*) g_object_get_data(G_OBJECT(gp), "plugin-data");
	remminafile = remmina_plugin_service->protocol_plugin_get_file(gp);

	remmina_plugin_service->protocol_plugin_set_width(gp, 640);
	remmina_plugin_service->protocol_plugin_set_height(gp, 480);
	gtk_widget_set_size_request(GTK_WIDGET(gp), 640, 480);
	gpdata->socket_id = gtk_socket_get_id(GTK_SOCKET(gpdata->socket));

	term = g_strdup (remmina_plugin_service->file_get_string (remminafile, "terminal"));

	if (strcmp(term, "st") == 0)
	{
		embed = g_strdup ("-w");
	}
	else if (strcmp(term, "xterm") == 0)
	{
		embed = g_strdup ("-into");
	}
	else if (strcmp(term, "urxvt") == 0)
	{
		embed = g_strdup ("-embed");
	}

	argc = 0;
	// Main executable name
	ADD_ARGUMENT(term, NULL);
	// Embed terminal window in another window
	if (gpdata->socket_id != 0)
		ADD_ARGUMENT(embed, g_strdup_printf("%i", gpdata->socket_id));
	//g_free(option_str);
	// End of the arguments list
	ADD_ARGUMENT(NULL, NULL);
	// Retrieve the whole command line
	command_line = g_strjoinv(g_strdup(" "), (gchar **)&argv_debug[0]);
	remmina_plugin_service->log_printf("[TERMINAL] starting %s\n", command_line);
	g_free(command_line);
	// Execute the external process terminal
	ret = g_spawn_async(NULL, argv, NULL, G_SPAWN_SEARCH_PATH,
			NULL, NULL, &gpdata->pid, &error);
	remmina_plugin_service->log_printf(
			"[TERMINAL] started terminal with GPid %d\n", &gpdata->pid);
	// Free the arguments list
	for (i = 0; i < argc; i++)
	{
		g_free(argv_debug[i]);
		g_free(argv[i]);
	}
	// Show error message
	if (!ret)
		remmina_plugin_service->protocol_plugin_set_error(gp, "%s", error->message);
	// Show attached window socket ID
	remmina_plugin_service->log_printf("[TERMINAL] attached window to socket %d\n", gpdata->socket_id);
	return TRUE;
}

static gboolean remmina_plugin_terminal_close(RemminaProtocolWidget *gp)
{
	TRACE_CALL(__func__);
	remmina_plugin_service->log_printf("[%s] Plugin close connection\n", PLUGIN_NAME);
	remmina_plugin_service->protocol_plugin_emit_signal(gp, "disconnect");
	return FALSE;
}

/* Array of RemminaProtocolSetting for basic settings.
 * Each item is composed by:
 * a) RemminaProtocolSettingType for setting type
 * b) Setting name
 * c) Setting description
 * d) Compact disposition
 * e) Values for REMMINA_PROTOCOL_SETTING_TYPE_SELECT or REMMINA_PROTOCOL_SETTING_TYPE_COMBO
 * f) Unused pointer
 */
static const RemminaProtocolSetting remmina_plugin_terminal_basic_settings[] =
{
	{ REMMINA_PROTOCOL_SETTING_TYPE_TEXT, "command", N_("Command to be executed or shell"), FALSE, NULL, NULL },
	{ REMMINA_PROTOCOL_SETTING_TYPE_END, NULL, NULL, FALSE, NULL, NULL }
};

/* Array of RemminaProtocolSetting for advanced settings.
 * Each item is composed by:
 * a) RemminaProtocolSettingType for setting type
 * b) Setting name
 * c) Setting description
 * d) Compact disposition
 * e) Values for REMMINA_PROTOCOL_SETTING_TYPE_SELECT or REMMINA_PROTOCOL_SETTING_TYPE_COMBO
 * f) Unused pointer
 */
static const RemminaProtocolSetting remmina_plugin_terminal_advanced_settings[] =
{
	{ REMMINA_PROTOCOL_SETTING_TYPE_SELECT, "terminal", N_("Termina Emulator"), FALSE, terminal_list, NULL },
	{ REMMINA_PROTOCOL_SETTING_TYPE_END, NULL, NULL, FALSE, NULL, NULL }
};

/* Array for available features.
 * The last element of the array must be REMMINA_PROTOCOL_FEATURE_TYPE_END. */
static const RemminaProtocolFeature remmina_plugin_terminal_features[] =
{
	{ REMMINA_PROTOCOL_FEATURE_TYPE_END, 0, NULL, NULL, NULL }
};

static RemminaProtocolPlugin remmina_plugin_terminal =
{
	REMMINA_PLUGIN_TYPE_PROTOCOL,                // Type
	PLUGIN_NAME,                                 // Name
	N_(PLUGIN_DESCRIPTION),                      // Description
	GETTEXT_PACKAGE,                             // Translation domain
	VERSION,                                     // Version number
	PLUGIN_APPICON,                              // Icon for normal connection
	PLUGIN_APPICON,                              // Icon for SSH connection
	remmina_plugin_terminal_basic_settings,      // Array for basic settings
	remmina_plugin_terminal_advanced_settings,   // Array for advanced settings
	REMMINA_PROTOCOL_SSH_SETTING_NONE,           // SSH settings type
	remmina_plugin_terminal_features,            // Array for available features
	remmina_plugin_terminal_init,                // Plugin initialization
	remmina_plugin_terminal_new,                 // Plugin open connection
	remmina_plugin_terminal_close,               // Plugin close connection
	NULL,                                        // Query for available features
	NULL,                                        // Call a feature
	NULL,                                        // Send a keystroke
	NULL                                         // Screenshot
};

G_MODULE_EXPORT gboolean
remmina_plugin_entry(RemminaPluginService *service)
{
	TRACE_CALL(__func__);
	remmina_plugin_service = service;

	bindtextdomain(GETTEXT_PACKAGE, REMMINA_LOCALEDIR);
	bind_textdomain_codeset(GETTEXT_PACKAGE, "UTF-8");

	if (!service->register_plugin((RemminaPlugin *) &remmina_plugin_terminal))
	{
		return FALSE;
	}

	return TRUE;
}
