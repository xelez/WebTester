/*
 * DO NOT EDIT THIS FILE - it is generated by Glade.
 */

#ifdef HAVE_CONFIG_H
#  include <config.h>
#endif

#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <string.h>
#include <stdio.h>

#include <gdk/gdkkeysyms.h>
#include <gtk/gtk.h>

#include "callbacks.h"
#include "interface.h"
#include "support.h"

#define GLADE_HOOKUP_OBJECT(component,widget,name) \
  g_object_set_data_full (G_OBJECT (component), name, \
    gtk_widget_ref (widget), (GDestroyNotify) gtk_widget_unref)

#define GLADE_HOOKUP_OBJECT_NO_REF(component,widget,name) \
  g_object_set_data (G_OBJECT (component), name, widget)

GtkWidget*
create_main_window (void)
{
  GtkWidget *main_window;
  GdkPixbuf *main_window_icon_pixbuf;
  GtkWidget *hbox12;
  GtkWidget *vbox30;
  GtkWidget *expander1;
  GtkWidget *hbox6;
  GtkWidget *label11;
  GtkWidget *vbox5;
  GtkWidget *hbox7;
  GtkWidget *label12;
  GtkWidget *hbox9;
  GtkWidget *server;
  GtkWidget *connect;
  GtkWidget *alignment7;
  GtkWidget *hbox11;
  GtkWidget *image7;
  GtkWidget *label18;
  GtkWidget *login_at_connect;
  GtkWidget *hbox8;
  GtkWidget *label14;
  GtkWidget *table1;
  GtkWidget *label13;
  GtkWidget *label15;
  GtkWidget *login;
  GtkWidget *password;
  GtkWidget *label17;
  GtkWidget *label10;
  GtkWidget *hbox1;
  GtkWidget *frame1;
  GtkWidget *alignment3;
  GtkWidget *console_tabs;
  GtkWidget *alignment4;
  GtkWidget *vbox1;
  GtkWidget *console_scroll;
  GtkWidget *console_view;
  GtkWidget *label4;
  GtkWidget *hbox2;
  GtkWidget *image1;
  GtkWidget *cmd_entry;
  GtkWidget *btn_cmdSend;
  GtkWidget *label6;
  GtkWidget *alignment5;
  GtkWidget *pipe_scroll;
  GtkWidget *pipe_view;
  GtkWidget *label7;
  GtkWidget *label2;
  GtkWidget *vbox2;
  GtkWidget *frame2;
  GtkWidget *alignment2;
  GtkWidget *vbox3;
  GtkWidget *ctrlButton_0;
  GtkWidget *ctrlButton_1;
  GtkWidget *ctrlButton_2;
  GtkWidget *ctrlButton_3;
  GtkWidget *alignment6;
  GtkWidget *hbox3;
  GtkWidget *image2;
  GtkWidget *hbox4;
  GtkWidget *queue_progress;
  GtkWidget *queue_usage;
  GtkWidget *label9;
  GtkWidget *image3;
  GtkWidget *hbox5;
  GtkWidget *belts_progress;
  GtkWidget *belts_usage;
  GtkWidget *ctrlButton_4;
  GtkWidget *ctrlButton_5;
  GtkWidget *ctrlButton_6;
  GtkWidget *label5;
  GtkWidget *label3;
  GtkWidget *label8;
  GtkWidget *image6;

  main_window = gtk_window_new (GTK_WINDOW_TOPLEVEL);
  gtk_window_set_title (GTK_WINDOW (main_window), _("WebTester Server Console"));
  gtk_window_set_resizable (GTK_WINDOW (main_window), FALSE);
  main_window_icon_pixbuf = create_pixbuf ("wt32.png");
  if (main_window_icon_pixbuf)
    {
      gtk_window_set_icon (GTK_WINDOW (main_window), main_window_icon_pixbuf);
      gdk_pixbuf_unref (main_window_icon_pixbuf);
    }

  hbox12 = gtk_hbox_new (FALSE, 0);
  gtk_widget_show (hbox12);
  gtk_container_add (GTK_CONTAINER (main_window), hbox12);

  vbox30 = gtk_vbox_new (FALSE, 0);
  gtk_widget_show (vbox30);
  gtk_box_pack_start (GTK_BOX (hbox12), vbox30, TRUE, TRUE, 0);

  expander1 = gtk_expander_new (NULL);
  gtk_widget_show (expander1);
  gtk_box_pack_start (GTK_BOX (vbox30), expander1, FALSE, TRUE, 0);
  gtk_widget_set_size_request (expander1, 640, -1);
  gtk_expander_set_expanded (GTK_EXPANDER (expander1), TRUE);

  hbox6 = gtk_hbox_new (FALSE, 2);
  gtk_widget_show (hbox6);
  gtk_container_add (GTK_CONTAINER (expander1), hbox6);

  label11 = gtk_label_new ("");
  gtk_widget_show (label11);
  gtk_box_pack_start (GTK_BOX (hbox6), label11, FALSE, FALSE, 0);
  gtk_widget_set_size_request (label11, 16, -1);

  vbox5 = gtk_vbox_new (FALSE, 0);
  gtk_widget_show (vbox5);
  gtk_box_pack_start (GTK_BOX (hbox6), vbox5, FALSE, TRUE, 0);

  hbox7 = gtk_hbox_new (FALSE, 6);
  gtk_widget_show (hbox7);
  gtk_box_pack_start (GTK_BOX (vbox5), hbox7, TRUE, TRUE, 0);

  label12 = gtk_label_new (_("Server:Port"));
  gtk_widget_show (label12);
  gtk_box_pack_start (GTK_BOX (hbox7), label12, FALSE, FALSE, 0);

  hbox9 = gtk_hbox_new (FALSE, 0);
  gtk_widget_show (hbox9);
  gtk_box_pack_start (GTK_BOX (hbox7), hbox9, TRUE, TRUE, 0);

  server = gtk_entry_new ();
  gtk_widget_show (server);
  gtk_box_pack_start (GTK_BOX (hbox9), server, TRUE, TRUE, 0);

  connect = gtk_toggle_button_new ();
  gtk_widget_show (connect);
  gtk_box_pack_start (GTK_BOX (hbox9), connect, FALSE, FALSE, 0);

  alignment7 = gtk_alignment_new (0.5, 0.5, 0, 0);
  gtk_widget_show (alignment7);
  gtk_container_add (GTK_CONTAINER (connect), alignment7);

  hbox11 = gtk_hbox_new (FALSE, 2);
  gtk_widget_show (hbox11);
  gtk_container_add (GTK_CONTAINER (alignment7), hbox11);

  image7 = create_pixmap (main_window, "connect.png");
  gtk_widget_show (image7);
  gtk_box_pack_start (GTK_BOX (hbox11), image7, FALSE, FALSE, 0);

  label18 = gtk_label_new (_("Connect"));
  gtk_widget_show (label18);
  gtk_box_pack_start (GTK_BOX (hbox11), label18, FALSE, FALSE, 0);

  login_at_connect = gtk_check_button_new_with_mnemonic (_("Login at connect"));
  gtk_widget_show (login_at_connect);
  gtk_box_pack_start (GTK_BOX (vbox5), login_at_connect, FALSE, FALSE, 0);

  hbox8 = gtk_hbox_new (FALSE, 0);
  gtk_widget_show (hbox8);
  gtk_box_pack_start (GTK_BOX (hbox6), hbox8, TRUE, TRUE, 0);

  label14 = gtk_label_new ("");
  gtk_widget_show (label14);
  gtk_box_pack_start (GTK_BOX (hbox8), label14, FALSE, FALSE, 0);
  gtk_widget_set_size_request (label14, 8, -1);

  table1 = gtk_table_new (2, 2, FALSE);
  gtk_widget_show (table1);
  gtk_box_pack_start (GTK_BOX (hbox8), table1, TRUE, TRUE, 0);
  gtk_table_set_col_spacings (GTK_TABLE (table1), 4);

  label13 = gtk_label_new (_("Login"));
  gtk_widget_show (label13);
  gtk_table_attach (GTK_TABLE (table1), label13, 0, 1, 0, 1,
                    (GtkAttachOptions) (GTK_FILL),
                    (GtkAttachOptions) (0), 0, 0);
  gtk_misc_set_alignment (GTK_MISC (label13), 0, 0.5);

  label15 = gtk_label_new (_("Password"));
  gtk_widget_show (label15);
  gtk_table_attach (GTK_TABLE (table1), label15, 0, 1, 1, 2,
                    (GtkAttachOptions) (GTK_FILL),
                    (GtkAttachOptions) (0), 0, 0);
  gtk_misc_set_alignment (GTK_MISC (label15), 0, 0.5);

  login = gtk_entry_new ();
  gtk_widget_show (login);
  gtk_table_attach (GTK_TABLE (table1), login, 1, 2, 0, 1,
                    (GtkAttachOptions) (GTK_EXPAND | GTK_FILL),
                    (GtkAttachOptions) (0), 0, 0);
  gtk_widget_set_sensitive (login, FALSE);

  password = gtk_entry_new ();
  gtk_widget_show (password);
  gtk_table_attach (GTK_TABLE (table1), password, 1, 2, 1, 2,
                    (GtkAttachOptions) (GTK_EXPAND | GTK_FILL),
                    (GtkAttachOptions) (0), 0, 0);
  gtk_widget_set_sensitive (password, FALSE);
  gtk_entry_set_visibility (GTK_ENTRY (password), FALSE);

  label17 = gtk_label_new ("");
  gtk_widget_show (label17);
  gtk_box_pack_start (GTK_BOX (hbox8), label17, FALSE, FALSE, 0);
  gtk_widget_set_size_request (label17, 8, -1);

  label10 = gtk_label_new (_("Connection"));
  gtk_widget_show (label10);
  gtk_expander_set_label_widget (GTK_EXPANDER (expander1), label10);

  hbox1 = gtk_hbox_new (FALSE, 2);
  gtk_widget_show (hbox1);
  gtk_box_pack_start (GTK_BOX (vbox30), hbox1, TRUE, TRUE, 0);

  frame1 = gtk_frame_new (NULL);
  gtk_widget_show (frame1);
  gtk_box_pack_start (GTK_BOX (hbox1), frame1, TRUE, TRUE, 0);
  gtk_frame_set_label_align (GTK_FRAME (frame1), 0.5, 0.5);

  alignment3 = gtk_alignment_new (0.5, 0.5, 1, 1);
  gtk_widget_show (alignment3);
  gtk_container_add (GTK_CONTAINER (frame1), alignment3);
  gtk_alignment_set_padding (GTK_ALIGNMENT (alignment3), 2, 4, 4, 4);

  console_tabs = gtk_notebook_new ();
  gtk_widget_show (console_tabs);
  gtk_container_add (GTK_CONTAINER (alignment3), console_tabs);

  alignment4 = gtk_alignment_new (0.5, 0.5, 1, 1);
  gtk_widget_show (alignment4);
  gtk_container_add (GTK_CONTAINER (console_tabs), alignment4);
  gtk_notebook_set_tab_label_packing (GTK_NOTEBOOK (console_tabs), alignment4,
                                      TRUE, TRUE, GTK_PACK_START);
  gtk_alignment_set_padding (GTK_ALIGNMENT (alignment4), 2, 2, 2, 2);

  vbox1 = gtk_vbox_new (FALSE, 0);
  gtk_widget_show (vbox1);
  gtk_container_add (GTK_CONTAINER (alignment4), vbox1);

  console_scroll = gtk_scrolled_window_new (NULL, NULL);
  gtk_widget_show (console_scroll);
  gtk_box_pack_start (GTK_BOX (vbox1), console_scroll, TRUE, TRUE, 0);
  gtk_scrolled_window_set_policy (GTK_SCROLLED_WINDOW (console_scroll), GTK_POLICY_AUTOMATIC, GTK_POLICY_ALWAYS);
  gtk_scrolled_window_set_shadow_type (GTK_SCROLLED_WINDOW (console_scroll), GTK_SHADOW_IN);

  console_view = gtk_text_view_new ();
  gtk_widget_show (console_view);
  gtk_container_add (GTK_CONTAINER (console_scroll), console_view);
  gtk_text_view_set_editable (GTK_TEXT_VIEW (console_view), FALSE);
  gtk_text_view_set_wrap_mode (GTK_TEXT_VIEW (console_view), GTK_WRAP_CHAR);
  gtk_text_view_set_pixels_above_lines (GTK_TEXT_VIEW (console_view), 4);
  gtk_text_view_set_pixels_below_lines (GTK_TEXT_VIEW (console_view), 4);
  gtk_text_view_set_left_margin (GTK_TEXT_VIEW (console_view), 4);
  gtk_text_view_set_right_margin (GTK_TEXT_VIEW (console_view), 4);

  label4 = gtk_label_new ("");
  gtk_widget_show (label4);
  gtk_box_pack_start (GTK_BOX (vbox1), label4, FALSE, FALSE, 0);
  gtk_widget_set_size_request (label4, 360, 3);

  hbox2 = gtk_hbox_new (FALSE, 4);
  gtk_widget_show (hbox2);
  gtk_box_pack_start (GTK_BOX (vbox1), hbox2, FALSE, TRUE, 0);

  image1 = create_pixmap (main_window, "go.png");
  gtk_widget_show (image1);
  gtk_box_pack_start (GTK_BOX (hbox2), image1, FALSE, TRUE, 0);

  cmd_entry = gtk_entry_new ();
  gtk_widget_show (cmd_entry);
  gtk_box_pack_start (GTK_BOX (hbox2), cmd_entry, TRUE, TRUE, 0);

  btn_cmdSend = gtk_button_new_with_mnemonic (_("Send"));
  gtk_widget_show (btn_cmdSend);
  gtk_box_pack_start (GTK_BOX (hbox2), btn_cmdSend, FALSE, FALSE, 0);

  label6 = gtk_label_new (_("User's console"));
  gtk_widget_show (label6);
  gtk_notebook_set_tab_label (GTK_NOTEBOOK (console_tabs), gtk_notebook_get_nth_page (GTK_NOTEBOOK (console_tabs), 0), label6);

  alignment5 = gtk_alignment_new (0.5, 0.5, 1, 1);
  gtk_widget_show (alignment5);
  gtk_container_add (GTK_CONTAINER (console_tabs), alignment5);
  gtk_notebook_set_tab_label_packing (GTK_NOTEBOOK (console_tabs), alignment5,
                                      TRUE, TRUE, GTK_PACK_START);
  gtk_alignment_set_padding (GTK_ALIGNMENT (alignment5), 2, 2, 2, 2);

  pipe_scroll = gtk_scrolled_window_new (NULL, NULL);
  gtk_widget_show (pipe_scroll);
  gtk_container_add (GTK_CONTAINER (alignment5), pipe_scroll);
  gtk_scrolled_window_set_policy (GTK_SCROLLED_WINDOW (pipe_scroll), GTK_POLICY_AUTOMATIC, GTK_POLICY_ALWAYS);
  gtk_scrolled_window_set_shadow_type (GTK_SCROLLED_WINDOW (pipe_scroll), GTK_SHADOW_IN);

  pipe_view = gtk_text_view_new ();
  gtk_widget_show (pipe_view);
  gtk_container_add (GTK_CONTAINER (pipe_scroll), pipe_view);
  gtk_text_view_set_editable (GTK_TEXT_VIEW (pipe_view), FALSE);
  gtk_text_view_set_wrap_mode (GTK_TEXT_VIEW (pipe_view), GTK_WRAP_CHAR);
  gtk_text_view_set_pixels_above_lines (GTK_TEXT_VIEW (pipe_view), 4);
  gtk_text_view_set_pixels_below_lines (GTK_TEXT_VIEW (pipe_view), 4);
  gtk_text_view_set_left_margin (GTK_TEXT_VIEW (pipe_view), 4);
  gtk_text_view_set_right_margin (GTK_TEXT_VIEW (pipe_view), 4);

  label7 = gtk_label_new (_("Pipe"));
  gtk_widget_show (label7);
  gtk_notebook_set_tab_label (GTK_NOTEBOOK (console_tabs), gtk_notebook_get_nth_page (GTK_NOTEBOOK (console_tabs), 1), label7);
  gtk_label_set_line_wrap (GTK_LABEL (label7), TRUE);

  label2 = gtk_label_new (_("<b>WebTester</b> Console"));
  gtk_widget_show (label2);
  gtk_frame_set_label_widget (GTK_FRAME (frame1), label2);
  gtk_label_set_use_markup (GTK_LABEL (label2), TRUE);

  vbox2 = gtk_vbox_new (FALSE, 0);
  gtk_widget_show (vbox2);
  gtk_box_pack_start (GTK_BOX (hbox1), vbox2, FALSE, TRUE, 0);

  frame2 = gtk_frame_new (NULL);
  gtk_widget_show (frame2);
  gtk_box_pack_start (GTK_BOX (vbox2), frame2, TRUE, TRUE, 0);
  gtk_frame_set_label_align (GTK_FRAME (frame2), 0.5, 0.5);

  alignment2 = gtk_alignment_new (0.5, 0.5, 1, 1);
  gtk_widget_show (alignment2);
  gtk_container_add (GTK_CONTAINER (frame2), alignment2);
  gtk_alignment_set_padding (GTK_ALIGNMENT (alignment2), 2, 4, 4, 4);

  vbox3 = gtk_vbox_new (FALSE, 0);
  gtk_widget_show (vbox3);
  gtk_container_add (GTK_CONTAINER (alignment2), vbox3);

  ctrlButton_0 = gtk_button_new_with_mnemonic (_("(Unassigned)"));
  gtk_widget_show (ctrlButton_0);
  gtk_box_pack_start (GTK_BOX (vbox3), ctrlButton_0, FALSE, FALSE, 0);

  ctrlButton_1 = gtk_button_new_with_mnemonic (_("(Unassigned)"));
  gtk_widget_show (ctrlButton_1);
  gtk_box_pack_start (GTK_BOX (vbox3), ctrlButton_1, FALSE, FALSE, 0);

  ctrlButton_2 = gtk_button_new_with_mnemonic (_("(Unassigned)"));
  gtk_widget_show (ctrlButton_2);
  gtk_box_pack_start (GTK_BOX (vbox3), ctrlButton_2, FALSE, FALSE, 0);

  ctrlButton_3 = gtk_button_new_with_mnemonic (_("(Unassigned)"));
  gtk_widget_show (ctrlButton_3);
  gtk_box_pack_start (GTK_BOX (vbox3), ctrlButton_3, FALSE, FALSE, 0);

  alignment6 = gtk_alignment_new (0.5, 0.5, 1, 1);
  gtk_widget_show (alignment6);
  gtk_box_pack_start (GTK_BOX (vbox3), alignment6, FALSE, FALSE, 0);
  gtk_alignment_set_padding (GTK_ALIGNMENT (alignment6), 2, 2, 0, 0);

  hbox3 = gtk_hbox_new (FALSE, 0);
  gtk_widget_show (hbox3);
  gtk_container_add (GTK_CONTAINER (alignment6), hbox3);

  image2 = create_pixmap (main_window, "queue.png");
  gtk_widget_show (image2);
  gtk_box_pack_start (GTK_BOX (hbox3), image2, FALSE, TRUE, 0);

  hbox4 = gtk_hbox_new (FALSE, 1);
  gtk_widget_show (hbox4);
  gtk_box_pack_start (GTK_BOX (hbox3), hbox4, FALSE, TRUE, 0);

  queue_progress = gtk_progress_bar_new ();
  gtk_widget_show (queue_progress);
  gtk_box_pack_start (GTK_BOX (hbox4), queue_progress, FALSE, FALSE, 0);
  gtk_widget_set_size_request (queue_progress, 10, 48);
  gtk_progress_bar_set_orientation (GTK_PROGRESS_BAR (queue_progress), GTK_PROGRESS_BOTTOM_TO_TOP);

  queue_usage = gtk_progress_bar_new ();
  gtk_widget_show (queue_usage);
  gtk_box_pack_start (GTK_BOX (hbox4), queue_usage, FALSE, FALSE, 0);
  gtk_widget_set_size_request (queue_usage, 10, 48);
  gtk_progress_bar_set_orientation (GTK_PROGRESS_BAR (queue_usage), GTK_PROGRESS_BOTTOM_TO_TOP);

  label9 = gtk_label_new ("");
  gtk_widget_show (label9);
  gtk_box_pack_start (GTK_BOX (hbox3), label9, FALSE, FALSE, 0);
  gtk_widget_set_size_request (label9, 6, -1);

  image3 = create_pixmap (main_window, "belts.png");
  gtk_widget_show (image3);
  gtk_box_pack_start (GTK_BOX (hbox3), image3, FALSE, FALSE, 0);

  hbox5 = gtk_hbox_new (FALSE, 1);
  gtk_widget_show (hbox5);
  gtk_box_pack_start (GTK_BOX (hbox3), hbox5, FALSE, FALSE, 0);

  belts_progress = gtk_progress_bar_new ();
  gtk_widget_show (belts_progress);
  gtk_box_pack_start (GTK_BOX (hbox5), belts_progress, FALSE, FALSE, 0);
  gtk_widget_set_size_request (belts_progress, 10, 48);
  gtk_progress_bar_set_orientation (GTK_PROGRESS_BAR (belts_progress), GTK_PROGRESS_BOTTOM_TO_TOP);

  belts_usage = gtk_progress_bar_new ();
  gtk_widget_show (belts_usage);
  gtk_box_pack_start (GTK_BOX (hbox5), belts_usage, FALSE, FALSE, 0);
  gtk_widget_set_size_request (belts_usage, 10, 48);
  gtk_progress_bar_set_orientation (GTK_PROGRESS_BAR (belts_usage), GTK_PROGRESS_BOTTOM_TO_TOP);

  ctrlButton_4 = gtk_button_new_with_mnemonic (_("(Unassigned)"));
  gtk_widget_show (ctrlButton_4);
  gtk_box_pack_start (GTK_BOX (vbox3), ctrlButton_4, FALSE, FALSE, 0);

  ctrlButton_5 = gtk_button_new_with_mnemonic (_("(Unassigned)"));
  gtk_widget_show (ctrlButton_5);
  gtk_box_pack_start (GTK_BOX (vbox3), ctrlButton_5, FALSE, FALSE, 0);

  ctrlButton_6 = gtk_button_new_with_mnemonic (_("(Unassigned)"));
  gtk_widget_show (ctrlButton_6);
  gtk_box_pack_start (GTK_BOX (vbox3), ctrlButton_6, FALSE, FALSE, 0);

  label5 = gtk_label_new ("");
  gtk_widget_show (label5);
  gtk_box_pack_start (GTK_BOX (vbox3), label5, TRUE, FALSE, 0);

  label3 = gtk_label_new (_("Control"));
  gtk_widget_show (label3);
  gtk_frame_set_label_widget (GTK_FRAME (frame2), label3);
  gtk_label_set_use_markup (GTK_LABEL (label3), TRUE);

  label8 = gtk_label_new (_("2007 (c) nazgul"));
  gtk_widget_show (label8);
  gtk_box_pack_start (GTK_BOX (vbox2), label8, FALSE, FALSE, 0);

  image6 = create_pixmap (main_window, "wt.png");
  gtk_widget_show (image6);
  gtk_box_pack_start (GTK_BOX (hbox12), image6, TRUE, TRUE, 0);

  g_signal_connect ((gpointer) main_window, "remove",
                    G_CALLBACK (on_main_window_remove),
                    NULL);
  g_signal_connect ((gpointer) connect, "toggled",
                    G_CALLBACK (on_connect_toggled),
                    NULL);
  g_signal_connect ((gpointer) login_at_connect, "toggled",
                    G_CALLBACK (on_login_at_connect_toggled),
                    NULL);
  g_signal_connect ((gpointer) cmd_entry, "key_press_event",
                    G_CALLBACK (on_cmd_entry_key_press_event),
                    NULL);
  g_signal_connect ((gpointer) btn_cmdSend, "clicked",
                    G_CALLBACK (on_btn_cmdSend_clicked),
                    NULL);
  g_signal_connect ((gpointer) ctrlButton_0, "clicked",
                    G_CALLBACK (on_ctrlButton_clicked),
                    NULL);
  g_signal_connect ((gpointer) ctrlButton_1, "clicked",
                    G_CALLBACK (on_ctrlButton_clicked),
                    NULL);
  g_signal_connect ((gpointer) ctrlButton_2, "clicked",
                    G_CALLBACK (on_ctrlButton_clicked),
                    NULL);
  g_signal_connect ((gpointer) ctrlButton_3, "clicked",
                    G_CALLBACK (on_ctrlButton_clicked),
                    NULL);
  g_signal_connect ((gpointer) ctrlButton_4, "clicked",
                    G_CALLBACK (on_ctrlButton_clicked),
                    NULL);
  g_signal_connect ((gpointer) ctrlButton_5, "clicked",
                    G_CALLBACK (on_ctrlButton_clicked),
                    NULL);
  g_signal_connect ((gpointer) ctrlButton_6, "clicked",
                    G_CALLBACK (on_ctrlButton_clicked),
                    NULL);

  /* Store pointers to all widgets, for use by lookup_widget(). */
  GLADE_HOOKUP_OBJECT_NO_REF (main_window, main_window, "main_window");
  GLADE_HOOKUP_OBJECT (main_window, hbox12, "hbox12");
  GLADE_HOOKUP_OBJECT (main_window, vbox30, "vbox30");
  GLADE_HOOKUP_OBJECT (main_window, expander1, "expander1");
  GLADE_HOOKUP_OBJECT (main_window, hbox6, "hbox6");
  GLADE_HOOKUP_OBJECT (main_window, label11, "label11");
  GLADE_HOOKUP_OBJECT (main_window, vbox5, "vbox5");
  GLADE_HOOKUP_OBJECT (main_window, hbox7, "hbox7");
  GLADE_HOOKUP_OBJECT (main_window, label12, "label12");
  GLADE_HOOKUP_OBJECT (main_window, hbox9, "hbox9");
  GLADE_HOOKUP_OBJECT (main_window, server, "server");
  GLADE_HOOKUP_OBJECT (main_window, connect, "connect");
  GLADE_HOOKUP_OBJECT (main_window, alignment7, "alignment7");
  GLADE_HOOKUP_OBJECT (main_window, hbox11, "hbox11");
  GLADE_HOOKUP_OBJECT (main_window, image7, "image7");
  GLADE_HOOKUP_OBJECT (main_window, label18, "label18");
  GLADE_HOOKUP_OBJECT (main_window, login_at_connect, "login_at_connect");
  GLADE_HOOKUP_OBJECT (main_window, hbox8, "hbox8");
  GLADE_HOOKUP_OBJECT (main_window, label14, "label14");
  GLADE_HOOKUP_OBJECT (main_window, table1, "table1");
  GLADE_HOOKUP_OBJECT (main_window, label13, "label13");
  GLADE_HOOKUP_OBJECT (main_window, label15, "label15");
  GLADE_HOOKUP_OBJECT (main_window, login, "login");
  GLADE_HOOKUP_OBJECT (main_window, password, "password");
  GLADE_HOOKUP_OBJECT (main_window, label17, "label17");
  GLADE_HOOKUP_OBJECT (main_window, label10, "label10");
  GLADE_HOOKUP_OBJECT (main_window, hbox1, "hbox1");
  GLADE_HOOKUP_OBJECT (main_window, frame1, "frame1");
  GLADE_HOOKUP_OBJECT (main_window, alignment3, "alignment3");
  GLADE_HOOKUP_OBJECT (main_window, console_tabs, "console_tabs");
  GLADE_HOOKUP_OBJECT (main_window, alignment4, "alignment4");
  GLADE_HOOKUP_OBJECT (main_window, vbox1, "vbox1");
  GLADE_HOOKUP_OBJECT (main_window, console_scroll, "console_scroll");
  GLADE_HOOKUP_OBJECT (main_window, console_view, "console_view");
  GLADE_HOOKUP_OBJECT (main_window, label4, "label4");
  GLADE_HOOKUP_OBJECT (main_window, hbox2, "hbox2");
  GLADE_HOOKUP_OBJECT (main_window, image1, "image1");
  GLADE_HOOKUP_OBJECT (main_window, cmd_entry, "cmd_entry");
  GLADE_HOOKUP_OBJECT (main_window, btn_cmdSend, "btn_cmdSend");
  GLADE_HOOKUP_OBJECT (main_window, label6, "label6");
  GLADE_HOOKUP_OBJECT (main_window, alignment5, "alignment5");
  GLADE_HOOKUP_OBJECT (main_window, pipe_scroll, "pipe_scroll");
  GLADE_HOOKUP_OBJECT (main_window, pipe_view, "pipe_view");
  GLADE_HOOKUP_OBJECT (main_window, label7, "label7");
  GLADE_HOOKUP_OBJECT (main_window, label2, "label2");
  GLADE_HOOKUP_OBJECT (main_window, vbox2, "vbox2");
  GLADE_HOOKUP_OBJECT (main_window, frame2, "frame2");
  GLADE_HOOKUP_OBJECT (main_window, alignment2, "alignment2");
  GLADE_HOOKUP_OBJECT (main_window, vbox3, "vbox3");
  GLADE_HOOKUP_OBJECT (main_window, ctrlButton_0, "ctrlButton_0");
  GLADE_HOOKUP_OBJECT (main_window, ctrlButton_1, "ctrlButton_1");
  GLADE_HOOKUP_OBJECT (main_window, ctrlButton_2, "ctrlButton_2");
  GLADE_HOOKUP_OBJECT (main_window, ctrlButton_3, "ctrlButton_3");
  GLADE_HOOKUP_OBJECT (main_window, alignment6, "alignment6");
  GLADE_HOOKUP_OBJECT (main_window, hbox3, "hbox3");
  GLADE_HOOKUP_OBJECT (main_window, image2, "image2");
  GLADE_HOOKUP_OBJECT (main_window, hbox4, "hbox4");
  GLADE_HOOKUP_OBJECT (main_window, queue_progress, "queue_progress");
  GLADE_HOOKUP_OBJECT (main_window, queue_usage, "queue_usage");
  GLADE_HOOKUP_OBJECT (main_window, label9, "label9");
  GLADE_HOOKUP_OBJECT (main_window, image3, "image3");
  GLADE_HOOKUP_OBJECT (main_window, hbox5, "hbox5");
  GLADE_HOOKUP_OBJECT (main_window, belts_progress, "belts_progress");
  GLADE_HOOKUP_OBJECT (main_window, belts_usage, "belts_usage");
  GLADE_HOOKUP_OBJECT (main_window, ctrlButton_4, "ctrlButton_4");
  GLADE_HOOKUP_OBJECT (main_window, ctrlButton_5, "ctrlButton_5");
  GLADE_HOOKUP_OBJECT (main_window, ctrlButton_6, "ctrlButton_6");
  GLADE_HOOKUP_OBJECT (main_window, label5, "label5");
  GLADE_HOOKUP_OBJECT (main_window, label3, "label3");
  GLADE_HOOKUP_OBJECT (main_window, label8, "label8");
  GLADE_HOOKUP_OBJECT (main_window, image6, "image6");

  return main_window;
}

