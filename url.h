/* the URL parsing facility

   Copyright (C) 2020 Junling Ma <junlingm@gmail.com>

   This program is free software; you can redistribute it and/or
   modify it under the terms of the GNU General Public License as
   published by the Free Software Foundation; either version 2, or (at
   your option) any later version.

   This program is distributed in the hope that it will be useful, but
   WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
   General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program; if not, write to the Free Software
   Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA. */

#ifndef __URL_H__
#define __URL_H__

/* a URL */
struct URL {
  char *scheme;
  char *host;
  char *path;
  char *user;
  char *pass;
  int port;
};

/* parse a string into a struct URL */
struct URL *parse_url(const char *url_string);
/* free url returned from parse_url */
void url_free(struct URL*);

#endif