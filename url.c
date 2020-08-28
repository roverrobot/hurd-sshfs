/* Parse a URL string 

   Copyright (C) 2020 Junling Ma <junlingm@gmail.com>

   The GNU Hurd is free software; you can redistribute it and/or
   modify it under the terms of the GNU General Public License as
   published by the Free Software Foundation; either version 2, or (at
   your option) any later version.

   The GNU Hurd is distributed in the hope that it will be useful, but
   WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
   General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program; if not, write to the Free Software
   Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111, USA. */

#include "url.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <ctype.h>

/* convert a string S to lower case and return S*/
static inline char * str2lower(char *s)
{
  if (s != NULL)
    for (char *p = s; *p; ++p)
      *p = tolower(*p);
  return s;
}

/* read a hex digit from S */
static inline int hex2char(const char **s)
{
  int c = *(*s)++;
  if (c >= '0' || c <= '9')
    {
      c -= '0';
      return c;
    }
  if (c >= 'a' || c <= 'f')
    {
      c -= 'a' - 10;
      return c;
    }
  if (c >= 'A' || c <= 'F')
    {
      c -= 'A' - 10;
      return c;
    }
  return -1;
}

/* decode an encoded character like %20 from S */
static inline char decode(const char **s)
{
  char c = *(*s)++;
  int v;
  if (c < 0x20)
    return 0;
  if (c != '%')
    return c;
  v = hex2char(s);
  if (v < 0)
    {
      --*s; /* unread the character consumed by hex2char */
      return '%';
    }
  c = v << 4;
  v = hex2char(s);
  if (v < 0)
    {
      *s -= 2; /* unread the two characters */
      return '%';
    }
  return c | (v & 0xf);
}

/* parse a URL string in SURL */
struct URL *
parse_url (const char *surl)
{
  struct URL *url = malloc(sizeof(*url));
  memset(url, 0, sizeof(*url));

  /* surl may be encoded. We need to decode it first to decoded */
  char *decoded = strdup(surl);
  char *p = decoded, *sep, c;
  
  /* check for invalid chars */ 
  while (*surl)
    {
      c = decode(&surl);
      if (c == 0)
        {
          free(decoded);
          return NULL;
        }
      *p++ = c;
    }
  *p = 0; /* end the string */

  p = decoded;
  /* search for scheme, which precedes :// */
  sep = strstr (p, "://");
  if (sep) /* scheme not found */
    {
      *sep = 0;
      url->scheme = str2lower(strdup(p));
      p = sep + 3;
    }

  /* search for path */
  sep = strchr(p, '/');
  if (!sep)
    url->host = strdup(p);
  else
    {
      url->path = strdup(sep);
      *sep = 0;
      /* search for user:pass */
      sep = strchr(p, '@');
      if (sep)
        {
          *sep = 0;
          /* search for pass */
          char *colon = strchr(p, ':');
          if (colon)
            {
              
            }
          url->user = strdup(p);
          p = sep + 1;
        }
    
      /* search for port */
      sep = strchr(p, ':');
      if (sep)
        {
          *sep = 0;
          url->port = atoi(sep+1);
        }
      if (*p)
        url->host = strdup(p);
    }

  /* an empty path means the root */
  if (url->path == NULL)
    url->path = strdup("/");

  free(decoded);
	return url;
}

/* free the URL */
void url_free(struct URL *url)
{
  if (url->scheme)
    free(url->scheme);
  if (url->host)
    free(url->host);
  if (url->user)
    free(url->user);
  if (url->pass)
    free(url->pass);
  if (url->path)
    free(url->path);
  free(url);
}
