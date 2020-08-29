/* create a sshfs filesystem

   Copyright (C) 2020. Junling Ma <junlingm@gmail.com>

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
   
#include <hurd.h>
#include <hurd/iohelp.h>

/* read an (base 10) integer from s, and move s forward */
static int parse_int(const char **s)
{
  if (!**s || **s < '0' || **s > '9')
    return -1;
  int v = 0;
  for (; **s && **s >= '0' && **s <= '9'; ++*s)
    v = (v * 10) + **s - '0';
  return v;
}

/* parse the output of the id command */
struct iouser *sshfs_parse_id(const char *s)
{
  char *p = strstr(s, "uid=");
  if (p == NULL)
    return NULL;
  s = p + 4;
  uid_t uid = parse_int(&s);
  if (uid == -1)
    return NULL;
  p = strstr(s, "groups=");
  s = p + 7;
  gid_t gids[100];
  int n;
  for (n = 0; n < 100 && p != NULL; ++n)
    {
      gids[n] = parse_int(&s);
      if (gids[n] == -1)
        break;
      p = strstr(s, ",");
      if (p == NULL)
        ++n;
      else
        s = p + 1;
    }
  if (n == 0)
    return NULL;
  struct iouser *user;
  if (iohelp_create_complex_iouser(&user, &uid, 1, gids, n))
    return NULL;
  return user;
}

/* replace the remote user UID and GID by the ones in LOCAL_USER if they match REMOTE_USER
 * otherwise, return -1 in BOTH UID and GID */
error_t sshfs_replace_user(struct iouser *remote_user, struct iouser *local_user, uid_t *uid, gid_t *gid)
{
  *uid = (idvec_contains(remote_user->uids, *uid)) ? local_user->uids->ids[0] : -1;
  *gid = (idvec_contains(remote_user->gids, *gid)) ? local_user->gids->ids[0] : -1;
  return ESUCCESS;
}
