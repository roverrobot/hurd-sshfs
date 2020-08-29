/* sshfs inode hashing facility

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
#include <hurd/ihash.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>

typedef uint64_t ino64_t;
/* Calculate NAME_PTR's hash value.  */
static hurd_ihash_key_t ihash_hash (const void *name)
{
  return (hurd_ihash_key_t) hurd_ihash_hash32 (name, strlen ((const char*)name), 0);
}

/* Compare two names which are used as keys.  */
static int ihash_compare (const void *key1, const void *key2)
{
  return strcmp ((const char *)key1, (const char *)key2) == 0;
}

static void cleanup(hurd_ihash_value_t value, void *arg)
{
  free((void*)(uintptr_t)value);
}

/* The following declarations exist because libssh and hurd conflict on the definition of
 * socket. So libssl and hurd heads caanot be included together */

/* create the inode hash table */
struct hurd_ihash *sshfs_getihash()
{
  struct hurd_ihash *hash;
  error_t err = hurd_ihash_create (&hash, HURD_IHASH_NO_LOCP);
  if (err)
    return NULL;
  hurd_ihash_set_gki (hash, ihash_hash, ihash_compare);  
  hurd_ihash_set_cleanup (hash, cleanup, NULL);
  return hash;
}

/* return the inode corresponding to PATH in INO by looking up in INODES */
error_t sshfs_getinode(struct hurd_ihash *inodes, char *path, ino64_t *ino)
{
  error_t err = ESUCCESS;
  *ino = (uintptr_t)hurd_ihash_find(inodes, (hurd_ihash_key_t)path);
  if (*ino == 0)
    {
      err = hurd_ihash_add (inodes, (hurd_ihash_key_t)path, path);
      if (!err)
        *ino = (uintptr_t)path;
    }
  else
    free(path);
  return err;
}

/* drop the inode INO from the hash table INODES */
void sshfs_dropinode(struct hurd_ihash *inodes, ino64_t ino)
{
  hurd_ihash_remove(inodes, (hurd_ihash_key_t)ino);
}
