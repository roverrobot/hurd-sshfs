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

#ifndef __SSHFS_H__
#define __SSHFS_H__

#include "url.h"
#include <stdio.h>

struct sshfs *sshfs_create(struct URL *url);

extern FILE *sshfs_log_file;
#define sshfs_log(...) \
  if (sshfs_log_file) \
    { \
      fprintf(sshfs_log_file, __VA_ARGS__); \
      fflush(sshfs_log_file); \
    }

#endif