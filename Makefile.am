# automake definitions for libvfs
# 
#   Copyright (C) 23020. Junling Ma <junlingm@gmail.com>
#
#   This program is free software; you can redistribute it and/or
#   modify it under the terms of the GNU General Public License as
#   published by the Free Software Foundation; either version 2, or (at
#   your option) any later version.
#
#   This program is distributed in the hope that it will be useful, but
#   WITHOUT ANY WARRANTY; without even the implied warranty of
#   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
#   General Public License for more details.
#
#   You should have received a copy of the GNU General Public License
#   along with this program; if not, write to the Free Software
#   Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.

bin_PROGRAMS = sshfs
sshfs_SOURCES = hash.c main.c sshfs.c sshfs.h sshfs_hooks.h url.c url.h

AM_CFLAGS = -std=gnu99 -fgnu89-inline
AM_LDFLAGS = -lvfs -lnetfs -lihash