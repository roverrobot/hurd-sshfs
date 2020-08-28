/* Manage a virtual filesystem

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

#ifndef __SSHFS_HOOKS_H__
#define __SSHFS_HOOKS_H__

#include <libssh/libssh.h>
#include <libssh/sftp.h>
#include <libvfs/vfs_hooks.h>
#include <pthread.h>

/* the file returned by the open hook */
struct vfs_file {
  /* the sftp session representation */
  sftp_file file;
  /* the vfs and its hooks */
  struct sshfs *fs;
  /* we need to keep track of the current offset since libssh does not provide a 
   * pread/pwrite interface
   */
  off_t offset;
};

/* the dir returned by the opendir hook */
struct vfs_dir {
  /* the sftp session representation */
  sftp_dir dir;
  /* the vfs and its hooks */
  struct sshfs *fs;
};

/* the vfs implementation with its vfs_hooks */
struct sshfs {
  /* implements the vfs_hooks interface */
  struct vfs_hooks hooks;
  /* the url that we have opened */
  struct URL *url;
  /* the libssh sftp session */
  sftp_session sftp;
  /* A hash table that maps paths to inodes that has been accessed and not yet dropped
   * we use the absolute path on the server to represent an inode. Two paths with the same 
   * content must be mapped to the same inode. So we used the unique value stored in the
   * hash table as the inode value
   */
  struct hurd_ihash *inodes;
  /* a global lock, because libssh cannot be concurrently called on multiple threads */
  pthread_mutex_t lock;
};

/* The following declarations exist because libssh and hurd conflict on the definition of
 * socket. So libssl and hurd heads caanot be included together */

/* the type of the sshfs, will be the value of FSTYPE_FTP, used in the statfs hook */
extern int sshfs_type;
/* The log file, as specified by the --log (-l) argument */
extern FILE *sshfs_log_file;
/* create the inode hash table */
extern struct hurd_ihash *sshfs_getihash();
/* return the inode corresponding to PATH in INO by looking up in INODES */
extern error_t sshfs_getinode(struct hurd_ihash *inodes, char *path, ino_t *ino);
/* drop the inode INO from the hash table INODES */
void sshfs_dropinode(struct hurd_ihash *inodes, ino_t ino);


#endif
