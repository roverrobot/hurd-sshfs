/* sshfs filesystem: sftp connection and implementing the libvfs hooks

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
#include "sshfs_hooks.h"
#include "sshfs.h"
#include <stdio.h>
#include <stdlib.h>
#include <sys/time.h>

/* do we have stdin to read password? */
static inline int stdio_ok()
{
  return read(0, NULL, 0) == 0;
}

/* verify a ssh server */
static error_t verify_knownhost(ssh_session session)
{
  enum ssh_known_hosts_e state;
  unsigned char *hash = NULL;
  ssh_key srv_pubkey = NULL;
  size_t hlen;
  char buf[10];
  char *hexa;
  char *p;
  int cmp;

  /* get public key hash */
  int rc = ssh_get_server_publickey(session, &srv_pubkey);
  if (rc < 0)
    return -1;
  rc = ssh_get_publickey_hash(srv_pubkey,
                              SSH_PUBLICKEY_HASH_SHA1,
                              &hash,
                              &hlen);
  ssh_key_free(srv_pubkey);
  if (rc < 0)
    return -1;

  state = ssh_session_is_known_server(session);
  switch (state) 
    {
    case SSH_KNOWN_HOSTS_OK:
      /* OK */
      break;
    case SSH_KNOWN_HOSTS_CHANGED:
      fprintf(stderr, "Host key for server changed: it is now:\n");
      ssh_print_hash(SSH_PUBLICKEY_HASH_SHA1, hash, hlen);
      fprintf(stderr, "For security reasons, connection will be stopped\n");
      ssh_clean_pubkey_hash(&hash);
      return -1;
    case SSH_KNOWN_HOSTS_OTHER:
      fprintf(stderr, "The host key for this server was not found but an other"
              "type of key exists.\n");
      fprintf(stderr, "An attacker might change the default server key to"
              "confuse your client into thinking the key does not exist\n");
      ssh_clean_pubkey_hash(&hash);
      return -1;
    case SSH_KNOWN_HOSTS_NOT_FOUND:
      fprintf(stderr, "Could not find known host file.\n");
      fprintf(stderr, "If you accept the host key here, the file will be"
              "automatically created.\n");
      /* FALL THROUGH to SSH_SERVER_NOT_KNOWN behavior */
    case SSH_KNOWN_HOSTS_UNKNOWN:
      if (!stdio_ok())
        {
          fprintf(stderr,"Cannot read user input\n");
          return -1;
        }
      hexa = ssh_get_hexa(hash, hlen);
      fprintf(stderr,"The server is unknown. Public key hash: %s\nDo you trust the host key? (yes/no): ", hexa);
      ssh_string_free_char(hexa);
      ssh_clean_pubkey_hash(&hash);
      p = fgets(buf, sizeof(buf), stdin);
      if (p == NULL)
        return -1;
      cmp = strncasecmp(buf, "yes", 3);
      if (cmp != 0)
        return -1;
      rc = ssh_session_update_known_hosts(session);
      if (rc < 0) {
        fprintf(stderr, "Error %s\n", strerror(errno));
        return -1;
      }
      break;
    case SSH_KNOWN_HOSTS_ERROR:
      fprintf(stderr, "Error %s", ssh_get_error(session));
      ssh_clean_pubkey_hash(&hash);
      return -1;
    }
  ssh_clean_pubkey_hash(&hash);
  return 0;
}

/* connect to an ssh server with the URL */
sftp_session sshfs_connect(struct URL *url)
{
  /* only accepts sftp://... */
  if (strcmp(url->scheme, "sftp") != 0)
    return NULL;

  /* start an ssh session */
  ssh_session session = ssh_new();
  if (session == NULL)
    return NULL;

  ssh_options_set(session, SSH_OPTIONS_HOST, url->host);
  if (url->port)
    ssh_options_set(session, SSH_OPTIONS_PORT, &url->port);
    
  /* connect */
  int rc = ssh_connect(session);
  if (rc != SSH_OK)
    {
      fprintf(stderr, "Error connecting to %s: %s\n", url->host, ssh_get_error(session));
      return NULL;
    }

  /* verify server */
  if (verify_knownhost(session) < 0)
    return NULL;

  /* authenticate user */
  rc = ssh_userauth_publickey_auto(session, url->user, "");
  /* there seems no way to read password from console */
  if (rc != SSH_AUTH_SUCCESS)
    {
      if (!stdio_ok())
        {
          fprintf(stderr, "Cannot read user password\n");
          return NULL;
        }
      char buf[50];
      rc = ssh_getpass("Password: ", buf, sizeof(buf), 0, 0);
      if (rc == -1)
        return NULL;
      rc = ssh_userauth_password(session, NULL, buf);
    }
  if (rc != SSH_AUTH_SUCCESS)
    {
      fprintf(stderr, "Error authenticating: %s\n", ssh_get_error(session));
      return NULL;
    }
    
  /* start sftp */
  sftp_session sftp = sftp_new(session);
  if (sftp == NULL)
    {
      fprintf(stderr, "Error allocating SFTP session: %s\n", ssh_get_error(session));
      return NULL;
    }
  rc = sftp_init(sftp);
  if (rc != SSH_OK)
    {
      fprintf(stderr, "Error initializing SFTP session\n");
      return NULL;
    }
    
  return sftp;
}

/* convert the libssh error number to error_t */
static error_t get_errno(int ssh_error)
{
  switch (ssh_error)
    {
    case SSH_FX_OK:
    case SSH_FX_EOF: return ESUCCESS;
    case SSH_FX_NO_SUCH_FILE:
    case SSH_FX_NO_SUCH_PATH:
      return ENOENT;
    case SSH_FX_PERMISSION_DENIED: return EACCES;
    case SSH_FX_OP_UNSUPPORTED: return ENOTSUP;
    case SSH_FX_INVALID_HANDLE: return EBADF;
    case SSH_FX_FILE_ALREADY_EXISTS: return EEXIST;
    case SSH_FX_WRITE_PROTECT: return EROFS;
    case SSH_FX_NO_MEDIA: return ENOTSUP;
    case SSH_FX_FAILURE:
    case SSH_FX_BAD_MESSAGE:
    case SSH_FX_NO_CONNECTION:
    case SSH_FX_CONNECTION_LOST:
    default:
      /* irrecoverable error */
      fprintf(stderr, "connection lost\n");
      exit(1);
    }
}

/* concat the DIR name with a BASE name to form a path DIR/BASE */
static char *concat_path(const char *dir, const char *base)
{
  size_t ldir = strlen(dir);
  char *path = malloc(ldir + strlen(base) + 2);
  strcpy(path, dir);
  while (ldir && path[ldir-1] == '/')
    --ldir;
  path[ldir] = 0;
  while (base && *base && *base == '/')
    ++base;
  if (!base || *base == 0)
    {
      if (*path == 0)
        strcpy(path, "/");
    }
  else
    {
      strcat(path, "/");
      strcat(path, base);
    }
  return path;
}

/* get the libssh error */
error_t get_error(struct vfs_hooks *fs)
{
  sftp_session sftp = ((struct sshfs *)fs)->sftp;
  sshfs_log("get error\n");
  pthread_mutex_lock(&((struct sshfs *)fs)->lock);
  int sftp_err = sftp_get_error(sftp);
  if (sftp_err == 0)
    {
      sftp_err = ssh_get_error_code(sftp->session);
      sshfs_log("ssh error: %s\n", ssh_get_error(sftp->session));
    }
  pthread_mutex_unlock(&((struct sshfs *)fs)->lock);
  error_t err = get_errno(sftp_err);
  sshfs_log("got error: %d -> %d (%x)\n", sftp_err, err, err);
  return err;
}

/* return the absolute path of the inode INO on the server */
static const char *remote_path(struct vfs_hooks *fs, ino64_t ino)
{
  return ino ? (const char *)(uintptr_t)ino : ((struct sshfs *)fs)->url->path;
}

/* an inode is not used by libvfs any more. It should be dropped */
void sshfs_drop(struct vfs_hooks *fs, ino64_t ino)
{
  if (ino)
    {
      pthread_mutex_unlock(&((struct sshfs*)fs)->lock);
      sshfs_dropinode(((struct sshfs *)fs)->inodes, ino);
      pthread_mutex_unlock(&((struct sshfs*)fs)->lock);
    }
}

error_t sshfs_statfs(struct vfs_hooks *hooks, struct statfs *statbuf)
{
  memset (statbuf, 0, sizeof *statbuf);
  statbuf->f_type = sshfs_type;
  statbuf->f_fsid = getpid();
  return 0;
}

/* convert sftp_attributes into struct stat, with the given inode INO (because sftp_attributes
 * does not contain an inode) */
static error_t fill_stat(struct stat64 *statbuf, sftp_attributes attr, ino64_t ino)
{
  struct timeval tp;
  error_t err = gettimeofday(&tp, NULL);
  if (err)
    return err;
 
  memset(statbuf, 0, sizeof(*statbuf));
  statbuf->st_dev = 0;
  statbuf->st_ino = ino;
  statbuf->st_mode = attr->permissions;
  statbuf->st_nlink = 0;
  statbuf->st_uid = attr->uid;
  statbuf->st_gid = attr->gid;
  statbuf->st_rdev = 0;
  statbuf->st_size = attr->size;
  statbuf->st_atim.tv_sec = attr->atime;
  statbuf->st_atim.tv_nsec = attr->atime_nseconds;
  statbuf->st_mtim.tv_sec = attr->mtime;
  statbuf->st_mtim.tv_nsec = attr->mtime_nseconds;
  TIMEVAL_TO_TIMESPEC(&tp, &statbuf->st_ctim);
  statbuf->st_blksize = 0;
  statbuf->st_blocks = 0;
  return ESUCCESS;
}

  /* stat the inode INO and return in STATBUF, do not follow the symlink if INO is one */
static error_t sshfs_lstat(struct vfs_hooks *fs, ino64_t ino, struct stat64 *statbuf)
{
  const char *p = remote_path(fs, ino);
  sshfs_log("lstat: %s\n", p);
  pthread_mutex_lock(&((struct sshfs*)fs)->lock);
  sftp_attributes attr = sftp_lstat(((struct sshfs *)fs)->sftp, p);
  pthread_mutex_unlock(&((struct sshfs*)fs)->lock);
  if (!attr)
    return get_error(fs);
  error_t err = fill_stat(statbuf, attr, ino);
  sftp_attributes_free(attr);
  sshfs_log("lstat done: %s (%o)\n", p, statbuf->st_mode);
  return err;
}

/* look up a NAME in a DIR, and return the inode in INO */
error_t sshfs_lookup(struct vfs_hooks *fs, ino64_t dir, const char *name, ino64_t *ino)
{
  char *p = concat_path(remote_path(fs, dir), name);
  if (p == NULL)
    return ENOMEM;
  pthread_mutex_lock(&((struct sshfs*)fs)->lock);
  error_t err = sshfs_getinode(((struct sshfs*)fs)->inodes, p, ino);
  pthread_mutex_unlock(&((struct sshfs*)fs)->lock);
  return err;
}

static error_t sshfs_opendir(struct vfs_hooks *fs, ino64_t ino, struct vfs_dir **dir)
{
  const char *p = remote_path(fs, ino);
  error_t err = ESUCCESS;
  *dir = (err) ? NULL :  malloc(sizeof(**dir));
  if (*dir) 
    {
      sshfs_log("opendir: %s\n", p);
      pthread_mutex_lock(&((struct sshfs*)fs)->lock);
      (*dir)->dir = sftp_opendir(((struct sshfs *)fs)->sftp, p);
      pthread_mutex_unlock(&((struct sshfs*)fs)->lock);
      sshfs_log("opendir done: %s\n", p);
      if ((*dir)->dir == NULL)
        {
          free(*dir);
          *dir = NULL;
          err = get_error(fs);
        }
      else
        (*dir)->fs = (struct sshfs *)fs;
    }
  return err;
}

/* read an DIR entry into DIRENT, which has a maximum size DIRENT_SIZE. If the maximum
 * size is not large enough to hold the entry, return EKERN_NO_SPACE. DIRENT may be 
 * NULL, in which case the entry will be skipped. ENOENT will be returned if no further 
 * entries exist */ 
static error_t sshfs_readdir(struct vfs_dir *dir, struct dirent *ent, size_t size)
{
  sshfs_log("readdir: %s\n", dir->dir->name);
  pthread_mutex_lock(&dir->fs->lock);
  sftp_attributes attr = sftp_readdir(dir->fs->sftp, dir->dir);
  pthread_mutex_unlock(&dir->fs->lock);
  if (attr == NULL)
    return ENOENT;

  if (ent == NULL)
    return ESUCCESS;

  char *p = concat_path(dir->dir->name, attr->name);
  if (p == NULL)
    return ENOMEM;

  size_t namlen = strlen(attr->name);
  size_t reclen = DIRENT_LEN(namlen);
  if (size < reclen)
    return EKERN_NO_SPACE;

  pthread_mutex_lock(&dir->fs->lock);
  ino64_t ino;
  error_t err = sshfs_getinode(dir->fs->inodes, p, &ino);
  pthread_mutex_unlock(&dir->fs->lock);
  if (err)
    return err;

  memcpy(ent->d_name, attr->name, namlen);
  ent->d_ino = ino;
  ent->d_reclen = reclen;
  ent->d_namlen = namlen;
  ent->d_type = IFTODT(attr->permissions);
  sshfs_log("got %s (%o)\n", attr->name, ent->d_type);

  sftp_attributes_free(attr);
  return ESUCCESS;
}

static error_t sshfs_closedir(struct vfs_dir *dir)
{
  sshfs_log("closedir: %s\n", dir->dir->name);
  pthread_mutex_lock(&dir->fs->lock);
  int r = sftp_closedir(dir->dir);
  pthread_mutex_unlock(&dir->fs->lock);
  sshfs_log("closedir done\n");
  free(dir);
  return r;
}

/* read the content of a symlink stored in INO into CONTENT */
static error_t sshfs_readlink(struct vfs_hooks *fs, ino64_t ino, char **content)
{
  const char *p = remote_path(fs, ino);
  sshfs_log("readlink: %s\n", p);
  pthread_mutex_lock(&((struct sshfs*)fs)->lock);
  *content = sftp_readlink(((struct sshfs *)fs)->sftp, p);
  pthread_mutex_unlock(&((struct sshfs*)fs)->lock);
  sshfs_log("readlink done: %s\n", p);
  return (*content == NULL) ? get_error(fs) : ESUCCESS;
}

/* create an sshfs the implements vfs_hooks from the URL */
struct sshfs *sshfs_create(struct URL *url)
{
  if (url == NULL || url->host == NULL)
    return NULL;
  if (url->pass != NULL)
    {
      fprintf(stderr, "the password shall not be included in the url\n");
      return NULL;
    }
  struct sshfs *fs = malloc(sizeof(*fs));
  if (fs == NULL)
    return NULL;
  memset(fs, 0, sizeof(*fs));
  pthread_mutex_init(&fs->lock, 0);
  fs->url = url;
  fs->sftp = sshfs_connect(url);
  if (fs->sftp == NULL)
    {
      free(fs);
      url_free(url);
      return NULL;
    }
  fs->hooks.statfs = sshfs_statfs;
  fs->hooks.drop = sshfs_drop;
  fs->hooks.lstat = sshfs_lstat;
  fs->hooks.lookup = sshfs_lookup;
  fs->hooks.opendir = sshfs_opendir;
  fs->hooks.readdir = sshfs_readdir;
  fs->hooks.closedir = sshfs_closedir;
  fs->hooks.readlink = sshfs_readlink;
  fs->inodes = sshfs_getihash();
  return fs;
}
