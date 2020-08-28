/* ssh filesystem

   Copyright (C) 2020. Junling Ma <junlingm@gmail.com>

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

#include <libvfs/vfs.h>
#include <string.h>
#include <unistd.h>
#include <argp.h>
#include <error.h>
#include <argz.h>
#include <netdb.h>
#include <sys/stat.h>
#include "sshfs.h"

char *sshfs_server_name = "sshfs";
char *sshfs_server_version = PACKAGE_VERSION;
int netfs_maxsymlinks = 12;
FILE *sshfs_log_file = NULL;
int sshfs_type = FSTYPE_FTP;
const char *argp_program_version = PACKAGE_VERSION;;

static char *args_doc = "SSHFS";
static char *doc = "Hurd s filesystem translator."
"\vSSHFS is a URL, in the form of sftp://[USER@]HOST[/PATH]. If USER is not specified,"
"the local user that starts sshfs will be used. If PATH is not specified, then / is used."
" Note that a password shall not be included for security reasons, and the ssh "
"authentication is made by public key with no passphrase";

/* The filesystem.  */

/* The sftp url that we're connected too.  */
struct URL *sshfs_url = NULL;

/* Startup options.  */

static const struct argp_option startup_options[] =
{
  {"log", 'l', "FILE", 0, "Print debug output to FILE"}, { 0 }
};

/* Parse a single command line option/argument.  */
static error_t
parse_startup_opt (int key, char *arg, struct argp_state *state)
{
  switch (key)
    {
    case 'l':
      if (strcmp(arg, "-") == 0)
        sshfs_log_file = stderr;
      else
        sshfs_log_file = fopen(arg, "w");
      break;
    case ARGP_KEY_ARG:
      if (state->arg_num >= 1)
        argp_usage (state);
      else if (state->arg_num == 0)
        {
          sshfs_url = parse_url(arg);
          if (sshfs_url == NULL)
            argp_failure (state, 99, EINVAL, "%s", arg);
        }
      break;

    case ARGP_KEY_SUCCESS:
      if (state->arg_num == 0)
        argp_error (state, "No remote filesystem specified");

    case ARGP_KEY_INIT:
      break;

    default:
      return ARGP_ERR_UNKNOWN;
    }

  return 0;
}

static void get_stdio()
{
  if (write(2, NULL, 0) == 0)
    {
      dup2(2, 1);
      dup2(2, 0);
    }
}

static struct argp runtime_argp =
  { 0 };

/* Use by netfs_set_options to handle runtime option parsing.  */
struct argp *netfs_runtime_argp = &runtime_argp;

/* Program entry point.  */
int
main (int argc, char **argv)
{
  get_stdio();
  error_t err;
  const struct argp_child argp_children[] =
    { {&netfs_std_startup_argp}, {0} };
  struct argp argp =
    { startup_options, parse_startup_opt, args_doc, doc, argp_children };
  argp_parse (&argp, argc, argv, 0, 0, 0);

  struct sshfs *sshfs =sshfs_create(sshfs_url);
  if (sshfs == NULL)
    return 1;

  struct vfs *fs;
  err = vfs_create(sshfs_server_name, sshfs_server_version, (struct vfs_hooks*)sshfs, &fs);
  if (err)
    error (2, err, "create file system");
  return vfs_start (fs, O_READ | O_WRITE);
}
