AC_PREPREQ(2.57)
AC_INIT([libvfs], [0.1], [junlingm@gmail.com])
AM_INIT_AUTOMAKE
LT_INIT

AC_LANG(C)
AC_CHECK_HEADER([libssh/libssh.h], [], [AC_MSG_ERROR([libssh is required])])
AC_CHECK_LIB([ssh], ssh_new, [], [AC_MSG_ERROR([libssh is required])])

AC_CONFIG_FILES([Makefile])
AC_OUTPUT