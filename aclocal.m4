# PR_FUNC_SETGRENT_VOID
# ---------------------
# Check whether setgret returns void, and #define SETGRENT_VOID in
# that case.
AC_DEFUN([PR_FUNC_SETGRENT_VOID],
[AC_CACHE_CHECK([whether setgrent returns void], [ac_cv_func_setgrent_void],
  [AC_RUN_IFELSE([
    #include <sys/types.h>
    #include <grp.h>
    int main(int argc, char *argv[]) {
      int i = 0;
      getgrent();
      i = setgrent();
      return (i != 1);
    }
  ],
  [ac_cv_func_setgrent_void=no],
  [ac_cv_func_setgrent_void=yes],,
)])

if test $ac_cv_func_setgrent_void = yes; then
  AC_DEFINE(SETGRENT_VOID, 1,
    [Define to 1 if the `setgrent' function returns void instead of `int'.])
fi
])

# PR_CHECK_CC_OPT
# ---------------------
# Check whether the C compiler accepts the given option
AC_DEFUN(PR_CHECK_CC_OPT,
  [AC_MSG_CHECKING([whether ${CC-cc} accepts -[$1]])
   echo 'void f(){}' > conftest.c
   if test -z "`${CC-cc} -c -$1 conftest.c 2>&1`"; then
     AC_MSG_RESULT(yes)
     CFLAGS="$CFLAGS -$1"
   else
     AC_MSG_RESULT(no)
   fi
   rm -f conftest*
  ])

