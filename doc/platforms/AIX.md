# ProFTPD 1.3.x on AIX

There are two issues when compiling on AIX systems that can be worked around
using the proper configure command lines.

One problem involves the less than optimal default shared object search path
that the IBM linker inserts into executables.  The second problem is
compilaton failure stemming from an incompatibility with the `<string.h>`
header file when the IBM compiler attempts to inline some string functions.

Also, a minor usage note: do _not_ use the `--enable-autoshadow` or
`--enable-shadow` configure options when configuring ProFTPD for AIX.  AIX
does not use the shadow libraries.

## Executive Summary

If you are using the IBM `xlc/cc` compiler with the IBM `ld` linker:
```sh
env CC=cc \
  CFLAGS='-D_NO_PROTO' \
  LDFLAGS='-blibpath:/usr/lib:/lib:/usr/local/lib' \
  ./configure ...
```
If you are using the GNU `gcc` compiler with the IBM `ld` linker:
```sh
env CC=gcc \
  LDFLAGS='-Wl,-blibpath:/usr/lib:/lib:/usr/local/lib' \
  ./configure ...
```

If you are using the GNU `gcc` compiler with the GNU `ld` linker, something
like this ought to work (untested):
```sh
env CC=gcc \
  LDFLAGS='-Wl,-rpath,/usr/lib,-rpath,/lib,-rpath,/usr/local/lib' \
  ./configure ...
```

Note that the library paths shown here are for example use only.  You may need
to use different paths on your system, particularly when linking with any
optional libraries (_e.g._ krb5, ldap, mysql, _etc._).

## Compiling with the GNU compiler

It is recommend that `gcc-3.3.2` _not_ be used when compiling ProFTPD on AIX.
There were problems reported of session processes going into endless loops.
Using `gcc-4.1.0` or later should work properly.

## Linking with the IBM or GNU linker

There is a potential security problem when using the IBM linker.  Unlike other
Unix systems, by default the IBM linker automatically will use the compile-time
library search path as the runtime shared library search path.  The use of
relative paths in the runtime library search path is an especially acute
security problem for _suid_ or _sgid_ programs.

This default behavior is documented, so it is not considered a bug by IBM.
However, some _suid_ programs that have shipped with AIX have included insecure
library search paths and are vulnerable to privilege elevation exploits.

This may not be such a serious a security problem for ProFTPD, since it is not
installed _suid_ or _sgid_.  Nonetheless, it is wise to configure the
runtime shared library search path with a reasonable setting.  For instance,
consider potential problems from searching NFS mounted directories.

An existing AIX executable's library search path can be displayed:
```sh
dump -H progname
```

The runtime library search patch should be specified explicitly at build time
using the `-blibpath` option:
```sh
cc -blibpath:/usr/lib:/lib:/usr/local/lib

gcc -Wl,-blibpath:/usr/lib:/lib:/usr/local/lib
```

See the `ld` documentation, not just that of `xlc/cc`, for further information
on the IBM linker flags.  Alternatively, an insecure library search path can be
avoided using `-bnolibpath`, which causes the default path to be used (either
the value of the `LIBPATH` environment variable, if defined, or
`/usr/lib:/lib`, if not).

It has been reported that at least some versions of GNU `ld` (_e.g._ 2.9.1)
have emulated this default linking behavior on AIX platforms.  However, GNU
`ld` uses `-rpath` to set the runtime library search path, rather than the IBM
`ld -blibpath` or the Sun `ld -R` options:
```sh
gcc -Wl,-rpath,/usr/lib,-rpath,/lib,-rpath,/usr/local/lib
```

Again, consult the GNU `ld` documentation for further information.  Note that
using the `gcc` compiler does not imply that it uses the GNU `ld` linker.  In
fact, it is more common to use the IBM system linker.

The upshot of all this is that you should tell `configure` what to use for the
runtime shared library search path.  This can be done by setting `LDFLAGS` on
the `configure` command line, possibly like this:
```sh
env CC=cc \
  LDFLAGS='-blibpath:/usr/lib:/lib:/usr/local/lib' \
 ./configure ...

env CC=gcc \
  LDFLAGS='-Wl,-blibpath:/usr/lib:/lib:/usr/local/lib' \
  ./configure ...
```

In addition to setting the runtime library search path during the original
software build, the IBM linker can relink an existing _unstripped_ executable
using a new runtime library search path:
```sh
cc -blibpath:/usr/lib:/lib:/usr/local/lib -lm -ldl \
  -o progname.new progname

gcc -Wl,-blibpath:/usr/lib:/lib:/usr/local/lib -lm -ldl \
  -o progname.new progname
```
where the `-l` options refer to shared libraries, which can be determined from
the output of:
```sh
dump -Hv progname
```
which displays shared library information.  A basic `proftpd` executable
probably will not require any `-l` options at all.

## Compiling with the IBM xlc/cc compiler

There is a problem with the `index` and `rindex` macros defined in
`<string.h>`.  Apparently, these are used as part of an attempt to inline
string functions when the `__STR__` C preprocessor macro is defined.  Conflicts
with these definitions will cause compilation failures.

The work-around is to undefine the `__STR__` C preprocessor macro, which is
predefined by the IBM compiler.  This can be done on the `configure` command
line by adding `-U__STR__` to the `CPPFLAGS` variable:
```sh
env CC=cc CPPFLAGS='-U__STR__' ./configure ...
```

However, with newer versions of ProFTPD, it has been found that the following
combination works better when compiling:
```sh
env CC=cc CFLAGS='-D_NO_PROTO' ./configure ...
```

## Sendfile support in AIX

It appears that the `sendfile(2)` function in AIX 5.3 (specifically AIX
5300-04-02) is faulty.  If you are running ProFTPD 1.3.0 or later on AIX,
place the following in your `proftpd.conf`:
```text
  UseSendfile off
```
Failure to do so can result in downloads of files that end up being the wrong
size (downloaded files being far too large, _etc_).
