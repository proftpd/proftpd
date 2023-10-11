# ProFTPD on Cygwin

Cygwin is a UNIX-like environment framework for Microsoft Windows 98/NT/2000/XP
operating systems. Most programs that you are used to using can compile and
behave exacttly the same way as on your favorite Unix system. However, there
are some minor differences and compatibility issues.

## Configuring and Compiling 

In standard Cygwin setup, there's no such username as "root". By default, the
`configure` script assigns 'Administrator' as the installation username.
Should you want to change this, then specify a username in the `install_user`
environment variable:
```sh
install_user=MyUserHere ./configure ...
```
The rest of the installation process is as usual:
```sh
./configure
make
make install
```

_Note_ that Cygwin does not currently support large files (_e.g._ files larger
than 2 GB).  Also, Cygwin 1.3.22 or later should be installed.  Earlier
versions of Cygwin would result in error messages like:
```text
  426 Transfer aborted.  Socket operation on non-socket
```

## Installing as Windows service

Create a shell script and put it somewhere, with the following contents:
```text
#!/bin/sh
# File: proftpd-config.sh
# Purpose: Installs ProFTPD daemon as a Windows service

cygrunsrv --install proftpd \
          --path /usr/local/sbin/proftpd.exe \
          --args "--nodaemon" \
          --type manual \
          --disp "Cygwin proftpd" \
          --desc "ProFTPD FTP daemon"
```
The `--nodaemon` option is important.  It prevents the process from detaching.
Thus you can always shut it down with `net stop proftpd` command.

After running this script, you may run the daemon with `net start proftpd`
command.  Or, change the `type` from `manual` to `auto`, and it will run on the
system startup.

You can remove the service with the command:
```sh
cygrunsrv --remove proftpd
```

## Installing as inetd service

Edit the corresponding line in `/etc/inetd.conf`:
```text
  ftp stream tcp nowait root /usr/local/sbin/in.proftpd in.proftpd
```
You can specify an alternative configuration file with `-c` option.

## Configuration File

The default configuration file resides in `/usr/local/etc/proftpd.conf`.
However, the default version of the `proftpd.conf` created by the installation
script is unusable within the Cygwin environment.

Some configuration directives need to be changed as follows:
```text
  ServerType standalone|inetd
```
Needs to be set correctly.  Having `standalone` when running from `inetd`
produces daemon processes which are difficult or impossible to kill.

```text
User  System
Group Administrators
```
By default, a Windows service runs as the `SYSTEM` user, and if `User`
directive specifies some other user, ProFTPD fails to change to that user.
Also, if no `User` directive given, the daemon tries to change the UID to the
`SYSTEM` user ID.

Using a less privileged user and/or group will result in errors when users
attempt to login.

```text
<Anonymous directory_name>
```
The user specified in `User` directive should exist as a Windows account. In
Windows User Manager, this login can be even disabled.  As usual, make sure
you have this entry in the Cygwin `/etc/passwd` file (produced by
`mkpasswd.exe`).

```text
UserPassword username encrypted_passwd
```
The encrypted password can be produced with the `openssl passwd` command.

When a user logs in, the following non-fatal warnings will appear in the
ProFTPD logs:
```text
  error setting write fd IP_TOS: Invalid argument
  error setting read fd IP_TOS: Invalid argument
  error setting write fd TCP_NOPUSH: Protocol not available
  error setting read fd TCP_NOPUSH: Protocol not available
```

## Author

Stanislav Sinyagin
CCIE #5478
ssinyagin@yahoo.com
