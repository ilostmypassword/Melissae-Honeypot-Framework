#!/bin/bash

touch /var/log/wtmp /var/log/lastlog /var/log/btmp /run/utmp
chmod 664 /var/log/wtmp /var/log/lastlog /run/utmp
chmod 600 /var/log/btmp

mkdir -p /run/rsyslogd
rm -f /run/rsyslogd.pid

touch /host-logs/telnet/auth.log
touch /host-logs/telnet/commands.log
chmod 666 /host-logs/telnet/auth.log
chmod 666 /host-logs/telnet/commands.log

rsyslogd
sleep 1

exec inetutils-inetd --debug

