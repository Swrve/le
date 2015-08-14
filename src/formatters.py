
# coding: utf-8
# vim: set ts=4 sw=4 et:

__author__ = 'Logentries'

__all__ = ['FormatPlain', 'FormatSyslog']


import datetime
import socket


class FormatPlain(object):

    """Formats lines as plain text, prepends each line with token."""

    def __init__(self, token):
        self._token = token

    def format_line(self, line):
        return self._token + line


class FormatSyslog(object):

    """Formats lines according to Syslog format RFC 5424. Hostname is taken
    from configuration or current hostname is used."""

    def __init__(self, hostname, appname, token):
        if hostname:
            self._hostname = hostname
        else:
            self._hostname = socket.gethostname()
        self._appname = appname
        self._token = token

    def format_line(self, line, msgid='-', token=''):
        if not token:
            token = self._token
        return '{token}<14>1 {dt}Z {hostname} {appname} - {msgid} - hostname={hostname} appname={appname} {line}'.format(
            token=token, dt=datetime.datetime.utcnow().isoformat('T'),
            hostname=self._hostname, appname=self._appname,
            msgid=msgid, line=line)


class FormatCustom(object):

    """Formats lines according to the supplied format string. Hostname is taken
    from configuration or current hostname is used. The supported variables
    in the format string are as follows:

    {isodatetime}: current ISO-8601-formatted date/time in UTC timezone,
    e.g. "2015-08-11T13:10:09.320514".
    {hostname}: taken from config, or current hostname is used.
    {appname}: the current application name.
    {line}: the log line."""

    def __init__(self, format, hostname, appname, token):
        self._format = format
        if hostname:
            self._hostname = hostname
        else:
            self._hostname = socket.gethostname()
        self._appname = appname
        self._token = token

    def format_line(self, line):
        return self._token + self._format.format(
            isodatetime=datetime.datetime.utcnow().isoformat('T'),
            hostname=self._hostname,
            appname=self._appname,
            line=line.rstrip('\n')) + '\n'

