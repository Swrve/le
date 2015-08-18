#!/usr/bin/env python
# coding: utf-8
# vim: set ts=4 sw=4 et:

#
# Logentries Agent <https://logentries.com/>.
#

#
# Constants
#

from utils import *
from __init__ import __version__

CORP = "logentries"

NOT_SET = None

# Default user and agent keys of none are defined in configuration
DEFAULT_USER_KEY = NOT_SET
DEFAULT_AGENT_KEY = NOT_SET

# Configuration files
CONFIG_DIR_SYSTEM = '/etc/le'
CONFIG_DIR_USER = '.le'
LE_CONFIG = 'config'
CACHE_NAME = 'cache'

LOCAL_CONFIG_DIR_USER = '.le'
LOCAL_CONFIG_DIR_SYSTEM = '/etc/le'

PID_FILE = '/var/run/logentries.pid'

MAIN_SECT = 'Main'
USER_KEY_PARAM = 'user-key'
AGENT_KEY_PARAM = 'agent-key'
FILTERS_PARAM = 'filters'
FORMATTER_PARAM = 'formatter'
CUSTOM_FORMAT_PARAM = 'custom-format'
SUPPRESS_SSL_PARAM = 'suppress_ssl'
USE_CA_PROVIDED_PARAM = 'use_ca_provided'
FORCE_DOMAIN_PARAM = 'force_domain'
DATAHUB_PARAM = 'datahub'
SYSSTAT_TOKEN_PARAM = 'system-stat-token'
HOSTNAME_PARAM = 'hostname'
TOKEN_PARAM = 'token'
PATH_PARAM = 'path'
DESTINATION_PARAM = 'destination'
PULL_SERVER_SIDE_CONFIG_PARAM = 'pull-server-side-config'
KEY_LEN = 36
ACCOUNT_KEYS_API = '/agent/account-keys/'
ID_LOGS_API = '/agent/id-logs/'

# Maximal queue size for events sent
SEND_QUEUE_SIZE = 32000

# Logentries server details
LE_SERVER_API = '/'

LE_DEFAULT_SSL_PORT = 20000
LE_DEFAULT_NON_SSL_PORT = 10000


class Domain(object):

    """ Logentries domains. """
    # General domains
    MAIN = 'logentries.com'
    API = 'api.logentries.com'
    DATA = 'data.logentries.com'
    PULL = 'pull.logentries.com'
    # Local debugging
    MAIN_LOCAL = '127.0.0.1'
    API_LOCAL = '127.0.0.1'
    DATA_LOCAL = '127.0.0.1'
    LOCAL = '127.0.0.1'


CONTENT_LENGTH = 'content-length'

# Log root directory
LOG_ROOT = '/var/log'

# Timeout after server connection fail. Might be a temporary network
# failure.
SRV_RECON_TIMEOUT = 10  # in seconds
SRV_RECON_TO_MIN = 1   # in seconds
SRV_RECON_TO_MAX = 10  # in seconds

# Timeout after invalid server response. Might be a version mishmash or
# temporary server/network failure
INV_SRV_RESP_TIMEOUT = 30  # Seconds

# Time interval between re-trying to open log file
REOPEN_TRY_INTERVAL = 1  # Seconds

# Number of lines which can be sent in one buck, piggybacking
MAX_LINES_SENT = 10

# Time in seconds spend between log re-checks
TAIL_RECHECK = 0.2  # Seconds

# Number of attemps to read a file, until the name is recheck
NAME_CHECK = 4  # TAIL_RECHECK cycles

# Number of read line false attemps between are-you-alive packets
IAA_INTERVAL = 100
IAA_TOKEN = "###LE-IAA###\n"

# Maximal size of a block of events
MAX_EVENTS = 65536

# Interval between attampts to open a file
REOPEN_INT = 1  # Seconds

# Linux block devices
SYS_BLOCK_DEV = '/sys/block/'
# Linux CPU stat file
CPUSTATS_FILE = '/proc/stat'
# Linux mmeory stat file
MEMSTATS_FILE = '/proc/meminfo'
# Linux network stat file
NETSTATS_FILE = '/proc/net/dev'

# List of accepted network devices
NET_DEVICES = ['  eth', ' wlan', 'venet', ' veth']

EPOCH = 5  # in seconds

QUEUE_WAIT_TIME = 1  # time in seconds to wait for reading from the transport queue if it is empty


# File Handler Positions
FILE_BEGIN = 0
FILE_CURRENT = 1
FILE_END = 2

# Config response parameters
CONF_RESPONSE = 'response'
CONF_REASON = 'reason'
CONF_LOGS = 'logs'
CONF_SERVERS = 'servers'
CONF_OK = 'ok'

# Server requests
RQ_WORKLOAD = 'push_wl'

# Release information on LSB systems
LSB_RELEASE = '/etc/lsb-release'


#
# Usage help
#

PULL_USAGE = "pull <path> <when> <filter> <limit>"
PUSH_USAGE = "push <file> <path> <log-type>"
USAGE = "Logentries agent version " + __version__ + """
usage: le COMMAND [ARGS]

Where command is one of:
  init      Write local configuration file
  reinit    As init but does not reset undefined parameters
  register  Register this host
    --name=  name of the host
    --hostname=  hostname of the host
  whoami    Displays settings for this host
  monitor   Monitor this host
  follow <filename>  Follow the given log
    --name=  name of the log
    --type=  type of the log
  followed <filename>  Check if the file is followed
  clean     Removes configuration file
  ls        List internal filesystem and settings: <path>
  rm        Remove entity: <path>
  pull      Pull log file: <path> <when> <filter> <limit>

Where parameters are:
  --help                  show usage help and exit
  --version               display version number and exit
  --account-key=          set account key and exit
  --host-key=             set local host key and exit, generate key if key is empty
  --no-timestamps         no timestamps in agent reportings
  --force                 force given operation
  --suppress-ssl          do not use SSL with API server
  --yes                   always respond yes
  --datahub               send logs to the specified data hub address
                          the format is address:port with port being optional
  --system-stat-token=    set the token for system stats log (beta)
  --pull-server-side-config=False do not use server-side config for following files
"""


def print_usage(version_only=False):
    if version_only:
        report(__version__)
    else:
        report(USAGE)

    sys.exit(EXIT_HELP)


#
# Libraries
#

# Do not remove - fix for Python #8484
try:
    import hashlib
except ImportError:
    pass

import string
import re
import Queue
import random
import ConfigParser
import fileinput
import getopt
import glob
import logging
import os
import os.path
import platform
import socket
import subprocess
import traceback
import sys
import threading
import time
import datetime
import urllib
import httplib
import getpass
import atexit
import logging.handlers
from backports import CertificateError, match_hostname

import formatters
import metrics

#
# Start logging
#

log = logging.getLogger(LOG_LE_AGENT)
if not log:
    report("Cannot open log output")
    sys.exit(EXIT_ERR)

log.setLevel(logging.INFO)

stream_handler = logging.StreamHandler()
stream_handler.setLevel(logging.DEBUG)
stream_handler.setFormatter(logging.Formatter("%(message)s"))
log.addHandler(stream_handler)


def debug_filters(msg, *args):
    if config.debug_filters:
        print >> sys.stderr, msg % args

#
# Imports that may not be available
#

try:
    import json

    try:
        json_loads = json.loads
        json_dumps = json.dumps
    except AttributeError:
        json_loads = json.read
        json_dumps = json.write
except ImportError:
    try:
        import simplejson
    except ImportError:
        die('NOTE: Please install Python "simplejson" package (python-simplejson) or a newer Python (2.6).')
    json_loads = simplejson.loads
    json_dumps = simplejson.dumps

# FIXME
no_ssl = False
try:
    import ssl

    wrap_socket = ssl.wrap_socket
    CERT_REQUIRED = ssl.CERT_REQUIRED

except ImportError:
    no_ssl = True

    try:
        _ = httplib.HTTPSConnection
    except AttributeError:
        die('NOTE: Please install Python "ssl" module.')

    def wrap_socket(sock, ca_certs=None, cert_reqs=None):
        return socket.ssl(sock)

    CERT_REQUIRED = 0

#
# Custom proctitle
#


#
# User-defined filtering code
#

def filter_events(events):
    """
    User-defined filtering code. Events passed are about to be sent to
    logentries server. Make the required modifications to the events such
    as removing unwanted or sensitive information.
    """
    # By default, this method is empty
    return events


def default_filter_filenames(filename):
    """
    By default we allow to follow any files specified in the condifuration.
    """
    return True


def call(command):
    """
    Calls the given command in OS environment.
    """
    output = subprocess.Popen(
        command, stdout=subprocess.PIPE, shell=True).stdout.read()
    if len(output) == 0:
        return ''
    if output[-1] == '\n':
        output = output[:-1]
    return output


def uniq(arr):
    """
    Returns the list with duplicate elements removed.
    """
    return list(set(arr))


def _lock_pid_file_name():
    """
    Returns path to a file for protecting critical section
    for daemonizing (see daemonize() )
    """
    return config.pid_file + '.lock'


def _lock_pid():
    """
    Tries to exclusively open file for protecting of critical section
    for daemonizing.
    """
    file_name = _lock_pid_file_name()
    try:
        fd = os.open(file_name, os.O_WRONLY | os.O_CREAT | os.O_EXCL)
    except OSError:
        return None
    if fd == -1:
        return None
    os.close(fd)
    return True


def _unlock_pid():
    """
    Releases file for protecting of critical section for daemonizing.
    """
    try:
        file_name = _lock_pid_file_name()
        os.remove(file_name)
    except OSError:
        pass


def _try_daemonize():
    """
    Creates a daemon from the current process.
    http://www.jejik.com/articles/2007/02/a_simple_unix_linux_daemon_in_python/
    Alternative: python-daemon
    """

    try:
        pidfile = file(config.pid_file, 'r')
        pid = int(pidfile.read().strip())
        pidfile.close()
    except IOError:
        pid = None
    if pid:
        if not os.path.exists('/proc') or os.path.exists("/proc/%d/status" % pid):
            return "Pidfile %s already exist. Daemon already running?" % config.pid_file

    try:
        # Open pid file
        if config.pid_file:
            file(config.pid_file, 'w').close()

        pid = os.fork()
        if pid > 0:
            sys.exit(EXIT_OK)
        os.chdir("/")
        os.setsid()
        os.umask(0)
        pid = os.fork()
        if pid > 0:
            sys.exit(EXIT_OK)
        sys.stdout.flush()
        sys.stderr.flush()
        si = file('/dev/null', 'r')
        so = file('/dev/null', 'a+')
        se = file('/dev/null', 'a+', 0)
        os.dup2(si.fileno(), sys.stdin.fileno())
        os.dup2(so.fileno(), sys.stdout.fileno())
        os.dup2(se.fileno(), sys.stderr.fileno())

        # Write pid file
        if config.pid_file:
            pid = str(os.getpid())
            pidfile = file(config.pid_file, 'w')
            atexit.register(rm_pidfile)
            pidfile.write("%s\n" % pid)
            pidfile.close()
    except OSError, e:
        rm_pidfile(config)
        return "Cannot daemonize: %s" % e.strerror
    return None


def daemonize():
    """
    Creates a daemon from the current process.

    It uses helper file as a lock and then checks inside critical section
    whether pid file contains pid of a valid process.
    If not then it daemonizes itself, otherwise it dies.
    """
    if not _lock_pid():
        die("Daemon already running. If you are sure it isn't please remove %s" %
            _lock_pid_file_name())
    err = _try_daemonize()
    _unlock_pid()
    if err:
        die("%s" % err)

    # Setting the proctitle
    set_proc_title('logentries-daemon')

    # Logging for daemon mode
    log.removeHandler(stream_handler)
    shandler = logging.StreamHandler()
    shandler.setLevel(logging.DEBUG)
    shandler.setFormatter(logging.Formatter("%(asctime)s  %(message)s"))
    log.addHandler(shandler)


def print_total(elems, name):
    """
    Prints total number of elements in the list
    """
    total = len(elems)
    if total == 0:
        report("no %ss" % name)
    elif total == 1:
        report("1 " + name)
    else:
        report("%d %ss" % (total, name))


def collect_log_names(system_info):
    """
    Collects standard local logs and identifies them.
    """
    logs = []
    for root, dirs, files in os.walk(LOG_ROOT):
        for name in files:
            if name[-3:] != '.gz' and re.match(r'.*\.\d+$', name) is None:
                logs.append(os.path.join(root, name))

    log.debug("Collected logs: %s", logs)
    try:
        c = httplib.HTTPSConnection(LE_SERVER_API)
        request = {
            'logs': json_dumps(logs),
            'distname': system_info['distname'],
            'distver': system_info['distver']
        }
        log.debug("Requesting %s", request)
        c.request('post', ID_LOGS_API, urllib.urlencode(request), {})
        response = c.getresponse()
        if not response or response.status != 200:
            die('Error: Unexpected response from logentries (%s).' %
                response.status)
        data = json_loads(response.read())
        log_data = data['logs']

        log.debug("Identified logs: %s", log_data)
    except socket.error, msg:
        die('Error: Cannot contact server, %s' % msg)
    except ValueError, msg:
        die('Error: Invalid response from the server (Parsing error %s)' % msg)
    except KeyError:
        die('Error: Invalid response from the server, log data not present.')

    return log_data


def lsb_release(system_info):
    # General LSB system
    if os.path.isfile(LSB_RELEASE):
        try:
            fields = dict((a.split('=') for a in rfile(LSB_RELEASE).split('\n') if len(a.split('=')) == 2))
            system_info['distname'] = fields['DISTRIB_ID']
            system_info['distver'] = fields['DISTRIB_RELEASE']
            return True
        except ValueError:
            pass
        except KeyError:
            pass

    # Information not found
    return False


def release_test(filename, distname, system_info):
    if os.path.isfile(filename):
        system_info['distname'] = distname
        system_info['distver'] = rfile(filename)
        return True
    return False


def system_detect(details):
    """
    Detects the current operating system. Returned information contains:
        distname: distribution name
        distver: distribution version
        kernel: kernel type
        system: system name
        hostname: host name
    """
    uname = platform.uname()
    sys = uname[0]
    system_info = dict(system=sys, hostname=socket.getfqdn(),
                       kernel='', distname='', distver='')

    if not details:
        return system_info

    if sys == "SunOS":
        pass
    elif sys == "AIX":
        system_info['distver'] = call("oslevel -r")
    elif sys == "Darwin":
        system_info['distname'] = call("sw_vers -productName")
        system_info['distver'] = call("sw_vers -productVersion")
        system_info['kernel'] = uname[2]

    elif sys == "Linux":
        system_info['kernel'] = uname[2]
        # XXX CentOS?
        releases = [
            ['/etc/debian_version', 'Debian'],
            ['/etc/UnitedLinux-release', 'United Linux'],
            ['/etc/annvix-release', 'Annvix'],
            ['/etc/arch-release', 'Arch Linux'],
            ['/etc/arklinux-release', 'Arklinux'],
            ['/etc/aurox-release', 'Aurox Linux'],
            ['/etc/blackcat-release', 'BlackCat'],
            ['/etc/cobalt-release', 'Cobalt'],
            ['/etc/conectiva-release', 'Conectiva'],
            ['/etc/fedora-release', 'Fedora Core'],
            ['/etc/gentoo-release', 'Gentoo Linux'],
            ['/etc/immunix-release', 'Immunix'],
            ['/etc/knoppix_version', 'Knoppix'],
            ['/etc/lfs-release', 'Linux-From-Scratch'],
            ['/etc/linuxppc-release', 'Linux-PPC'],
            ['/etc/mandriva-release', 'Mandriva Linux'],
            ['/etc/mandrake-release', 'Mandrake Linux'],
            ['/etc/mandakelinux-release', 'Mandrake Linux'],
            ['/etc/mklinux-release', 'MkLinux'],
            ['/etc/nld-release', 'Novell Linux Desktop'],
            ['/etc/pld-release', 'PLD Linux'],
            ['/etc/redhat-release', 'Red Hat'],
            ['/etc/slackware-version', 'Slackware'],
            ['/etc/e-smith-release', 'SME Server'],
            ['/etc/release', 'Solaris SPARC'],
            ['/etc/sun-release', 'Sun JDS'],
            ['/etc/SuSE-release', 'SuSE'],
            ['/etc/sles-release', 'SuSE Linux ES9'],
            ['/etc/tinysofa-release', 'Tiny Sofa'],
            ['/etc/turbolinux-release', 'TurboLinux'],
            ['/etc/ultrapenguin-release', 'UltraPenguin'],
            ['/etc/va-release', 'VA-Linux/RH-VALE'],
            ['/etc/yellowdog-release', 'Yellow Dog'],
        ]

        # Check for known system IDs
        for release in releases:
            if release_test(release[0], release[1], system_info):
                break
        # Check for general LSB system
        if os.path.isfile(LSB_RELEASE):
            try:
                fields = dict((a.split('=') for a in rfile(LSB_RELEASE).split('\n') if len(a.split('=')) == 2))
                system_info['distname'] = fields['DISTRIB_ID']
                system_info['distver'] = fields['DISTRIB_RELEASE']
            except ValueError:
                pass
            except KeyError:
                pass
    return system_info


# Identified ranges

SEC = 1000
MIN = 60 * SEC
HOUR = 60 * MIN
DAY = 24 * HOUR
MON = 31 * DAY
YEAR = 365 * DAY


def date_patterns():
    """ Generates date patterns of the form [day<->month year?].
    """
    for year in [' %Y', ' %y']:
        for mon in ['%b', '%B', '%m']:
            yield ['%%d %s%s' % (mon, year), DAY, []]
            yield ['%s %%d%s' % (mon, year), DAY, []]
    for mon in ['%b', '%B']:  # Year empty
        yield ['%%d %s' % (mon), DAY, [YEAR]]
        yield ['%s %%d' % (mon), DAY, [YEAR]]
    yield ['%%Y %%d %s' % (mon), DAY, []]
    yield ['%%Y %s %%d' % (mon), DAY, []]
    yield ['%Y %m %d', DAY, []]


def time_patterns(c_cols):
    """Generates time patterns of the form [hour:min:sec?] including empty
    time.
    """
    if c_cols >= 2:
        yield ['%H:%M:%S', SEC, []]
    if c_cols >= 1:
        yield ['%H:%M', MIN, []]
        yield ['%I:%M%p', MIN, []]
    yield ['%I%p', HOUR, []]


def datetime_patterns(c_cols):
    """Generates combinations of date and time patterns.
    """
    # Generate dates only
    for date_pattern in date_patterns():
        yield date_pattern

    # Generate combinations
    for t in time_patterns(c_cols):
        for d in date_patterns():
            yield ['%s %s' % (d[0], t[0]), t[1], d[2]]
            yield ['%s %s' % (t[0], d[0]), t[1], d[2]]
        yield [t[0], t[1], [YEAR, MON, DAY]]


def timestamp_patterns(sample):
    """Generates all timestamp patterns we can handle. It is constructed by
    generating all possible combinations of date, time, day name and zone. The
    pattern is [day_name? date<->time zone?] plus simple date and time.
    """
    # All timestamps variations
    day_name = ''
    if len(sample) > 0:
        if sample[0] in string.ascii_letters:
            day_name = '%a '
    c_cols = sample.count(':')
    for zone in ['', ' %Z', ' %z']:
        for dt in datetime_patterns(c_cols):
            yield ['%s%s%s' % (day_name, dt[0], zone), dt[1], dt[2]]


def timestamp_group(text):
    """Returns a tuple [timestamp, range] which corresponds to the date and
    time given. Exists on parse error.
    """
    timep = re.sub(r' +', ' ', re.sub(r'[-,./]', ' ', text)).strip()
    start_tuple = None
    for p in timestamp_patterns(timep):
        pattern, resolution, filling = p
        try:
            start_tuple = time.strptime(timep, p[0])
            break
        except ValueError:
            pass
    if not start_tuple:
        die("Error: Date '%s' not recognized" % text)

    today = datetime.date.today()
    # Complete filling
    if YEAR in filling:
        start_tuple.rm_year = today.year
    if MON in filling:
        start_tuple.rm_month = today.month
    if DAY in filling:
        start_tuple.rm_day = today.day
    return [int(time.mktime(start_tuple)) * 1000, resolution]


def timestamp_range(text):
    """Identifies range in the text given. Returns -1 if the range has not been
    identified.  """

    # Parse range
    m = re.match(r'^(last)?\s*(\d+)?\s*(s|sec|second|m|min|minute|h|hour|d|day|mon|month|y|year)s?$', text.strip())
    if not m:
        return -1
    count = m.group(2)  # Count of time frames
    tf = m.group(3)  # Time frame
    # Get count
    if count:
        count = int(count)
    else:
        count = 1
    # Get time frame
    f_groups = [
        [['s', 'sec', 'second'], SEC],
        [['m', 'min', 'minute'], MIN],
        [['h', 'hour'], HOUR],
        [['d', 'day'], DAY],
        [['mon', 'month'], MON],
        [['y', 'year'], YEAR],
    ]
    for tg in f_groups:
        if tf in tg[0]:
            return count * tg[1]
    return -1


def parse_timestamp_range(text):
    """Parses the time range given and return start-end pair of timestamps.

    Recognized structures are:
    t|today
    y|yesterday
    last? \\d* (m|min|minute|h|hour|d|day|mon|month|y|year) s?
    range
    datetime
    datetime -> range
    datetime -> datetime
    """

    text = text.strip()
    # No time frame
    if text == '':
        return [0, 9223372036854775807]

    # Day spec
    now = datetime.datetime.now()
    if text in ['t', 'today']:
        today = int(time.mktime(datetime.datetime(now.year, now.month, now.day).timetuple())) * 1000
        return [today, today + DAY]
    if text in ['y', 'yesterday']:
        yesterday = int(time.mktime(
            (datetime.datetime(now.year, now.month, now.day) -
                datetime.timedelta(days=1)).timetuple())) * 1000
        return [yesterday, yesterday + DAY]

    # Range spec
    parts = text.split('->')
    r = timestamp_range(parts[0])
    if (r != -1 and len(parts) > 1) or len(parts) > 2:
        die("Error: Date and range '%s' has invalid structure" % text)
    if r != -1:
        now = int(time.time() * 1000)
        return [now - r, now]

    # Date spec
    start_group = timestamp_group(parts[0])
    start = start_group[0]
    end = start + start_group[1]

    if len(parts) > 1:
        end_range = timestamp_range(parts[1])
        if end_range != -1:
            end = start + end_range
        else:
            end_group = timestamp_group(parts[1])
            end = end_group[0] + end_group[1]

    return [start, end]


def choose_account_key(accounts):
    """
    Allows user to select the right account.
    """
    if len(accounts) == 0:
        die('No account is associated with your profile. Log in to Logentries to create a new account.')
    if len(accounts) == 1:
        return accounts[0]['account_key']

    for i in range(0, len(accounts)):
        account = accounts[i]
        print >> sys.stderr, '[%s] %s %s' % (
            i, account['account_key'][:8], account['name'])

    while True:
        try:
            selection = int(raw_input('Pick account you would like to use: '))
            if selection in range(0, len(accounts)):
                return accounts[selection]['account_key']
        except ValueError:
            pass
        print >> sys.stderr, 'Invalid choice. Please try again or break with Ctrl+C.'


def retrieve_account_key():
    """
    Retrieves account keys from the web server.
    """
    while True:
        try:
            username = raw_input('Email: ')
            password = getpass.getpass()
            c = domain_connect(config, Domain.MAIN, Domain)
            c.request('POST', ACCOUNT_KEYS_API,
                      urllib.urlencode({'username': username, 'password': password}),
                      {
                          'Referer': 'https://logentries.com/login/',
                          'Content-type': 'application/x-www-form-urlencoded',
                      })
            response = c.getresponse()
            if not response or response.status != 200:
                resp_val = 'err'
                if response:
                    resp_val = response.status
                if resp_val == 403:
                    print >> sys.stderr, 'Error: Login failed. Invalid credentials.'
                else:
                    print >> sys.stderr, 'Error: Unexpected login response from logentries (%s).' % resp_val
            else:
                data = json_loads(response.read())
                return choose_account_key(data['accounts'])
        except socket.error, msg:
            print >> sys.stderr, 'Error: Cannot contact server, %s' % msg
        except ValueError, msg:
            print >> sys.stderr, 'Error: Invalid response from the server (Parsing error %s)' % msg
        except KeyError:
            print >> sys.stderr, 'Error: Invalid response from the server, user key not present.'

        print >> sys.stderr, 'Try to log in again, or press Ctrl+C to break'


class Stats(object):

    """Collects statistics about the system work load.
    """

    def __init__(self):
        self.timer = None
        self.to_remove = False
        self.first = True

        # Memory fields we are looking for in /proc/meminfo
        self.MEM_FIELDS = ['MemTotal:', 'Active:', 'Cached:']
        # Block devices in the system
        all_devices = [os.path.basename(filename)
                       for filename in glob.glob(SYS_BLOCK_DEV + '/*')]
        # Monitored devices (all devices except loop)
        self.our_devices = frozenset([device_name for device_name in all_devices if
                                      not device_name.startswith("loop") and not device_name.startswith(
                                          "ram") and not device_name.startswith("md")])

        self.prev_cpu_stats = [0, 0, 0, 0, 0, 0, 0]
        self.prev_disk_stats = [0, 0]
        self.prev_net_stats = [0, 0]
        self.total = {}
        self.total['dr'] = 0
        self.total['dw'] = 0
        self.total['ni'] = 0
        self.total['no'] = 0

        self.procfilesystem = True
        if not os.path.exists(CPUSTATS_FILE):
            # store system type for later reference in pulling stats
            # in an alternate manner
            self.procfilesystem = False
            self.uname = platform.uname()
            self.sys = self.uname[0]
            log.debug('sys: %s', self.sys)

        # for scaling in osx_top_stats -- key is a scale factor (gig,
        # meg, etc), value is what to multiply by to get to kilobytes
        self.scale2kb = {'M': 1024, 'G': 1048576}

        if not config.debug_nostats:
            pass
            # New stats will go here

    @staticmethod
    def save_data(data, name, value):
        """
        Saves the value under the name given. Negative values are set to 0.
        """
        if value >= 0:
            data[name] = value
        else:
            data[name] = 0

    def cpu_stats(self, data):
        """
        Collects CPU statistics. Virtual ticks are ignored.
        """
        try:
            for line in fileinput.input([CPUSTATS_FILE]):
                if len(line) < 13:
                    continue
                if line.startswith('cpu '):
                    raw_stats = [long(part) for part in line.split()[1:8]]
                    break
            fileinput.close()
        except IOError:
            return

        self.save_data(data, 'cu', raw_stats[0] - self.prev_cpu_stats[0])
        self.save_data(data, 'cl', raw_stats[1] - self.prev_cpu_stats[1])
        self.save_data(data, 'cs', raw_stats[2] - self.prev_cpu_stats[2])
        self.save_data(data, 'ci', raw_stats[3] - self.prev_cpu_stats[3])
        self.save_data(data, 'cio', raw_stats[4] - self.prev_cpu_stats[4])
        self.save_data(data, 'cq', raw_stats[5] - self.prev_cpu_stats[5])
        self.save_data(data, 'csq', raw_stats[6] - self.prev_cpu_stats[6])
        self.prev_cpu_stats = raw_stats

    def disk_stats(self, data):
        """
        Collects disk statistics. Interested in block devices only.
        """
        reads = 0L
        writes = 0L
        # For all block devices
        for device in self.our_devices:
            try:
                # Read device stats
                f = open(SYS_BLOCK_DEV + device + '/stat', 'r')
                line = f.read()
                f.close()
            except IOError:
                continue

            # Parse device stats
            parts = line.split()
            if len(parts) < 7:
                continue
            reads += long(parts[2])
            writes += long(parts[6])

        reads *= 512
        writes *= 512
        self.save_data(data, 'dr', reads - self.prev_disk_stats[0])
        self.save_data(data, 'dw', writes - self.prev_disk_stats[1])
        self.prev_disk_stats = [reads, writes]
        self.total['dr'] = reads
        self.total['dw'] = writes

    def mem_stats(self, data):
        """
        Collects memory statistics.
        """
        mem_vars = {}
        for field in self.MEM_FIELDS:
            mem_vars[field] = 0L
        try:
            for line in fileinput.input([MEMSTATS_FILE]):
                parts = line.split()
                name = parts[0]
                if name in self.MEM_FIELDS:
                    mem_vars[name] = long(parts[1])
            fileinput.close()
        except IOError:
            return
        self.save_data(data, 'mt', mem_vars[self.MEM_FIELDS[0]])
        self.save_data(data, 'ma', mem_vars[self.MEM_FIELDS[1]])
        self.save_data(data, 'mc', mem_vars[self.MEM_FIELDS[2]])

    def net_stats(self, data):
        """
        Collects network statistics. Collecting only selected interfaces.
        """
        receive = 0L
        transmit = 0L
        try:
            for line in fileinput.input([NETSTATS_FILE]):
                if line[:5] in NET_DEVICES:
                    parts = line.replace(':', ' ').split()
                    receive += long(parts[1])
                    transmit += long(parts[9])
            fileinput.close()
        except IOError:
            return

        self.save_data(data, 'ni', receive - self.prev_net_stats[0])
        self.save_data(data, 'no', transmit - self.prev_net_stats[1])
        self.prev_net_stats = [receive, transmit]
        self.total['ni'] = receive
        self.total['no'] = transmit

    def osx_top_stats(self, data):
        """
        Darwin/OS-X doesn't seem to provide nearly the same amount of
        detail as the /proc filesystem under Linux -- at least not
        easily accessible to the command line.  The headers from
        top(1) seem to be the quickest & most detailed source of data
        about CPU, and disk transfer as separated into reads & writes.
        (vs. iostat, which shows CPU less granularly; it shows more
         detail about per-disk IO, but does not split IO into reads and
         writes)

        Frustratingly, the level of per-disk statistics from top is
        incredibly un-granular

        We'll get physical memory details from here too
        """
        cpure = re.compile(r'CPU usage:\s+([\d.]+)\% user, ([\d.]+)\% sys, '
                           r'([\d.]+)\% idle')
        memre = re.compile(r'PhysMem:\s+(\d+\w+) wired, '
                           r'(\d+\w+) active, (\d+\w+) inactive, '
                           r'(\d+\w+) used, (\d+\w+) free.')
        diskre = re.compile(r'Disks: (\d+)/(\d+\w+) read, '
                            r'(\d+)/(\d+\w+) written.')

        # scaling routine for use in map() later
        def scaletokb(value):
            # take a value like 1209M or 10G and return an integer
            # representing the value in kilobytes

            (size, scale) = re.split('([A-z]+)', value)[:2]
            size = int(size)
            if scale:
                if scale in self.scale2kb:
                    size *= self.scale2kb[scale]
                else:
                    log.warning("Error: value in %s expressed in "
                                "dimension I can't translate to kb: %s %s",
                                line, size, scale)
            return size

        # the first set of 'top' headers display average values over
        # system uptime.  so we only want to read the second set that we
        # see.
        toppass = 0

        # we should really do this first, so that we don't waste any time
        # if top fails to work.  however, it 'reads' better at this point
        try:
            proc = subprocess.Popen(['top',
                                     '-i', '2', '-l', '2', '-n', '0'],
                                    stdout=subprocess.PIPE)
        except:
            return

        for line in proc.stdout:
            # skip the first output
            if line.startswith('Processes: '):
                toppass += 1
            elif line.startswith('CPU usage: ') and toppass == 2:
                cpuresult = cpure.match(line)
                """
                the data we send to logentries is expected to be in terms
                of centiseconds of (user/system/idle/etc) time as all we
                have is %, multiply that % by the EPOCH and 100.
                """
                if cpuresult:
                    (cu, cs, ci) = map(lambda x: int(float(x) * 100 * EPOCH),
                                       cpuresult.group(1, 2, 3))
                    self.save_data(data, 'cu', cu)
                    self.save_data(data, 'cs', cs)
                    self.save_data(data, 'ci', ci)
                    # send zero in case all must be present
                    self.save_data(data, 'cl', 0)
                    self.save_data(data, 'cio', 0)
                    self.save_data(data, 'cq', 0)
                    self.save_data(data, 'csq', 0)
                else:
                    log.warning("Error: could not parse CPU stats "
                                "in top output line %s", line)

            elif line.startswith('PhysMem: ') and toppass == 2:
                """
                OS-X has no fixed cache size -- cached pages are stored in
                virtual memory as part of the Unified Buffer Cache.  It
                would appear to be nearly impossible to find out what the
                current size of the UBC is, save running purge(8) and
                comparing the values before and after -- UBC uncertainty
                principal? :-)

                http://wagerlabs.com/blog/2008/03/04/hacking-the-mac-osx-unified-buffer-cache/
                books.google.ie/books?isbn=0132702266
                http://reviews.cnet.com/8301-13727_7-57372267-263/purge-the-os-x-disk-cache-to-analyze-memory-usage/
                """
                memresult = memre.match(line)
                if memresult:
                    # logentries is expecting values in kilobytes
                    (wired, active, inactive, used, free) = map(
                        scaletokb, memresult.group(1, 2, 3, 4, 5))
                    self.save_data(data, 'mt', used + free)
                    self.save_data(data, 'ma', active)
                    self.save_data(data, 'mc', 0)
                else:
                    log.warning("Error: could not parse memory stats "
                                "in top output line %s", line)

            elif line.startswith('Disks: ') and toppass == 2:
                diskresult = diskre.match(line)
                """
                the data we send to logentries is expected to be in bytes
                """
                if diskresult:
                    (reads, writes) = map(scaletokb,
                                          diskresult.group(2, 4))
                    reads *= 1024
                    writes *= 1024

                    self.save_data(data, 'dr',
                                   reads - self.prev_disk_stats[0])
                    self.save_data(data, 'dw',
                                   writes - self.prev_disk_stats[1])
                    self.prev_disk_stats = [reads, writes]
                else:
                    log.warning("Error: could not parse disk stats "
                                "in top output line %s", line)

    def netstats_stats(self, data):
        """
        Read network bytes in/out from the output of "netstat -s"
        Not exact, as on OS-X it doesn't display bytes for every protocol,
        but more exact than using 'top' or 'netstat <interval>'
        """
        try:
            proc = subprocess.Popen(['netstat', '-bi'],
                                    stdout=subprocess.PIPE)
        except:
            return

        # if we see 11 non-blank fields,
        # #7 is input bytes, and #10 is output bytes, but avoid duplicate
        # device lines

        receive = 0L
        transmit = 0L
        netseen = {}

        for line in proc.stdout:
            if line.startswith('Name'):
                continue

            parts = line.split()
            if len(parts) != 11:
                continue
            if parts[1] in netseen:
                continue
            if not parts[6].isdigit():
                continue

            receive += long(parts[6])
            transmit += long(parts[9])
            netseen[parts[0]] = 1

        self.save_data(data, 'ni', receive - self.prev_net_stats[0])
        self.save_data(data, 'no', transmit - self.prev_net_stats[1])
        self.prev_net_stats = [receive, transmit]

    def stats(self):
        """Collects statistics."""
        data = {}

        if self.procfilesystem:
            self.cpu_stats(data)
            self.disk_stats(data)
            self.mem_stats(data)
            self.net_stats(data)
        else:
            if self.sys == "Darwin":
                self.osx_top_stats(data)
                self.netstats_stats(data)
        return data

    @staticmethod
    def new_request(rq):
        try:
            response = api_request(
                rq, silent=not config.debug, die_on_error=False)
            if config.debug_stats:
                log.info(response)
        except socket.error:
            pass

    def schedule(self, next_step):
        if not self.to_remove:
            self.timer = threading.Timer(next_step, self.send_stats, ())
            self.timer.daemon = True
            self.timer.start()

    def start(self):
        self.schedule(1)

    def send_stats(self):
        """
        Collects all statistics and sends them to Logentries.
        """
        ethalon = time.time()

        results = self.stats()
        results['request'] = RQ_WORKLOAD
        results['host_key'] = config.agent_key
        if config.debug_stats:
            log.info(results)
        if not self.first:
            # Send data
            if not config.datahub:
                self.new_request(results)
        else:
            self.first = False

        ethalon += EPOCH
        next_step = (ethalon - time.time()) % EPOCH
        self.schedule(next_step)

    def cancel(self):
        self.to_remove = True
        if self.timer:
            self.timer.cancel()


class Follower(object):

    """
    The follower keeps an eye on the file specified and sends new events to the
    logentries infrastructure.  """

    def __init__(self, name, event_filter, transport, formatter):
        """ Initializes the follower. """
        self.name = name
        self.flush = True
        self.event_filter = event_filter
        self.formatter = formatter
        self.transport = transport

        self._file = None
        self._shutdown = False
        self._worker = threading.Thread(
            target=self.monitorlogs, name=self.name)
        self._worker.daemon = True
        self._worker.start()

    def _file_candidate(self):
        """
        Returns list of file names which corresponds to the specified template.
        """
        try:
            candidates = glob.glob(self.name)

            if len(candidates) == 0:
                return None

            candidate_times = [[os.path.getmtime(name), name]
                               for name in candidates]
            candidate_times.sort()
            candidate_times.reverse()
            return candidate_times[0][1]
        except os.error:
            return None

    def _open_log(self):
        """Keeps trying to re-open the log file. Returns when the file has been
        opened or when requested to remove.  """
        error_info = True
        self.real_name = None

        while not self._shutdown:
            candidate = self._file_candidate()

            if candidate:
                self.real_name = candidate
                try:
                    self._close_log()
                    self._file = open(self.real_name)
                    break
                except IOError:
                    pass

            if error_info:
                log.info("Cannot open file '%s', re-trying in %ss intervals",
                         self.name, REOPEN_INT)
                error_info = False
            time.sleep(REOPEN_TRY_INTERVAL)

    def _close_log(self):
        if self._file:
            try:
                self._file.close()
            except IOError:
                pass
            self._file = None

    def _log_rename(self):
        """Detects file rename."""

        # Get file candidates
        candidate = self._file_candidate()
        if not candidate:
            return False

        try:
            ctime1 = os.fstat(self._file.fileno()).st_mtime
            ctime_new = os.path.getmtime(candidate)
            ctime2 = os.fstat(self._file.fileno()).st_mtime
        except os.error:
            pass

        if ctime1 == ctime2 and ctime1 != ctime_new:
            # We have a name change according to the time
            return True

        return False

    def _read_log_line(self):
        """ Reads a line from the log. Checks maximal line size. """
        buff = self._file.readline(MAX_EVENTS)
        return buff

    def _set_file_position(self, offset, start=FILE_BEGIN):
        """ Move the position of filepointers."""
        self._file.seek(offset, start)

    def _get_file_position(self):
        """ Returns the position filepointers."""
        pos = self._file.tell()
        return pos

    def _get_line(self):
        """
        Returns a block of newly detected line from the log. Returns None in case of timeout.
        """
        # Moves at the end of the log file
        if self.flush:
            self._set_file_position(0, FILE_END)
            self.flush = False

        # TODO: investigate select-like approach?
        idle_cnt = 0
        iaa_cnt = 0
        line = None
        while iaa_cnt != IAA_INTERVAL and not self._shutdown:
            # Collect line
            line = self._read_log_line()
            if len(line) != 0:
                break

            # No line, wait
            time.sleep(TAIL_RECHECK)

            # Log rename check
            idle_cnt += 1
            if idle_cnt == NAME_CHECK:
                if self._log_rename():
                    self._open_log()
                    iaa_cnt = 0
                else:
                    # Recover from external file modification
                    position = self._get_file_position()
                    self._set_file_position(0, FILE_END)
                    file_size = self._get_file_position()
                    if file_size < position:
                        # File has been externaly modified
                        position = file_size
                    self._set_file_position(position)
                idle_cnt = 0
            else:
                # To reset end-of-line error
                self._set_file_position(self._get_file_position())
            iaa_cnt += 1

        return line

    def _send_line(self, line):
        """ Sends the line. """
        if line:
            line = self.event_filter(line)
        if not line:
            return
        if config.debug_events:
            print >> sys.stderr, line,
        self.transport.send(self.formatter.format_line(line))

    def close(self):
        """Closes the follower by setting the shutdown flag and waiting for the
        worker thread to stop."""
        self._shutdown = True
        self._worker.join(1.0)

    def monitorlogs(self):
        """ Opens the log file and starts to collect new events. """
        self._open_log()
        while not self._shutdown:
            try:
                line = self._get_line()
                if line:
                    self._send_line(line)
            except IOError, e:
                if config.debug:
                    log.debug("IOError: %s", e)
                self._open_log()
            except UnicodeError, e:
                log.warn("Error sending line %s", line, exc_info=True)
            except Exception, e:
		log.error("Caught unknown error %s while sending line: %s", e, line, exc_info=True)
        self._close_log()


class Transport(object):

    """Encapsulates simple connection to a remote host. The connection may be
    encrypted. Each communication is started with the preamble."""

    def __init__(self, endpoint, port, use_ssl, preamble, debug_transport_events):
        # Copy transport configuration
        self.endpoint = endpoint
        self.port = port
        self.use_ssl = use_ssl
        self.preamble = preamble
        self._entries = Queue.Queue(SEND_QUEUE_SIZE)
        self._socket = None
        self._debug_transport_events = debug_transport_events

        self._shutdown = False

        # Get certificate name
        cert_name = None
        if not config.use_ca_provided:
            cert_name = system_cert_file()
            if cert_name is None:
                cert_name = default_cert_file(config)
        else:
            cert_name = default_cert_file(config)

        if use_ssl and not cert_name:
            die('Cannot get default certificate file name to provide connection over SSL!')
            # XXX Do we need to die here?
        self._certs = cert_name

        # Start asynchronous worker
        self._worker = threading.Thread(target=self.run)
        self._worker.daemon = True
        self._worker.start()

    def _get_address(self):
        """Returns an IP address of the endpoint. If the endpoint resolves to
        multiple addresses, a random one is selected. This works better than
        default selection."""
        return random.choice(
            socket.getaddrinfo(self.endpoint, self.port))[4][0]

    def _connect_ssl(self, plain_socket):
        """Connects the socket and wraps in SSL. Returns the wrapped socket
        or None in case of IO or other errors."""
        self._socket = None
        try:
            address = '-'
            address = self._get_address()
            s = plain_socket
            s.connect((address, self.port))

            try:
                s = ssl.wrap_socket(
                    plain_socket, ca_certs=self._certs,
                    cert_reqs=ssl.CERT_REQUIRED, ssl_version=ssl.PROTOCOL_TLSv1,
                    ciphers="HIGH:-aNULL:-eNULL:-PSK:RC4-SHA:RC4-MD5")
            except TypeError:
                s = ssl.wrap_socket(
                    plain_socket, ca_certs=self._certs, cert_reqs=ssl.CERT_REQUIRED,
                    ssl_version=ssl.PROTOCOL_TLSv1)

            try:
                match_hostname(s.getpeercert(), self.endpoint)
            except CertificateError, ce:
                report("Could not validate SSL certificate for %s: %s" %
                       (self.endpoint, ce.message))
                return None
            return s

        except IOError, e:
            cause = e.strerror
            if not cause:
                cause = "(No reason given)"
            report("Can't connect to %s/%s via SSL at port %s. Make sure that the host and port are reachable "
                   "and speak SSL: %s" % (self.endpoint, address, self.port, cause))
        return None

    def _connect_plain(self, plain_socket):
        """Connects the socket with the socket given. Returns the socket or None in case of IO errors."""
        self._socket = None
        address = self._get_address()
        try:
            plain_socket.connect((address, self.port))
        except IOError, e:
            cause = e.strerror
            if not cause:
                cause = ""
            report("Can't connect to %s/%s at port %s. Make sure that the host and port are reachable\n"
                   "Error message: %s" % (self.endpoint, address, self.port, e.strerror))
            return None
        return plain_socket

    def _open_connection(self):
        """ Opens a push connection to logentries. """
        log.debug("Opening connection %s:%s %s",
                  self.endpoint, self.port, self.preamble.strip())
        self._close_connection()
        retry = 0
        delay = SRV_RECON_TO_MIN
        # Keep trying to open the connection
        while not self._shutdown:
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(TCP_TIMEOUT)
                if self.use_ssl:
                    self._socket = self._connect_ssl(s)
                else:
                    self._socket = self._connect_plain(s)

                # If the socket is open, send preamble and leave
                if self._socket:
                    if self.preamble:
                        self._socket.send(self.preamble)
                    break
            except socket.error:
                if self._shutdown:
                    return  # XXX

            # Wait between attempts
            time.sleep(delay)
            retry += 1
            delay *= 2
            if delay > SRV_RECON_TO_MAX:
                delay = SRV_RECON_TO_MAX

    def _close_connection(self):
        if self._socket:
            try:
                self._socket.close()
            except socket.error:
                pass
            self._socket = None

    def _send_entry(self, entry):
        """Sends the entry. If the connection fails it will re-open it and try
        again."""
        # Keep sending data until successful
        while not self._shutdown:
            try:
                self._socket.send(entry)
                if self._debug_transport_events:
                    print >> sys.stderr, entry,
                break
            except socket.error:
                self._open_connection()

    def send(self, entry):
        """Sends the entry given. Depending on transport configuration it will
        block until the entry is sent or it will queue the entry for async
        send.

        Note: entry must end with a new line
        """
        while True:
            try:
                self._entries.put_nowait(entry)
                break
            except Queue.Full:
                try:
                    self._entries.get_nowait()
                except Queue.Empty:
                    pass

    def close(self):
        self._shutdown = True
        self._worker.join(1.5)

    def run(self):
        """When run with backgroud thread it collects entries from internal
        queue and sends them to destination."""
        self._open_connection()
        while not self._shutdown:
            try:
                entry = self._entries.get(True, 1)
                self._send_entry(entry)
            except Queue.Empty:
                pass
            except Exception:
                log.error("Exception in run: {0}".format(traceback.format_exc()))
        self._close_connection()


class DefaultTransport(object):

    def __init__(self, xconfig):
        self._transport = None
        self._config = xconfig

    def get(self):
        if not self._transport:
            use_ssl = not self._config.suppress_ssl
            if self._config.datahub:
                endpoint = self._config.datahub_ip
                port = self._config.datahub_port
            else:
                endpoint = Domain.DATA
                if use_ssl:
                    port = 443
                else:
                    port = 80
            if config.force_domain:
                endpoint = self._config.force_domain
            elif self._config.force_data_host:
                endpoint = self._config.force_data_host
            if self._config.debug_local:
                endpoint = Domain.LOCAL
                port = 10000
                use_ssl = False
            self._transport = Transport(
                endpoint, port, use_ssl, '', self._config.debug_transport_events)
        return self._transport

    def close(self):
        if self._transport:
            self._transport.close()


class ConfiguredLog(object):

    def __init__(self, name, token, destination, path):
        self.name = name
        self.token = token
        self.destination = destination
        self.path = path
        self.logset = None
        self.set_key = None
        self.log_key = None

    def is_logset(self):
        """
        Flag on whether its a valid sharedlog/logset.
        """
        return self.logset


class Config(object):

    def __init__(self):
        self.config_dir_name = self.get_config_dir()
        self.config_filename = self.config_dir_name + LE_CONFIG

        # Configuration variables
        self.agent_key = NOT_SET
        self.suppress_ssl = False
        self.use_ca_provided = False
        self.user_key = DEFAULT_USER_KEY
        self.datahub = NOT_SET
        self.datahub_ip = NOT_SET
        self.datahub_port = NOT_SET
        self.system_stats_token = NOT_SET
        self.pull_server_side_config = NOT_SET
        self.configured_logs = []
        self.metrics = metrics.MetricsConfig()

        # Special options
        self.daemon = False
        self.filters = NOT_SET
        self.formatter = NOT_SET
        self.custom_format = NOT_SET
        self.force = False
        self.hostname = NOT_SET
        self.name = NOT_SET
        self.no_timestamps = False
        self.pid_file = PID_FILE
        self.std = False
        self.std_all = False
        self.system_stats_token = NOT_SET
        self.type_opt = NOT_SET
        self.uuid = False
        self.xlist = False
        self.yes = False

        # Debug options

        # Enabled fine-grained logging
        self.debug = False
        # All recognized events are logged
        self.debug_events = False
        # All transported events are logged
        self.debug_transport_events = False
        # All filtering actions are logged
        self.debug_filters = False
        # All metrics actions are logged
        self.debug_metrics = False
        # Adapter connects to locahost
        self.debug_local = False
        # Do not collect statistics
        self.debug_nostats = False
        # Collected statistics are logged
        self.debug_stats = False
        # Collect statistics only
        self.debug_stats_only = False
        # Commands passed to server are logged
        self.debug_requests = False
        # Display system information and exit
        self.debug_system = False
        # Display list of logs in the system
        self.debug_loglist = False
        # Force host for api
        self.force_api_host = NOT_SET
        # Force host for data
        self.force_data_host = NOT_SET
        # Force host for this domain
        self.force_domain = NOT_SET

    def get_config_dir(self):
        """
        Identifies a configuration directory for the current user.
        Always terminated with slash.
        """
        if os.geteuid() == 0:
            # Running as root
            c_dir = CONFIG_DIR_SYSTEM
        else:
            # Running as an ordinary user
            c_dir = os.path.expanduser('~') + '/' + CONFIG_DIR_USER

        return c_dir + '/'

    def clean(self):
        """
        Wipes out old configuration file. Returns True if successful.
        """
        try:
            os.remove(self.config_filename)
        except OSError, e:
            if e.errno != 2:
                log.warning("Error: %s: %s",
                            self.config_filename, e.strerror)
                return False
        return True

    def basic_setup(self):
        pass

    def load(self):
        """
        Initializes configuration parameters from the configuration
        file.  Returns True if successful, False otherwise. Does not
        touch already defined parameters.
        """

        try:
            conf = ConfigParser.SafeConfigParser({
                USER_KEY_PARAM: '',
                AGENT_KEY_PARAM: '',
                FILTERS_PARAM: '',
                FORMATTER_PARAM: '',
                CUSTOM_FORMAT_PARAM: '',
                SUPPRESS_SSL_PARAM: '',
                FORCE_DOMAIN_PARAM: '',
                USE_CA_PROVIDED_PARAM: '',
                DATAHUB_PARAM: '',
                SYSSTAT_TOKEN_PARAM: '',
                HOSTNAME_PARAM: '',
                PULL_SERVER_SIDE_CONFIG_PARAM: 'True'
            })
            conf.read(self.config_filename)

            # Load parameters
            if self.user_key == NOT_SET:
                new_user_key = conf.get(MAIN_SECT, USER_KEY_PARAM)
                if new_user_key != '':
                    self.user_key = new_user_key
            if self.agent_key == NOT_SET:
                new_agent_key = conf.get(MAIN_SECT, AGENT_KEY_PARAM)
                if new_agent_key != '':
                    self.agent_key = new_agent_key
            if self.filters == NOT_SET:
                new_filters = conf.get(MAIN_SECT, FILTERS_PARAM)
                if new_filters != '':
                    self.filters = new_filters
            if self.formatter == NOT_SET:
                new_formatter = conf.get(MAIN_SECT, FORMATTER_PARAM)
                if new_formatter != '':
                    self.formatter = new_formatter
            if self.custom_format == NOT_SET:
                new_custom_format = conf.get(MAIN_SECT, CUSTOM_FORMAT_PARAM)
                if new_custom_format != '':
                    self.custom_format = new_custom_format
            if self.hostname == NOT_SET:
                self.hostname = conf.get(MAIN_SECT, HOSTNAME_PARAM)
                if not self.hostname:
                    self.hostname = NOT_SET
            if self.pull_server_side_config == NOT_SET:
                new_pull_server_side_config = conf.get(MAIN_SECT, PULL_SERVER_SIDE_CONFIG_PARAM)
                self.pull_server_side_config = new_pull_server_side_config == 'True'
                if new_pull_server_side_config is None:
                    self.pull_server_side_config = True

            new_suppress_ssl = conf.get(MAIN_SECT, SUPPRESS_SSL_PARAM)
            if new_suppress_ssl == 'True':
                self.suppress_ssl = new_suppress_ssl == 'True'
            new_force_domain = conf.get(MAIN_SECT, FORCE_DOMAIN_PARAM)
            if new_force_domain:
                self.force_domain = new_force_domain
            if self.datahub == NOT_SET:
                self.set_datahub_settings(
                    conf.get(MAIN_SECT, DATAHUB_PARAM), should_die=False)
            if self.system_stats_token == NOT_SET:
                system_stats_token_str = conf.get(
                    MAIN_SECT, SYSSTAT_TOKEN_PARAM)
                if system_stats_token_str != '':
                    self.system_stats_token = system_stats_token_str

            self.metrics.load(conf)

            self.load_configured_logs(conf)

        except ConfigParser.NoSectionError:
            # TODO: Warning
            return False
        except ConfigParser.NoOptionError:
            # TODO: Warning
            return False
        return True

    def load_configured_logs(self, conf):
        global log
        """
        Loads configured logs from the configuration file.
        These are logs that use tokens.
        """
        self.configured_logs = []
        account_hosts = None
        for name in conf.sections():
            if name != MAIN_SECT:
                token = ''
                try:
                    xtoken = conf.get(name, TOKEN_PARAM)
                    if xtoken:
                        token = uuid_parse(xtoken)
                        if not token:
                            log.warning("Invalid log token `%s' in section `%s'.", xtoken, name)
                except ConfigParser.NoOptionError:
                    pass
                path = conf.get(name, PATH_PARAM)

                destination = ''
                try:
                    destination = conf.get(name, DESTINATION_PARAM)
                except ConfigParser.NoOptionError:
                    pass

                configured_log = ConfiguredLog(name, token, destination, path)

                self.configured_logs.append(configured_log)

    def save(self):
        """
        Saves configuration parameters into the configuration file.
        The file with certificates is added as well.
        """
        try:
            conf = ConfigParser.SafeConfigParser()
            create_conf_dir(self)
            conf_file = open(self.config_filename, 'wb')
            conf.add_section(MAIN_SECT)
            if self.user_key != NOT_SET:
                conf.set(MAIN_SECT, USER_KEY_PARAM, self.user_key)
            if self.agent_key != NOT_SET:
                conf.set(MAIN_SECT, AGENT_KEY_PARAM, self.agent_key)
            if self.filters != NOT_SET:
                conf.set(MAIN_SECT, FILTERS_PARAM, self.filters)
            if self.formatter != NOT_SET:
                conf.set(MAIN_SECT, FORMATTER_PARAM, self.formatter)
            if self.custom_format != NOT_SET:
                conf.set(MAIN_SECT, CUSTOM_FORMAT_PARAM, self.custom_format)
            if self.hostname != NOT_SET:
                conf.set(MAIN_SECT, HOSTNAME_PARAM, self.hostname)
            if self.suppress_ssl:
                conf.set(MAIN_SECT, SUPPRESS_SSL_PARAM, 'True')
            if self.use_ca_provided:
                conf.set(MAIN_SECT, USE_CA_PROVIDED_PARAM, 'True')
            if self.force_domain:
                conf.set(MAIN_SECT, FORCE_DOMAIN_PARAM, self.force_domain)
            if self.pull_server_side_config != NOT_SET:
                conf.set(MAIN_SECT, PULL_SERVER_SIDE_CONFIG_PARAM, "%s" %
                         self.pull_server_side_config)
            if self.datahub != NOT_SET:
                conf.set(MAIN_SECT, DATAHUB_PARAM, self.datahub)
            if self.system_stats_token != NOT_SET:
                conf.set(
                    MAIN_SECT, SYSSTAT_TOKEN_PARAM, self.system_stats_token)

            for clog in self.configured_logs:
                conf.add_section(clog.name)
                if clog.token:
                    conf.set(clog.name, TOKEN_PARAM, clog.token)
                conf.set(clog.name, PATH_PARAM, clog.path)
                if clog.destination:
                    conf.set(clog.name, DESTINATION_PARAM, clog.destination)

            self.metrics.save(conf)

            conf.write(conf_file)
        except IOError, e:
            die("Error: IO error when writing to config file: %s" % e)

    def check_key(self, key):
        """
        Checks if the key looks fine
        """
        return len(key) == KEY_LEN

    def set_user_key(self, value):
        if not self.check_key(value):
            die('Error: User key does not look right.')
        self.user_key = value

    def user_key_required(self, ask_for_it):
        """
        Exits with error message if the user key is not defined.
        """
        if self.user_key == NOT_SET:
            if ask_for_it:
                log.info(
                    "Account key is required. Enter your Logentries login "
                    "credentials or specify the account key with "
                    "--account-key parameter.")
                self.user_key = retrieve_account_key()
            else:
                die("Account key is required. Enter your account key with --account-key parameter.")
            config.save()

    def set_system_stat_token(self, value):
        if not self.check_key(value):
            die('Error: system stat token does not look right.')
        self.system_stats_token = value

    def system_stats_token_required(self):
        if self.system_stats_token == NOT_SET:
            die("System stat token is required.")
        config.save()

    def set_agent_key(self, value):
        if not self.check_key(value):
            die('Error: Agent key does not look right.')
        self.agent_key = value

    def agent_key_required(self):
        """
        Exits with error message if the agent key is not defined.
        """
        if self.agent_key == NOT_SET:
            die("Host key is required. Register the host or specify the host key with the --host-key parameter.")

    def have_agent_key(self):
        """Tests if the agent key has been assigned to this instance."""
        return self.agent_key != ''

    def hostname_required(self):
        """
        Sets the hostname parameter based on server network name. If
        the hostname is set already, it is kept untouched.
        """
        if self.hostname == NOT_SET:
            self.hostname = socket.getfqdn()
        return self.hostname

    def name_required(self):
        """
        Sets host name if not set already. The new host name is
        delivered from its hostname. As a side effect this
        function sets a hostname as well.
        """
        if self.name == NOT_SET:
            self.name = self.hostname_required().split('.')[0]
        return self.name

    # The method gets all parameters of given type from argument list,
    # checks for their format and returns list of values of parameters
    # of specified type. E.g: We have params = ['true', 127.0.0.1, 10000] the call of
    # check_and_get_param_by_type(params, type='bool') yields [True]

    @staticmethod
    def check_and_get_param_by_type(params, type='bool'):
        ret_param = []

        for p in params:
            found = False
            p = p.lower()
            if type == 'ipaddr':
                if p.find('.') != -1:
                    octets = p.split('.', 4)
                    octets_ok = True
                    if len(octets) == 4:
                        for octet in octets:
                            octets_ok &= (octet.isdigit()) and (0 <= int(octet) <= 255)
                    else:
                        octets_ok = False
                    found = octets_ok
            elif type == 'bool':
                if (p.find('true') != -1 and len(p) == 4) or (p.find('false') != -1 and len(p) == 5):
                    found = True
            elif type == 'numeric':
                if p.isdigit():
                    found = True
            else:
                raise NameError('Unknown type name')

            if found:
                if type == 'numeric':
                    ret_param.append(int(p))
                elif type == 'bool':
                    ret_param.append(p == 'true')
                else:
                    ret_param.append(p)

        return ret_param

    def set_datahub_settings(self, value, should_die=True):
        if not value and should_die:
            die('--datahub requires a parameter')
        elif not value and not should_die:
            return

        values = value.split(":")
        if len(values) > 2:
            die("Cannot parse %s for --datahub. Expected format: hostname:port" %
                value)

        self.datahub_ip = values[0]
        if len(values) == 2:
            try:
                self.datahub_port = int(values[1])
            except ValueError:
                die("Cannot parse %s as port. Specify a valid --datahub address" %
                    values[1])
        self.datahub = value

    def process_params(self, params):
        """
        Parses command line parameters and updates config parameters accordingly
        """
        param_list = """user-key= account-key= agent-key= host-key= no-timestamps debug-events
                    debug-transport-events debug-metrics
                    debug-filters debug-loglist local debug-stats debug-nostats
                    debug-stats-only debug-cmds debug-system help version yes force uuid list
                    std std-all name= hostname= type= pid-file= debug no-defaults
                    suppress-ssl use-ca-provided force-api-host= force-domain=
                    system-stat-token= datahub= pull-server-side-config= config="""
        try:
            optlist, args = getopt.gnu_getopt(params, '', param_list.split())
        except getopt.GetoptError, err:
            die("Parameter error: " + str(err))
        for name, value in optlist:
            if name == "--help":
                print_usage()
            if name == "--version":
                print_usage(True)
            if name == "--config":
                self.config_filename = value
            if name == "--yes":
                self.yes = True
            elif name == "--user-key":
                self.set_user_key(value)
            elif name == "--account-key":
                self.set_user_key(value)
            elif name == "--agent-key":
                self.set_agent_key(value)
            elif name == "--host-key":
                self.set_agent_key(value)
            elif name == "--force":
                self.force = True
            elif name == "--list":
                self.xlist = True
            elif name == "--uuid":
                self.uuid = True
            elif name == "--name":
                self.name = value
            elif name == "--hostname":
                self.hostname = value
            elif name == "--pid-file":
                if value == '':
                    self.pid_file = None
                else:
                    self.pid_file = value
            elif name == "--std":
                self.std = True
            elif name == "--type":
                self.type_opt = value
            elif name == "--std-all":
                self.std_all = True
            elif name == "--no-timestamps":
                self.no_timestamps = True
            elif name == "--debug":
                self.debug = True
            elif name == "--debug-events":
                self.debug_events = True
            elif name == "--debug-transport-events":
                self.debug_transport_events = True
            elif name == "--debug-filters":
                self.debug_filters = True
            elif name == "--debug-metrics":
                self.debug_metrics = True
            elif name == "--local":
                self.debug_local = True
            elif name == "--debug-stats":
                self.debug_stats = True
            elif name == "--debug-nostats":
                self.debug_nostats = True
            elif name == "--debug-stats-only":
                self.debug_stats_only = True
            elif name == "--debug-loglist":
                self.debug_loglist = True
            elif name == "--debug-requests":
                self.debug_requests = True
            elif name == "--debug-system":
                self.debug_system = True
            elif name == "--suppress-ssl":
                self.suppress_ssl = True
            elif name == "--force-api-host":
                if value and value != '':
                    self.force_api_host = value
            elif name == "--force-data-host":
                if value and value != '':
                    self.force_data_host = value
            elif name == "--force-domain":
                if value and value != '':
                    self.force_domain = value
            elif name == "--use-ca-provided":
                self.use_ca_provided = True
            elif name == "--system-stat-token":
                self.set_system_stat_token(value)
            elif name == "--pull-server-side-config":
                self.pull_server_side_config = value == "True"
            elif name == "--datahub":
                self.set_datahub_settings(value)

        if self.datahub_ip and not self.datahub_port:
            if self.suppress_ssl:
                self.datahub_port = LE_DEFAULT_NON_SSL_PORT
            else:
                self.datahub_port = LE_DEFAULT_SSL_PORT

        if self.debug_local and self.force_api_host:
            die("Do not specify --local and --force-api-host at the same time.")
        if self.debug_local and self.force_data_host:
            die("Do not specify --local and --force-data-host at the same time.")
        if self.debug_local and self.force_domain:
            die("Do not specify --local and --force-domain at the same time.")
        return args

config = Config()


def do_request(conn, operation, addr, data=None, headers={}):
    log.debug('Domain request: %s %s %s %s', operation, addr, data, headers)
    if data:
        conn.request(operation, addr, data, headers=headers)
    else:
        conn.request(operation, addr, headers=headers)


def get_response(operation, addr, data=None, headers={}, silent=False, die_on_error=True, domain=Domain.API):
    """
    Returns response from the domain or API server.
    """
    response = None
    conn = None
    try:
        conn = domain_connect(config, domain, Domain)
        do_request(conn, operation, addr, data, headers)
        response = conn.getresponse()
        return response, conn
    except socket.sslerror, msg:  # Network error
        if not silent:
            log.info("SSL error: %s", msg)
    except socket.error, msg:  # Network error
        if not silent:
            log.debug("Network error: %s", msg)
    except httplib.BadStatusLine:
        error = "Internal error, bad status line"
        if die_on_error:
            die(error)
        else:
            log.info(error)

    return None, None


def api_request(request, required=False, check_status=False, silent=False, die_on_error=True):
    """
    Processes a request on the logentries domain.
    """
    # Obtain response
    response, conn = get_response(
        "POST", LE_SERVER_API, urllib.urlencode(request),
        silent=silent, die_on_error=die_on_error, domain=Domain.API,
        headers={'Content-Type': 'application/x-www-form-urlencoded'})

    # Check the response
    if not response:
        if required:
            die("Error: Cannot process LE request, no response")
        if conn:
            conn.close()
        return None
    if response.status != 200:
        if required:
            die("Error: Cannot process LE request: (%s)" % response.status)
        conn.close()
        return None

    xresponse = response.read()
    conn.close()
    log.debug('Domain response: "%s"', xresponse)
    try:
        d_response = json_loads(xresponse)
    except ValueError:
        error = 'Error: Invalid response, parse error.'
        if die_on_error:
            die(error)
        else:
            log.info(error)
            d_response = None

    if check_status and d_response['response'] != 'ok':
        error = "Error: %s" % d_response['reason']
        if die_on_error:
            die(error)
        else:
            log.info(error)
            d_response = None

    return d_response


def pull_request(what, params):
    """
    Processes a pull request on the logentries domain.
    """
    response = None

    # Obtain response
    addr = '/%s/%s/?%s' % (
        config.user_key, urllib.quote(what), urllib.urlencode(params))
    response, conn = get_response("GET", addr, domain=Domain.PULL)

    # Check the response
    if not response:
        die("Error: Cannot process LE request, no response")
    if response.status == 404:
        die("Error: Log not found")
    if response.status != 200:
        die("Error: Cannot process LE request: (%s)" % response.status)

    while True:
        data = response.read(65536)
        if len(data) == 0:
            break
        sys.stdout.write(data)
    conn.close()


def request(request, required=False, check_status=False, rtype='GET', retry=False):
    """
    Processes a list request on the API server.
    """
    noticed = False
    while True:
        # Obtain response
        response, conn = get_response(
            rtype, urllib.quote('/' + config.user_key + '/' + request),
            die_on_error=not retry)

        # Check the response
        if response:
            break
        if required:
            die('Error: Cannot process LE request, no response')
        if retry:
            if not noticed:
                log.info('Error: No response from LE, re-trying in %ss intervals',
                         SRV_RECON_TIMEOUT)
                noticed = True
            time.sleep(SRV_RECON_TIMEOUT)
        else:
            return None

    response = response.read()
    conn.close()
    log.debug('List response: %s', response)
    try:
        d_response = json_loads(response)
    except ValueError:
        die('Error: Invalid response (%s)' % response)

    if check_status and d_response['response'] != 'ok':
        die('Error: %s' % d_response['reason'])

    return d_response


def _startup_info():
    """
    Prints correct startup information based on OS
    """
    if 'darwin' in sys.platform:
        log.info(
            '  sudo launchctl unload /Library/LaunchDaemons/com.logentries.agent.plist')
        log.info(
            '  sudo launchctl load /Library/LaunchDaemons/com.logentries.agent.plist')
    elif 'linux' in sys.platform:
        log.info('  sudo service logentries restart')
    elif 'sunos' in sys.platform:
        log.info('  sudo svcadm disable logentries')
        log.info('  sudo svcadm enable logentries')
    else:
        log.info('')


def create_log(host_key, name, filename, type_opt, do_follow=True, source=None):
    """
    Creates a log on server with given parameters.
    """
    request = {
        'request': 'new_log',
        'user_key': config.user_key,
        'host_key': host_key,
        'name': name,
        'filename': filename,
        'type': type_opt,
    }
    request['follow'] = 'true'

    if not do_follow:
        request['follow'] = 'false'

    if source:
        request['source'] = source
    resp = api_request(request, True, True)

    if resp['response'] == 'ok':
        return resp['log']
    return None


def create_host(name, hostname, system, distname, distver):
    """
    Creates a new host on server with given parameters.
    """
    request = {
        'request': 'register',
        'user_key': config.user_key,
        'name': name,
        'hostname': hostname,
        'system': system,
        'distname': distname,
        'distver': distver
    }
    resp = api_request(request, True, True)
    if resp['response'] == 'ok':
        return resp['host']
    else:
        return None


def request_follow(filename, name, type_opt):
    """
    Creates a new log to follow the file given.
    """
    config.agent_key_required()
    followed_log = create_log(config.agent_key, name, filename, type_opt)
    print "Will follow %s as %s" % (filename, name)
    log.info("Don't forget to restart the daemon")
    _startup_info()
    return followed_log


def get_cache_dir():
    """Returns a directory suitable for cached data.
    """
    # XXX For daemon use system cache directory
    home = os.path.expanduser('~')
    cache_home = os.environ.get('XDG_CACHE_HOME') or os.path.join(home, '.cache')
    path = os.path.join(cache_home, CORP)
    if not os.path.isdir(path):
        os.makedirs(path)
    return path


def get_cache_filename():
    """Gets full cache filename.
    """
    cache_dir = get_cache_dir()
    return os.path.join(cache_dir, CACHE_NAME)


def load_cache():
    """Loads or creates cache.
    """
    cache_filename = get_cache_filename()
    try:
        if os.path.exists(cache_filename):
            fcache = open(cache_filename, 'r')
            cache_content = fcache.read()
            fcache.close()
            return json_loads(cache_content)
    except ValueError:
        log.warn("Could not read cache, ignoring")
    except IOError:
        log.warn("Error while reading cache, ignoring")

    return {'host_keys':{}, 'log_tokens':{}}


def save_cache(cache):
    """Saves cache given.
    """
    cache_filename = get_cache_filename()
    try:
        fcache = open(cache_filename, 'w')
        fcache.write(json_dumps(cache, indent=4, separators=(',', ': ')))
        fcache.close()
    except IOError:
        log.warning("Cannot write to %s, consider adjusting XDG_CACHE_HOME" % cache_filename)


def request_hosts(load_logs=False):
    """Returns list of registered hosts.
    """
    if load_logs:
        xload_logs = 'true'
    else:
        xload_logs = 'false'
    response = api_request({
        'request': 'get_user',
        'load_hosts': 'true',
        'load_logs': xload_logs,
        'user_key': config.user_key}, True, True)

    return response['hosts']


def get_or_create_host(cache, host_name):
    """Gets or creates a new host and refreshes the cache if necessary
    """
    # Find the host in cache
    if host_name in cache['host_keys']:
        return cache['host_keys'][host_name]

    # Retrieve the host via API
    account_hosts = request_hosts(load_logs=True)
    host = find_api_obj_by_name(account_hosts, host_name)

    if not host:
        # If it does not exist, create a new one
        host = create_host(host_name, '', '', '', '')

    host_key = host['key']
    cache['host_keys'][host_name] = host_key
    return host_key


def get_or_create_log(cache, host_key, log_name, destination):
    """ Gets or creates a log for the host given. It returns logs's token or
    None.
    """
    if not host_key:
        return None

    # Find log in cache
    if destination in cache['log_tokens']:
        return cache['log_tokens'][destination]

    # Retrieve the log via API
    account_hosts = request_hosts(load_logs=True)
    host = find_api_obj_by_key(account_hosts, host_key)
    if not host:
        return None
    xlog = find_api_obj_by_name(host['logs'], log_name)
    if not xlog:
        # Try to create the log
        xlog = create_log(host['key'], log_name, '', '', do_follow=False, source='token')
        if not xlog:
            return None

    token = xlog.get('token', None)
    if token:
        cache['log_tokens'][destination] = token
    return token


#
# Commands
#

def cmd_init(args):
    """
    Saves variables given to the configuration file. Variables not
    specified are not saved and thus are overwritten with default value.
    The configuration directory is created if it does not exit.
    """
    no_more_args(args)
    config.user_key_required(True)
    config.save()
    log.info("Initialized")


def cmd_reinit(args):
    """
    Saves variables given to the configuration file. The configuration
    directory is created if it does not exit.
    """
    no_more_args(args)
    config.load()
    config.save()
    log.info("Reinitialized")


def cmd_register(args):
    """
    Registers the agent in logentries infrastructure. The newly obtained
    agent key is stored in the configuration file.
    """
    no_more_args(args)
    config.load()

    if config.agent_key != NOT_SET and not config.force:
        report("Warning: Server already registered. Use --force to override current registration.")
        return
    config.user_key_required(True)
    config.hostname_required()
    config.name_required()

    si = system_detect(True)

    host = create_host(config.name, config.hostname, si['system'], si['distname'], si['distver'])

    config.agent_key = host['key']
    config.save()

    log.info("Registered %s (%s)", config.name, config.hostname)

    # Registering logs
    logs = []
    if config.std or config.std_all:
        logs = collect_log_names(si)
    for logx in logs:
        if config.std_all or logx['default'] == '1':
            request_follow(logx['filename'], logx['name'], logx['type'])

# The function checks for 2 things: 1) that the path is not empty;
# 2) the path starts with '/' character which indicates that the log has
# a "physical" path which starts from filesystem root.


def check_file_name(file_name):
    return file_name.startswith('/')


def get_filters(available_filters, filter_filenames, log_name, log_key, log_filename, log_token):
    debug_filters(
        "Log name=%s id=%s filename=%s token=%s", log_name, log_key,
        log_filename, log_token)

    # Check filters
    if not filter_filenames(log_filename):
        debug_filters(
            " Log blocked by filter_filenames, not following")
        log.info(
            'Not following %s, blocked by filter_filenames', log_name)
        return None
    debug_filters(
        " Looking for filters by log name, log id, and token")

    event_filter = None
    if not event_filter and log_name:
        debug_filters(" Looking for filters by log name")
        event_filter = available_filters.get(log_name)
        if not event_filter:
            debug_filters(" No filter found by log name")

    if not event_filter and log_key:
        debug_filters(" Looking for filters by log ID")
        event_filter = available_filters.get(log_key)
        if not event_filter:
            debug_filters(" No filter found by log ID")

    if not event_filter and log_token:
        debug_filters(" Looking for filters by token")
        event_filter = available_filters.get(log_token)
        if not event_filter:
            debug_filters(" No filter found by token")

    if event_filter and not hasattr(event_filter, '__call__'):
        debug_filters(
            " Filter found, but ignored because it's not a function")
        event_filter = None
    if not event_filter:
        event_filter = filter_events
        debug_filters(" No filter found")
    else:
        debug_filters(" Using filter %s", event_filter)
    return event_filter


def start_followers(default_transport):
    """
    Loads logs from the server (or configuration) and initializes followers.
    """
    noticed = False
    logs = []
    followers = []
    transports = []

    if config.pull_server_side_config:
        # Use LE server as the source for list of followed logs
        while not logs:
            resp = request('hosts/%s/' %
                           config.agent_key, False, False, retry=True)
            if resp['response'] != 'ok':
                if not noticed:
                    log.error('Error retrieving list of logs: %s, retrying in %ss intervals',
                              resp['reason'], SRV_RECON_TIMEOUT)
                    noticed = True
                time.sleep(SRV_RECON_TIMEOUT)
                continue
            logs = resp['list']
            if not logs:
                time.sleep(SRV_RECON_TIMEOUT)
        # Select logs for the agent
        logs = [l for l in logs if l.get('follow') == 'true']

    for cl in config.configured_logs:
        # Unpack log dictionary
        log_path = cl.path
        log_name = cl.name
        log_token = cl.token
        # Construct response-like item which has the same structure as ones
        # returned by LE Server.
        logs.append(
            {'type': 'token', 'name': log_name, 'filename': log_path, 'key': '', 'token': log_token,
                     'follow': 'true'})

    available_filters = {}
    filter_filenames = default_filter_filenames
    if config.filters != NOT_SET:
        sys.path.append(config.filters)
        try:
            import filters

            available_filters = getattr(filters, 'filters', {})
            filter_filenames = getattr(
                filters, 'filter_filenames', default_filter_filenames)

            debug_filters("Available filters: %s", available_filters)
            debug_filters("Filter filenames: %s", filter_filenames)
        except:
            log.error('Cannot import event filter module %s: %s',
                      config.filters, sys.exc_info()[1])
            log.error('Details: %s', traceback.print_exc(sys.exc_info()))

    # Start followers
    for l in logs:
        # Note! Token-type logs have follow param == false by default, so we need to
        # check also the type of the log.
        if l['follow'] == 'true' or l['type'] == 'token':
            log_name = l['name']
            log_filename = l['filename']
            log_key = l['key']
            log_token = ''
            if l['type'] == 'token':
                log_token = l['token']

            # Do not start a follower for a log with absent filepath.
            if not check_file_name(log_filename):
                continue

            entry_filter = get_filters(available_filters, filter_filenames,
                                       log_name, log_key, log_filename,
                                       log_token)
            if not entry_filter:
                continue

            log.info("Following %s", log_filename)

            if log_token or config.datahub:
                if config.formatter == 'custom':
                    formatter = formatters.FormatCustom(config.custom_format, config.hostname, log_name, log_token)
                elif config.formatter == 'plain':
                    formatter = formatters.FormatPlain(log_token)
                elif config.formatter == 'syslog' or config.formatter == NOT_SET:
                    formatter = formatters.FormatSyslog(config.hostname, log_name, log_token)
                else:
                    log.error("Ignoring unknown formatter %s, using syslog format instead", config.formatter)
                    formatter = formatters.FormatSyslog(config.hostname, log_name, log_token)
                transport = default_transport.get()
            elif log_key:
                endpoint = Domain.API
                port = 443
                use_ssl = not config.suppress_ssl
                if not use_ssl:
                    port = 80
                if config.force_domain:
                    endpoint = config.force_domain
                if config.debug_local:
                    endpoint = Domain.LOCAL
                    port = 8081
                    use_ssl = False
                preamble = 'PUT /%s/hosts/%s/%s/?realtime=1 HTTP/1.0\r\n\r\n' % (
                    config.user_key, config.agent_key, log_key)
                formatter = formatters.FormatPlain('')
                transport = Transport(endpoint, port, use_ssl, preamble,
                                      config.debug_transport_events)
                transports.append(transport)
            else:
                continue

            # Instantiate the follower
            follower = Follower(log_filename, entry_filter, transport,
                                formatter)
            followers.append(follower)
    return (followers, transports)


def is_followed(filename):
    """Checks if the file given is followed.
    """
    host = request('hosts/%s/' % config.agent_key, True, True)
    logs = host['list']
    for ilog in logs:
        if ilog['follow'] == 'true' and filename == ilog['filename']:
            return True
    return False


def create_configured_logs(configured_logs):
    """ Get tokens for all configured logs. Logs with no token specified are
    retrieved via API and created if needed.
    """
    cache = load_cache()
    for clog in configured_logs:
        if not clog.destination and not clog.token:
            log.error('Ignoring section {} as neither {} nor {} is specified'.format(clog.name, TOKEN_PARAM, DESTINATION_PARAM))
            continue

        if clog.destination and not clog.token:
            try:
                (hostname, logname) = clog.destination.split('/', 1)
            except ValueError:
                log.error('Ignoring section %s since `%s\' does not contain host' % (clog.name, DESTINATION_PARAM))
            host_key = get_or_create_host(cache, hostname)
            token = get_or_create_log(cache, host_key, logname, clog.destination)
            if not token:
                log.error('Ignoring section %s, cannot create log' % clog.name)

            clog.token = token
    save_cache(cache)


def cmd_monitor(args):
    """Monitors host activity and sends events collected to logentries
    infrastructure.
    """
    no_more_args(args)
    config.load()
    stats = None
    smetrics = None

    # We need account and host ID to get server side configuration
    if config.pull_server_side_config:
        config.user_key_required(not config.daemon)
        config.agent_key_required()

    # Ensure all configured logs are created
    if config.configured_logs and not config.datahub:
        create_configured_logs( config.configured_logs)

    if config.daemon:
        daemonize()

    # Start default transport channel
    default_transport = DefaultTransport(config)

    # Register resource monitoring
    if config.agent_key != NOT_SET:
        stats = Stats()
        stats.start()
    formatter = formatters.FormatSyslog(config.hostname, 'le',
                                        config.metrics.token)
    smetrics = metrics.Metrics(config.metrics, default_transport,
                                formatter, config.debug_metrics)
    smetrics.start()

    followers = []
    transports = []
    try:
        # Load logs to follow and start following them
        if not config.debug_stats_only:
            (followers, transports) = start_followers(default_transport)

        # Park this thread
        while True:
            time.sleep(600)  # FIXME: is there a better way?
    except KeyboardInterrupt:
        pass

    print >> sys.stderr, "\nShutting down"
    # Stop metrics
    if stats:
        stats.cancel()
    if smetrics:
        smetrics.cancel()
    # Close followers
    for follower in followers:
        follower.close()
    # Close transports
    for transport in transports:
        transport.close()
    default_transport.close()


def cmd_monitor_daemon(args):
    """Monitors as a daemon host activity and sends events collected to
    logentries infrastructure.
    """
    config.daemon = True
    cmd_monitor(args)


def cmd_follow(args):
    """
    Follow the log file given.
    """
    if len(args) == 0:
        die("Error: Specify the file name of the log to follow.")
    if len(args) > 1:
        die("Error: Too many arguments.\n"
            "A common mistake is to use wildcards in path that is being "
            "expanded by shell. Enclose the path in single quotes to avoid "
            "expansion.")

    config.load()
    config.agent_key_required()
    # FIXME: follow to add logs into local configuration

    arg = args[0]
    filename = os.path.abspath(arg)
    name = config.name
    if name == NOT_SET:
        name = os.path.basename(filename)
    type_opt = config.type_opt
    if type_opt == NOT_SET:
        type_opt = ""

    # Check that we don't follow that file already
    if not config.force and is_followed(filename):
        log.warning('Already following %s', filename)
        return

    if len(glob.glob(filename)) == 0:
        log.warning('\nWARNING: File %s does not exist', filename)

    request_follow(filename, name, type_opt)


def cmd_followed(args):
    """
    Check if the log file given is followed.
    """
    if len(args) == 0:
        die("Error: Specify the file name of the log to test.")
    if len(args) != 1:
        die("Error: Too many arguments. Only one file name allowed.")
    config.load()
    config.agent_key_required()

    filename = os.path.abspath(args[0])

    # Check that we don't follow that file already
    if is_followed(filename):
        print 'Following %s' % filename
        sys.exit(EXIT_OK)
    else:
        print 'NOT following %s' % filename
        sys.exit(EXIT_NO)


def cmd_clean(args):
    """
    Wipes out old configuration file.
    """
    no_more_args(args)
    if config.clean():
        log.info('Configuration clean')


def cmd_whoami(args):
    """
    Displays information about this host.
    """
    config.load()
    config.agent_key_required()
    no_more_args(args)

    list_object(request('hosts/%s' % config.agent_key, True, True))
    print ''
    list_object(request('hosts/%s/' % config.agent_key, True, True))


def logtype_name(logtype_uuid):
    response = request('logtypes', True, True)
    all_logtypes = response['list']
    for logtype in all_logtypes:
        if logtype_uuid == logtype['key']:
            return logtype['shortcut']
    return 'unknown'


def list_object(request, hostnames=False):
    """
    Lists object request given.
    """
    t = request['object']
    index_name = 'name'
    item_name = ''
    if t == 'rootlist':
        item_name = 'item'
    elif t == 'host':
        print 'name =', request['name']
        print 'hostname =', request['hostname']
        print 'key =', request['key']
        print 'distribution =', request['distname']
        print 'distver =', request['distver']
        return
    elif t == 'log':
        print 'name =', request['name']
        print 'filename =', request['filename']
        print 'key =', request['key']
        print 'type =', request['type']
        print 'follow =', request['follow']
        if 'token' in request:
            print 'token =', request['token']
        if 'logtype' in request:
            print 'logtype =', logtype_name(request['logtype'])
        return
    elif t == 'list':
        print 'name =', request['name']
        return
    elif t == 'hostlist':
        item_name = 'host'
        if hostnames:
            index_name = 'hostname'
    elif t == 'logtype':
        print 'title =', request['title']
        print 'description =', request['desc']
        print 'shortcut =', request['shortcut']
        return
    elif t == 'loglist':
        item_name = 'log'
    elif t == 'logtypelist':
        item_name = 'logtype'
        index_name = 'shortcut'
    else:
        die('Unknown object type "%s". Agent too old?' % t)

    # Standard list, print it sorted
    ilist = request['list']
    ilist = sorted(ilist, key=lambda item: item[index_name])
    for item in ilist:
        if config.uuid:
            print item['key'],
        print "%s" % (item[index_name])
    print_total(ilist, item_name)


def is_log_fs(addr):
    """Tests if the address points for a log.
    """
    log_addrs = [r'(logs|apps)/.*/',
                 r'host(name)?s/.*/.*/']
    for la in log_addrs:
        if re.match(la, addr):
            return True
    return False


def cmd_ls_ips(ags):
    """
    List IPs used by the agent.
    """
    l = []
    for name in [Domain.MAIN, Domain.API, Domain.DATA, Domain.PULL]:
        for info in socket.getaddrinfo(name, None, 0, 0, socket.IPPROTO_TCP):
            ip = info[4][0]
            print >>sys.stderr, '%-16s %s' % (ip, name)
            l.append(ip)
    print l
    print ' '.join(l)


def cmd_ls(args):
    """
    General list command
    """
    if len(args) == 1 and args[0] == 'ips':
        cmd_ls_ips(args)
        return
    if len(args) == 0:
        args = ['/']
    config.load()
    config.user_key_required(True)

    addr = args[0]
    if addr.startswith('/'):
        addr = addr[1:]
    # Make sure we are not downloading log
    if is_log_fs(addr):
        die('Use pull to get log content.')

    # if addr.count('/') > 2:
    # die( 'Path not found')
    list_object(request(addr, True, True),
                hostnames=addr.startswith('hostnames'))


def cmd_rm(args):
    """
    General remove command
    """
    if len(args) == 0:
        args = ['/']
    config.load()
    config.user_key_required(True)

    addr = args[0]
    if addr.startswith('/'):
        addr = addr[1:]
    if addr.count('/') > 2:
        die('Path not found')
    response = request(addr, True, True, rtype='DELETE')
    report(response['reason'])


def cmd_pull(args):
    """
    Log pull command
    """
    if len(args) == 0:
        die(PULL_USAGE)
    config.load()
    config.user_key_required(True)

    params = {}

    addr = args[0]
    if addr.startswith('/'):
        addr = addr[1:]
    if addr.endswith('/'):
        addr = addr[:-1]
    if not is_log_fs(addr + '/'):
        die('Error: Not a log')

    if len(args) > 1:
        time_range = parse_timestamp_range(args[1])
        params['start'] = time_range[0]
        params['end'] = time_range[1]
    if len(args) > 2:
        params['filter'] = args[2]
    if len(args) > 3:
        try:
            limit = int(args[3])
        except ValueError:
            die('Error: Limit must be integer')
        if limit < 1:
            die('Limit must be above 0')
        params['limit'] = limit

    pull_request(addr, params)


#
# Main method
#

def main():
    """Serious business starts here.
    """
    # Read command line parameters
    args = config.process_params(sys.argv[1:])

    if config.debug:
        log.setLevel(logging.DEBUG)
    if config.debug_system:
        die(system_detect(True))
    if config.debug_loglist:
        die(collect_log_names(system_detect(True)))

    argv0 = sys.argv[0]
    if argv0 and argv0 != '':
        pname = os.path.basename(argv0).split('-')
        if len(pname) != 1:
            args.insert(0, pname[-1])

    if len(args) == 0:
        report(USAGE)
        sys.exit(EXIT_HELP)

    commands = {
        'init': cmd_init,
        'reinit': cmd_reinit,
        'register': cmd_register,
        'monitor': cmd_monitor,
        'monitordaemon': cmd_monitor_daemon,
        'follow': cmd_follow,
        'followed': cmd_followed,
        'clean': cmd_clean,
        'whoami': cmd_whoami,
        # Filesystem operations
        'ls': cmd_ls,
        'rm': cmd_rm,
        'pull': cmd_pull,
    }
    for cmd, func in commands.items():
        if cmd == args[0]:
            return func(args[1:])
    die('Error: Unknown command "%s".' % args[0])


if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        die("Terminated", EXIT_TERMINATED)
