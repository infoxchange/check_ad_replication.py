#!/usr/bin/python

#############################################################################
#                                                                           #
# This script was initially developed by Infoxchange for internal use       #
# and has kindly been made available to the Open Source community for       #
# redistribution and further development under the terms of the             #
# GNU General Public License v2: http://www.gnu.org/licenses/gpl.html       #
# Copyright 2015 Infoxchange                                                #
#                                                                           #
#############################################################################
#                                                                           #
# This script is supplied 'as-is', in the hope that it will be useful, but  #
# neither Infoxchange nor the authors make any warranties or guarantees     #
# as to its correct operation, including its intended function.             #
#                                                                           #
# Or in other words:                                                        #
#       Test it yourself, and make sure it works for YOU.                   #
#                                                                           #
#############################################################################
# Author: George Hansper                     e-mail:  george@hansper.id.au  #
#############################################################################


import sys, getopt, re, subprocess
import dateutil.parser, dateutil.tz
import datetime
# for debugging:
import pprint

version = 'v1.0 $Id$'

#nagios return codes
UNKNOWN = 3
OK = 0
WARNING = 1
CRITICAL = 2

verbose=0
exit_code = 0
now = datetime.datetime.now(dateutil.tz.tzlocal())
message=''
perf_message=''
result_full=''
test_file = None

expect_host=None
expect_ip=None

def get_realm():
    realm = 'no_realm'
    bind_path = 'no_bind_path'
    ldap_server_name = 'none'
    ldap_server_ip = 'none'
    re_split = re.compile(r":\s+")
    if test_file:
        output = subprocess.check_output(['cat', test_file])
    else:
        output = subprocess.check_output(['net', 'ads','info'])
    for line in output.splitlines():
        fields = re_split.split(line)
        if fields[0].lower() == 'realm':
            realm = fields[1].lower()
        elif fields[0].lower() == 'bind path':
            bind_path = fields[1]
        elif fields[0].lower() == 'ldap server name':
            ldap_server_name = fields[1]
        elif fields[0].lower() == 'ldap server':
            ldap_server_ip = fields[1]
    return(realm,bind_path,ldap_server_name,ldap_server_ip)

def parse_date(date_str):
    if date_str == 'NTTIME(0)':
        return (dateutil.parser.parse('1 jan 1970 0:00 UTC'),'forever')
    date_obj = dateutil.parser.parse(date_str)
    date_delta = now - date_obj
    if date_delta.days >=2:
        how_long="%d days" % date_delta.days
    elif date_delta.total_seconds() > 6000: # 100 minutes
        how_long="%d hrs" % int(date_delta.total_seconds() / 3600)
    else:
        how_long="%d mins" % int(date_delta.total_seconds() / 60)
    return (date_obj,how_long)

def print_v(msg):
    global verbose
    if verbose:
        sys.stderr.write(msg+"\n")

def usage():
    print('Usage: ' + sys.argv[0] + " [-v] [-V]")
    print("""
    -v, --verbose  ... verbose messages, print full response
    -H, --host     ... expect this host as the LDAP server reported by 'net ads info'
    -I, --ip       ... expect this ip address as the LDAP server reported by 'net ads info'
    """)

def command_args(argv):
    global verbose, expect_host, expect_ip, test_file
    try:
        opts, args = getopt.getopt(argv, 'vhVH:I:T:', ['verbose', 'version', 'help', 'host=', 'ip='])
    except getopt.GetoptError:
        usage()
        sys.exit(3)
    for opt, arg in opts:
        if opt in ('-h', '--help'):
            usage()
            sys.exit(WARNING)
        elif opt in ('-V', '--version'):
            print(version)
            sys.exit(1)
        elif opt in ('-v', '--verbose'):
            verbose = 1
        elif opt in ('-H','--host'):
            expect_host = arg
        elif opt in ('-I','--iphost'):
            expect_ip = arg
        # Read data from this file (or fifo) instead of normal commands
        elif opt in ('-T','--test'):
            test_file = arg

# Parse command line args
command_args(sys.argv[1:])

(realm,bind_path,ldap_server_name,ldap_server_ip) = get_realm()

if realm == 'no_realm':
    print "CRITICAL: No realm in 'net ads info' output|ok=0"
    sys.exit(CRITICAL)
else:
    message = "Realm: %s" % realm
    exit_code=0

if expect_host is not None and not ( \
        ldap_server_name.startswith(expect_host+'.') or \
        ldap_server_name == expect_host ):
    message += ', LDAP server is: %s, expected: %s (!!)' % ( ldap_server_name, expect_host )
    exit_code=2
    
if expect_ip is not None and expect_ip != ldap_server_ip:
    message += ', LDAP server is: %s, expected: %s (!!)' % ( ldap_server_ip, expect_ip )
    exit_code=2

if test_file:
    output = subprocess.check_output(['cat', test_file])
else:
    output = subprocess.check_output(['samba-tool', 'drs','showrepl'])

re_object = re.compile(r"([^\s]*)"+bind_path,re.I)
re_object_bad = re.compile(r"([^\s]*)..=",re.I)
re_start_section=re.compile(r"^===*\s*(.*)")
re_last_success=re.compile(r"Last success @\s*(.*)")
re_peer_name = re.compile(r"([^ \\]*)\\([-A-Z0-9]+) +via|Server DNS name :\s*([-A-Z0-9]+)")
re_success=re.compile(r"Last attempt @\s*(.*) (was successful|failed)(, (.*))?")
re_failure=re.compile(r"Last attempt @\s*(.*) consecutive failure")

section='none'
peer_name = 'unknown'
ad_object = 'unknown'
isok =3

ad_peers=dict()
ad_objects=dict()
ad_objects_bad=dict()
nt_domains=dict()
peer_fail=dict()
peer_ok=dict()
peer_oldest_fail=dict()
peer_oldest_ok=dict()
object_fail=dict()
object_ok=dict()

for line in output.splitlines():
    match = re_start_section.match(line)
    if match:
        if match.group(1).startswith("IN"):
            section='in'
        elif match.group(1).startswith("OUT"):
            section='out'
        elif match.group(1).startswith("KCC"):
            section='kcc'
        else:
            section='none'
        peer_name = 'unknown'
        ad_object = 'unknown'
        isok = 3
        last_when_str = 'NTTIME(0)'
        last_when_t   = parse_date(last_when_str)
        if section not in peer_ok:
            peer_ok[section] = {}
        if section not in peer_fail:
            peer_fail[section] = {}
        if section not in peer_oldest_fail:
            peer_oldest_fail[section] = {}
        if section not in peer_oldest_ok:
            peer_oldest_ok[section] = {}
        if section not in object_fail:
            object_fail[section] = {}
        if section not in object_ok:
            object_ok[section] = {}
        continue

    match = re_object.search(line)
    if match:
        ad_object = match.group(1)
        if ad_object == '':
            ad_object='DC=...'
        if not ad_object in ad_objects:
            ad_objects[ad_object]=1
        if not ad_object in object_ok[section]:
            object_ok[section][ad_object] = 0
        if not ad_object in object_fail[section]:
            object_fail[section][ad_object] = 0
        continue
    elif re_object_bad.search(line):
        print_v("object not in my domain: %s"%line)
        ad_objects_bad[line.strip()]=1

    match = re_peer_name.search(line)
    if match:
        if match.group(2):
            nt_domain = match.group(1).strip()
            peer_name = match.group(2).lower()
            nt_domains[nt_domain] = 1
        elif match.group(3):
            peer_name = match.group(3).lower()
        if not peer_name in ad_peers:
            ad_peers[peer_name]=1
        if not peer_name in peer_ok[section]:
            peer_ok[section][peer_name] = 0
        if not peer_name in peer_fail[section]:
            peer_fail[section][peer_name] = 0
        continue

    last_result = re_success.search(line)
    if last_result:
        when_str = last_result.group(1)
        when_t = parse_date(when_str)
        if last_result.group(2) == 'was successful':
            isok=0
        else:
            isok=1

    # Peer last OK
    # If peer has failures, we want to know the OLDEST recent success
    # if peer is OK, we want to know the OLDEST recent success
    # BUT we want to distingush the 2 above cases
    if re_last_success.search(line):
        result = re_last_success.search(line) 
        last_when_str = result.group(1)
        last_when_t   = parse_date(last_when_str)

        if isok == 0:
            if peer_name in peer_ok[section]:
                peer_ok[section][peer_name] += 1
            else:
                peer_ok[section][peer_name] = 1
            if ad_object in object_ok[section]:
                object_ok[section][ad_object] += 1
            else:
                object_ok[section][ad_object] = 1
            if not peer_name in peer_oldest_ok[section] \
               or peer_oldest_ok[section][peer_name][0] > last_when_t[0]:
                peer_oldest_ok[section][peer_name] = last_when_t
        elif isok == 1:
            if peer_name in peer_fail[section]:
                peer_fail[section][peer_name] += 1
            else:
                peer_fail[section][peer_name] = 1
            if ad_object in object_fail[section]:
                object_fail[section][ad_object] += 1
            else:
                object_fail[section][ad_object] = 1
            if not peer_name in peer_oldest_fail[section] \
               or peer_oldest_fail[section][peer_name][0] > last_when_t[0]:
                peer_oldest_fail[section][peer_name] = last_when_t

# Analyse the results
# First, the critical list:
failing_peers=list()
ok_peers=list()

# Inbound replication - alert on this
for peer_name in sorted(ad_peers.keys()):
    if peer_fail['in'][peer_name] > 0:
        failing_peers.append(peer_name+' since '+peer_oldest_fail['in'][peer_name][1])
    else:
        ok_peers.append(peer_name+' as of '+peer_oldest_ok['in'][peer_name][1])

if len(failing_peers) > 0:
    exit_code |= 2
    message += ' Failing: ' + ", ".join(failing_peers) + '(!!)'
    if len(ok_peers) > 0:
        message += ', Still OK: ' + ", ".join(ok_peers)
else:
    exit_code |= 0
    message += ' OK: ' + ", ".join(ok_peers)

perf_message = 'ok=%d fail=%d' % ( len(ok_peers), len(failing_peers) )

# Any object outside of our domain (Domain Component / bind_path ) (highly unexpected)
# net ads info disagrees with samba-tool drs showrepl
if len(ad_objects_bad) != 0:
    message += ", %s bad objects (!!)" % len(ad_objects_bad.keys())
    exit_code != 2

if exit_code == 0:
  state = 'OK'
elif exit_code == 1:
  state = 'WARNING'
elif exit_code == 2 or exit_code == 3:
  state = 'CRITICAL'
  exit_code = 2
else:
  state = 'UNKNOWN'
  exit_code = 3

print('%s: %s|%s' % ( state, message, perf_message ))

# Long output message

result_full += "NTDomain: %s\n" % " ".join(nt_domains)

result_full += 'Bind Path: ' + bind_path
result_full += "\n"

for section in sorted(peer_ok.keys()):
    result_full += "\n%s:\n" % section
    for peer_name in sorted(ad_peers.keys()):
        if peer_name in peer_oldest_fail[section]:
            result_full+= "   %-12s failing since %s\n" % ( peer_name,peer_oldest_fail[section][peer_name][1] )
        if peer_name in peer_oldest_ok[section]:
            result_full+= "   %-12s ok as at %s\n" % ( peer_name,peer_oldest_ok[section][peer_name][1] )
    result_full += "   Objects:\n"
    for ad_object in ad_objects.keys():
        if ad_object in object_ok[section] or ad_object in object_fail[section]:
          result_full += '      %-28s' % ad_object
          if ad_object in object_ok[section]:
            result_full += ' %d OK' % object_ok[section][ad_object]
          if ad_object in object_fail[section]:
            result_full += ' %d failiing' % object_fail[section][ad_object]
          result_full += "\n"

if len(ad_objects_bad) != 0:
    result_full += "Bad Objects:\n   " + "\n   ".join(ad_objects_bad.keys())


if verbose:
    print(result_full)

sys.exit(exit_code)
