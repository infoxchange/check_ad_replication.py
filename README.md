check_ad_replication.py
=======================

This is a Nagios plugin for checking the normal operation of a Samba-based Active Directory server (Domain Controller).

As of Samba 4.x, Samba is capable of running as an Active Directory server (ie. Domain Controller).

AD Domain Controllers are normally 'clustered' for redundancy (high availability).
When clustered, they 'replicate' their date between each other.
AD clusters do not have a 'master'. Replication is peer-to-peer.

This plugin runs the command `samba-tool drs showrepl` and summarises the results, to indicate which other servers in the cluster are currently unable to replicate with this server.

### Prerequisites
* If you using Linux or Unix to run Samba as an Active Directory Domain Controller (either as the primary or secondary Domain Controller)

Then this plugin is for you

This plugin is written in Python and requires the package `python-dateutil` in addition to the standard python packages.

### What it does

The plugin check_ad_replication.py runs the commands:

* net ads info
* samba-tool drs showrepl

It analyses the output of these commands, and provides a one-line summary of:

* which of this server's peers are currently failing
* the length of time each of the peers has been having problems

If everything is OK, it shows the elapsed time of the most recent replication for each of the peers.

#### Sample Output - OK

**`/usr/lib/nagios/plugins/check_ad_replication.py`**

`OK: Realm: cas.example.net.au OK: my-dc1 as of 3 mins, my-dc3 as of 3 mins, my-dc4 as of 3 mins, my-win-ad1 as of 3 mins|ok=4 fail=0`

#### Sample Output - Errors

**`/usr/lib/nagios/plugins/check_ad_replication.py`**

`CRITICAL: Realm: cas.example.net.au Failing: my-dc1 since 5 mins(!!), Still OK: my-dc3 as of 5 mins, my-dc4 as of 5 mins, my-win-ad1 as of 5 mins|ok=3, fail=1`

`CRITICAL: Realm: cas.example.net.au Failing: my-dc2 since 11 mins, my-dc3 since 11 mins, my-dc4 since 11 mins(!!), Still OK: my-win-ad1 as of 11 mins|ok=1, fail=3`

### Sample Configuration

This plugin is normally launched through NRPE. It needs to run as the 'root' user, and 'sudo' can be used to achieve this

On the Nagios server, create a service cfg (example only):

```
define service {
  service_description            ad_replication
  use                            generic-service
  host_name                      my-smb-server
  check_command                  check_nrpe!check_ad_replication
}
```
(the command cfg for 'check_nrpe' should already exist)

Add to the file `/etc/nagios/nrpe.cfg` on the Nagios client:

```
command[check_ad_replication] = /usr/bin/sudo  /usr/lib64/nagios/plugins/check_ad_replication.py
```
(don't forget to restart nrpe after modifying the nrpe.cfg file)

Add to the file `/etc/sudoers` on the Nagios client:

```
Defaults:nrpe !requiretty
Defaults:nrpe syslog_goodpri=debug
nrpe    ALL=(ALL)    NOPASSWD: /usr/lib64/nagios/plugins/check_ad_replication.py ""
```

Some Linux distributions use the username 'nagios' instead of 'nrpe'

### Performance Data

This plugin generates some summary information as Nagios performance data. This can be graphed using PNP4Nagios.

Graphs are generated for:

* the number of AD peers which are failing to replicate to this server
  -- and --
* the number of AD peers which are working (OK).

A PNP4Nagios template is provided. This template requires the stack_outline.php file to be present in the same directory as the template file check_ad_replication.php
stack_outline.php is available from:

* https://github.com/infoxchange/opstools/blob/master/nagios/pnp4nagios-templates/stack_outline.php
