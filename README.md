# Kerbside, a SPICE VDI proxy

Kerbside is a SPICE VDI protocol proxy written in python. The long term idea is
that this would sit out the front of your Shaken Fist cluster and provide VDI
access to VMs running inside the cluster. It does this by determining what
VM to proxy your traffic to based on the password you provide
when connecting.

Kerbside currently knows how to proxy console sessions for Shaken Fist,
OpenStack, and oVirt. Ironically, OpenStack is probably the best documented of
those at the moment because there are patches to add deployment support for
Kerbside to Kolla-Ansible, whereas there is no deployment support for Shaken
Fist just yet.

## Features

### Rich Desktop Experience
The best features of the SPICE protocol are supported by Kerbside. High
resolution desktops (tested to 4K), audio, USB device passthrough, drag
and drop, cut and paste, and multiple connections to the same console.

### Multiple Cloud Integration
Kerbside can proxy consoles from Shaken Fist, OpenStack, and oVirt. It
can integrate multiple sources at the same time. It is possible to extend
support to other platforms that support SPICE.

### Web Interface
For administrators of the proxy, a web interface shows information about all
of the avaialble consoles. This includes logging events, direct connections,
information about connected users, the ability to terminate sessions, and more. 

#### Bootstrap CSS

Kerbside uses bootstrap CSS for styling. This was constructed by downloading
Bootstrap 5.3 and jQuery 3.7.0 and then installing to `kerbside/api/static/js`.

#### Axios

Kerbside's web administration API uses Axios for HTTP requests. Version 1.6.5
is cached at `kerbside/api/static/js`.

### REST API
Kerbside plays nicely with brokers. The REST API provides everything needed
to integrate into other solutions.

### Ops Friendly
Logs well, including in JSON format if desired. Can log detailed traffic
information for audit. Speaks prometheus. Does TLS. Can be deployed with
kolla-ansible.



