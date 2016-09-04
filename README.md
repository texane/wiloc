# WiFi based tracking device and server


## Description

WiLoc (short for WIfi LOCator) is primarly a WiFi based tracking
device that reports to a web server.

In the simplest configuration, a wiloc device relies only on
WiFi to implement both tracking and Internet communication. That
is, no GPS and GSM modules are needed. It does so by using:
- DNS tunnelling to communicate information to the web server
through open access points,
- geolocation services to resolve MAC addresses into coordinates.

The following diagram describes how it works:
![HowItWorks](doc/dia/main.png)

So, it is mainly useful in urban environments where WiFi access
points are available, and for which a decent MAC to coordinate
mapping exists (ie. most cities ...).

Also, the protocol supports for a GPS auxiliary device when
available. This can be used for contributing logs to help WiFi
based gelocation services to maintain their databases.


## Installation

### Server

TODO: DNS zone configuration

TODO: server compilation

Server command line:
- -dns_laddr: DNS server local address (default: 0.0.0.0)
- -dns_lport: DNS server local port (default: 53)
- -http_laddr: HTTP server local address (default: 0.0.0.0)
- -http_lport: HTTP server local port (default: 80)
- -geoloc_key: Google geolocation API key

### Device
TODO: device compilation, flashing


## Implementation notes

- src/server: server specific code
- src/device: device specific code
- src/common/wiloc.h: protocol
