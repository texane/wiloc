# WiFi based tracking device and server


## Description

wiloc (short for WIfi LOCator) is primarly a WiFi based tracking
device that reports to a web server.

In the simplest configuration, a wiloc device relies only on
WiFi to implement both tracking and server communication. That
is, no GPS and GSM modules are needed. It does so by using:
- DNS tunnelling to communicate information to the web server
through open access points,
- geolocation services to resolve MAC addresses into coordinates.

So, it is mainly useful in urban environments for which MAC
to coordinates maps exist, and where open access points are
available (ie. most cities ...).

Also, the protocol supports for a GPS auxiliary device when
available. This can be used for contributing logs to help WiFi
based gelocation services to maintain their databases.


## Usage

server command line:
-dns_laddr: DNS server local address (default: 0.0.0.0)
-dns_lport: DNS server local port (default: 53)
-http_laddr: HTTP server local address (default: 0.0.0.0)
-http_lport: HTTP server local port (default: 80)
-geoloc_key: Google geolocation API key


## Source code

src/server: server specific code
src/device: device specific code
src/common/wiloc.h: protocol
