# WiFi based geotracking


## Description

WiLoc (short for WIfi LOCator) is primarly a cheap WiFi based
tracking device that reports to a web server.

In the simplest configuration, a WiLoc device relies only on
WiFi to implement both tracking and Internet communication. That
is, no additional modules are needed (GPS, GSM ...). It does so
by using:
- DNS tunneling to communicate information (MAC addresses ...)
to the web server through open access points,
- geolocation services to resolve MAC addresses into coordinates.

The following diagram describes how it works:
![HowItWorks](doc/dia/main.png)

So, it is mainly useful in urban environments where WiFi access
points are available, and for which a decent MAC to coordinate
mapping exists (ie. most cities ...).

Also, the WiLoc protocol supports sending GPS coordinates when
an auxiliary GPS module is available. This can be used for
contributing logs to help WiFi based gelocation services to
maintain their databases.


## Installation

### Prerequisites

#### Delegate a DNS zone
First, you have to configure your DNS server so that queries to
a particular subdomain (let say my.zone.com) are redirected to
the WiLoc server. You can find more information on DNS tunneling
here:
http://beta.ivc.no/wiki/index.php/DNS_Tunneling

#### Install esp-open-sdk
Install the esp-open-sdk from
https://github.com/pfalcon/esp-open-sdk

#### Get a key to use Google geolocation service
All details available here:
https://developers.google.com/maps/documentation/geolocation/intro

### Compile and run the server
Compile the server executable:
```
cd $(WILOC_REPO)/src/server
make
```
Run the server it using the following command line options (may
require root priviledges):
```
sudo ./a.out
 -dns_laddr: DNS server local address (default: 0.0.0.0)
 -dns_lport: DNS server local port (default: 53)
 -http_laddr: HTTP server local address (default: 0.0.0.0)
 -http_lport: HTTP server local port (default: 80)
 -geoloc_key: Google geolocation API key
```

You can now connect on the server using a web browser.

### Compile and upload the device firmware
Compile and upload the firmware in the ESP8266 flash memory:
```
cd $(WILOC_REPO)/src/device
ESP_SDK_DIR=<sdk_path> CONFIG_DNS_ZONE=".my.zone.com" make -f esp8266.mk flash
```
