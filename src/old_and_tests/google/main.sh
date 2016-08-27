#!/usr/bin/env sh

# export K=googleapikey before running
curl -d @data00.json -H "Content-Type: application/json" -i 'https://www.googleapis.com/geolocation/v1/geolocate?key='$K
