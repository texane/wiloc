#!/usr/bin/env python


import sys
import json
import requests
try: import gpxpy, gpxpy.gpx
except: gpxpy = None


def mac_to_coord(macs, apikey, proxy = None):
    # return a pair (lat, lng)
    # use google api to retrieve location
    # https://developers.google.com/maps/documentation/geolocation/intro

    # url
    u = 'https://www.googleapis.com/geolocation/v1/geolocate?'
    u += 'key=' + apikey

    # headers
    h = { 'Content-Type': 'application/json' }

    if proxy != None: p = { 'https': proxy }
    else: p = None

    # build json manually
    x = '{' + '\n'
    x += ' "wifiAccessPoints": [' + '\n'
    for i in range(0, len(macs) - 1):
        x += '  { "macAddress": "' + macs[i] + '" }'
        if i != len(macs) - 2: x += ','
        x += '\n'
    x += ' ]' + '\n'
    x += '}' + '\n'

    try: r = requests.post(u, data = x, headers = h, proxies = p)
    except: return None

    if r.status_code != 200: return None

    if hasattr(r.json, '__call__'): j = r.json()
    else: j = r.json

    if 'location' not in j: return None
    if 'lat' not in j['location']: return None
    if 'lng' not in j['location']: return None

    return (j['location']['lat'], j['location']['lng'])


def read_ifile(ifile):
    try: f = open(ifile, 'r')
    except: return None

    all_macs = []
    macs = []

    in_macs = False
    while True:
        l = f.readline()
        if len(l) == 0: break
        l = l.strip()

        if len(l) == 0:
            if in_macs == True: all_macs.append(macs)
            in_macs = False
        elif in_macs == True:
            macs.append(l)
        elif l == 'macs:':
            macs = []
            in_macs = True

    if len(macs): all_macs.append(macs)

    return all_macs


def print_help():
    print('TODO, print help')
    return


def get_opts(ac, av):
    # command line options
    # -ifile <file>: the input file
    # -ofmt {txt, gpx}: the output format
    # -ofile <file>: the output file
    # -apikey <key>: the google api key
    # -proxy <proxy>: the google api key

    opts = {
        'ifile': None,
        'ofmt': 'txt',
        'ofile': None,
        'apikey': None,
        'proxy': None
    }

    if ac % 2: return None

    for i in range(0, ac - 1, 2):
        k = av[i + 0]
        v = av[i + 1]
        if k[0] != '-': return None
        if k[1:] not in opts.keys(): return None
        opts[k[1:]] = v

    for k in [ 'ifile', 'apikey' ]:
        if opts[k] == None: return None

    if opts['ofmt'] == 'gpx':
        if gpxpy == None:
            print('ERROR: gpxpy not installed')
            print('ERROR: https://github.com/tkrajina/gpxpy')
            return None

    return opts


def ofile_open(path, fmt):
    ofile = {
        'fmt': fmt,
        'file': None,
        'buf': '',
        'gpx': None,
        'gpx_track': None,
        'gpx_segment': None
    }

    if path != None:
        try: ofile['file'] = open(path, 'w')
        except: return None

    if fmt == 'gpx':
        try:
            gpx = gpxpy.gpx.GPX()
            gpx_track = gpxpy.gpx.GPXTrack()
            gpx_segment = gpxpy.gpx.GPXTrackSegment()
            gpx.tracks.append(gpx_track)
            gpx_track.segments.append(gpx_segment)
            ofile['gpx'] = gpx
            ofile['gpx_track'] = gpx_track
            ofile['gpx_segment'] = gpx_segment
        except:
            return None

    return ofile


def ofile_close(ofile):
    if ofile['fmt'] == 'gpx':
        try: ofile['buf'] = ofile['gpx'].to_xml()
        except: return -1

    try:
        if ofile['file'] == None: print(ofile['buf'])
        else: ofile['file'].write(ofile['buf'])
    except:
        return -1

    return 0


def ofile_add_coord(ofile, coord):
    lat = coord[0]
    lng = coord[1]

    if ofile['fmt'] == 'txt':
        ofile['buf'] += str(lat) + ', ' + str(lng) + '\n'
    elif ofile['fmt'] == 'gpx':
        p = gpxpy.gpx.GPXTrackPoint(lat, lng)
        ofile['gpx_segment'].points.append(p)

    return 0


def main(ac, av):

    opts = get_opts(ac - 1, av[1:])
    if opts == None:
        print_help()
        return -1

    all_macs = read_ifile(opts['ifile'])
    if all_macs == None: return -1

    ofile = ofile_open(opts['ofile'], opts['ofmt'])
    if ofile == None: return -1

    for macs in all_macs:
        coord = mac_to_coord(macs, opts['apikey'], proxy = opts['proxy'])
        if coord == None: continue
        ofile_add_coord(ofile, coord)

    ofile_close(ofile)

    return 0


main(len(sys.argv), sys.argv)
