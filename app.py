#!/usr/bin/env python3


#Python Built-in Library
import os
import re  #regular expressions
import time
import subprocess
import secrets
import sys
import traceback
import json
import bson.json_util as bson_json_util
from bson.objectid import ObjectId
import logging
from typing import Dict, List
from io import StringIO
from datetime import datetime
from builtins import next
from socket import AF_INET, AF_INET6
import functools
import requests # get/post to another servic3

# import ipaddress

#External Python Mods
from ipaddress import IPv4Network
from flask import Response, flash, Flask, request, render_template, redirect, session, abort, jsonify, send_from_directory
from flask_cors import CORS
import configparser
import paramiko
from jinja2 import Template
from datetime import datetime, date, time, timedelta
from pymongo import MongoClient
import asyncio #await / async
import ipaddress
import jwt

import icmplib

#Local Python Mods
from modules.System_Specs import System_Specs
from modules.Helpers import Helpers
from modules.Proxmox import Proxmox
from modules.Mail import Mail

log = logging.getLogger(__name__)

#Flask App Configuration
    # Flask constructor takes the name of
    # current module (__name__) as argument.
app = Flask(__name__)
app.secret_key = secrets.token_urlsafe(16)
app.config['TEMPLATES_AUTO_RELOAD'] = True


# from OpenSSL import SSL
# context = SSL.Context(SSL.SSL.TLSv1_2_METHOD)
# context.use_privatekey_file('server.key')
# context.use_certificate_file('server.crt')
#https://rdap.arin.net/registry/ip/066.248.232.000

CORS(app, supports_credentials=True) # Remove supports_credentials if sending Cookies across domains is not wanted


# System Config Name
system_conf = 'system.ini'


@app.errorhandler(400)
def incorrect_request(e):
        return render_template('error.html', error=["The server could not understand the request"]), 400


@app.errorhandler(404)
def not_found_404(error):
        flash ('we have an error')
        return render_template('error.html' , error=error),404




@app.before_request
def print_log_before(*args, **kwargs):
    print("[%s] request %s, %s", request.remote_addr, request.url, "|".join(["%s:%s"%(k,v) for k,v in request.headers.items()]))


@app.after_request
def print_log_after(response, *args, **kwargs):
    print("AFTER REQUEST [%s] reponse %s, %s", request.remote_addr,  request.url, response.status_code)
    return response

# FLASK Headder HEADDER GLOBALLY\
@app.after_request
def apply_Header_Change(response):
    del response.headers["server"]
    response.headers["server"] = "SAMEORIGIN"
    return response


@app.route("/assets/<path:path>")
def static_dir(path):
    return send_from_directory("assets", path)



# ROUTES
@app.route('/')
def hello_world():
        return jsonify({
           "status": "success",
            "message": "Hello World!"
        })


@app.route('/TEST')
def TEST():
        # cmd_output = stdout.read('ls -alF')
        cmd_output = exec_send_print('ls -alF')
        # redirecting all the output in cmd_output variable
        return cmd_output

# @staticmethod
# def listHelper(str):
#     s = []
#     str = str.split(',')
#     for e in str:
#         s.append(e.replace("[", "")).replace("]","")
#
# @staticmethod
# def trimStr(str):
#     return str.replace('"', '')
#
# @staticmethod
# def parseList(str):
#     if ',' in str:
#         return listHelper(str)
#     return str


@app.route('/TEST2')
def TEST2():
        flash ('we have an error')
        data = ''
        return render_template('peers.html' , data=data), 200
#


@app.route('/get_routes_all/' , methods=['GET'])
def get_routes_all(*args, **kwargs):
        '''GET ROUTES'''

        '''
        BIRD 2.0.8 ready.
        Table master4:
        0.0.0.0/0            unreachable [default4 2022-09-24 18:40:24] * (200)
        	Type: static univ
        44.190.190.0/24      unicast [AS64555v4 2022-09-24 18:40:29 from 100.64.64.64] * (100) [AS64555i]
        	via 66.248.232.156 on ens18
        	Type: BGP univ
        	BGP.origin: IGP
        	BGP.as_path: 64555
        	BGP.next_hop: 66.248.232.156
        	BGP.local_pref: 101
        	BGP.community: (6556,43)
        66.248.232.128/25    unicast [direct1 2022-09-24 18:40:24] * (240)
        	dev ens18
        	Type: device univ
        44.31.50.128/25      unreachable [static4 2022-09-24 18:40:24] * (200)
        	Type: static univ
        192.0.2.1/32         blackhole [null4 2022-09-24 18:40:24] * (200)
        	Type: static univ
        66.248.233.0/25      unicast [direct1 2022-09-24 21:08:05] * (240)
        	dev wg1
        	Type: device univ
                             unreachable [static4 2022-09-24 18:40:24] (200)
        	Type: static univ
        '''


        stdin, stdout, stderr = ssh.exec_command('sudo birdc show route all')
        result = ''
        # data = dict()
        data = {}
        json_arr = []
        via = ''
        device = ''
        type = ''
        next_hop = ''
        BGP_origin = ''
        BGP_as_path = ''
        BGP_next_hop = ''
        BGP_local_pref = ''
        BGP_community = ''

        # props = {}
        field_map = {
            'preference': 'preference',
            'bgp.origin:': 'bgp_origin',
            'bgp.as_path': 'bgp_as_path',
            'bgp.next_hop': 'bgp_next_hop',
            'bgp.local_pref': 'bgp_local_pref',
            'bgp.community': 'bgp_community',
            }
        # lineiterator = iter(stdout)
        pattern = re.compile(r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})')
        SUMMARY_UNWANTED_INFO = ["bird", "table" ]

        for line in stdout:
            if line.strip('\n').split(' ')[0].lower() not in SUMMARY_UNWANTED_INFO:
                matcher = re.search(r'[0-9]+(?:\.[0-9]+){3}',line)
                if matcher != None:
                    pattern_ip = pattern.search(line.strip('\n').rsplit()[0].lower())
                    # pattern_ip = re.findall(r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})',line)[0]
                    print (">>>>>>>>LINE>>>>>>" + line)



                    if pattern_ip:
                        if "unicast" in line.lower():
                            route_type = "unicast"
                        elif "unreachable" in line.lower():
                            route_type = "unreachable"
                        elif "blackhole" in line.lower():
                            route_type = "blackhole"

                        if "default4" in line.lower():
                            table = "default4"
                        if "direct4" in line.lower():
                            table = "direct4"
                        if "static4" in line.lower():
                            table = "static4"
                        if "direct1" in line.lower():
                            table = "direct1"
                        if "null4" in line.lower():
                            table = "null4"


                        line = next(stdout)

                        if 'via' in line:
                            device = line.strip("\n").split(" ")[3]
                            via = line.strip("\n").split(" ")[1]

                            line = next(stdout)
                            line = next(stdout)
                            if 'BGP.origin:' in line:
                                BGP_origin = line.strip("\n").split(" ")[1]
                            line = next(stdout)
                            if 'BGP.as_path:' in line:
                                BGP_as_path = line.strip("\n").split(" ")[1:9]
                            line = next(stdout)
                            if 'BGP.next_hop:' in line:
                                BGP_next_hop = line.strip("\n").split(" ")[1]
                            line = next(stdout)
                            if 'BGP.local_pref:' in line:
                                BGP_local_pref = line.strip("\n").split(" ")[1]
                            line = next(stdout)
                            if 'BGP.community:' in line:
                                BGP_community = line.strip("\n").split(" ")[1:12]


                        elif 'dev' in line:
                            device = line.strip("\n").split(" ")[1]
                            via = ''
                            type = ''
                            BGP_origin  = ''
                            BGP_as_path = ''
                            BGP_next_hop = ''
                            BGP_local_pref = ''
                            BGP_community = ''
                        # if line.lower() in field_map.keys():
                        #     result[field_map[field.lower()]] = value



                        result = {
                        'peer' : pattern_ip.group(),
                        'route_type' : route_type,
                        'via' : via,
                        'device' : device,
                        'table' : table,
                        'type' : type,
                        'BGP_orgin' : BGP_origin,
                        'BGP_as_path' : BGP_as_path,
                        'BGP_next_hop' : BGP_next_hop,
                        'BGP_local_pref' : BGP_local_pref,
                        'BGP_community:' : BGP_community,
                         }

                        json_arr.append(result)
                    print(json_arr)
                # match = re.search(r'[0-9]+(?:\.[0-9]+){3}',line)
                # # if match != None:
                # if line.strip().split(' ')[0].lower() != match:
                #     # result = {'prefix': line.strip('\n').rsplit()[0].lower()}
                #     result = {'prefix': line.strip('\n').rsplit()[0].lower()}

            # print(data)
        return jsonify(json_arr)






def _parse_route_stats(result_dict, key_name, value):
    if value.strip() == "---":
        return
    result_dict[key_name] = int(value)


from urllib.parse import unquote
def _get_query():
    q = unquote(request.args.get('q', '').strip())
    return q

@app.route('/get_peer_detail/' , methods=['GET'])
def get_peer_detail(*args, **kwargs):

    '''http://66.248.232.167:5000/get_peer_detail/?peer=AS64555v4'''
    """Parse the detailed peer information from BIRD, like:
    1006-  Description:    Peering AS8954 - InTouch
      Preference:     100
      Input filter:   ACCEPT
      Output filter:  ACCEPT
      Routes:         24 imported, 23 exported, 0 preferred
      Route change stats:     received   rejected   filtered    ignored   accepted
        Import updates:             50          3          19         0          0
        Import withdraws:            0          0        ---          0          0
        Export updates:              0          0          0        ---          0
        Export withdraws:            0        ---        ---        ---          0
        BGP state:          Established
          Session:          external route-server AS4
          Neighbor AS:      8954
          Neighbor ID:      85.184.4.5
          Neighbor address: 2001:7f8:1::a500:8954:1
          Source address:   2001:7f8:1::a519:7754:1
          Neighbor caps:    refresh AS4
          Route limit:      9/1000
          Hold timer:       112/180
          Keepalive timer:  16/60
    peer_detail_raw must be an array, where each element is a line of BIRD output.
    Returns a dict with the fields, if the peering is up:
        routes_imported, routes_exported, router_id
        and all combinations of:
        [import,export]_[updates,withdraws]_[received,rejected,filtered,ignored,accepted]
        wfor which the value above is not "---"
    """
    expression = ''



    expression = _get_query()
    print (expression)

    #
    # if not expression:
    #     abort(400)


    peer = request.args.get('peer')
    print (peer)
    stdin, stdout, stderr = ssh.exec_command(' sudo birdc s p a ' + peer)
    result = {}

    route_change_fields = [
        "import updates",
        "import withdraws",
        "export updates",
        "export withdraws"
        ]
    field_map = {
        'af announced': 'af_announced',
        'bgp Next hop': 'bgp_next_hop',
        'import limit': 'import_limit',
        'table': 'table',
        'state': 'state',
        'preference': 'preference',
        'keepalive timer': 'keepalive_timer',
        'bgp state': 'bgp_state',
        'description': 'description',
        'neighbor id': 'router_id',
        'neighbor address': 'address',
        'neighbor as': 'asn_neighbor',
        'local as': 'asn_local',
        'source address': 'source',
        'hold timer': 'hold_timer',
        'input filter': 'input_filter',
        'output filter': 'output_filter',
        'source adress': 'source_address',
        'session': "session",
        }
    lineiterator = iter(stdout)

    for line in lineiterator:
        line = line.strip()
        try:
            (field, value) = line.split(":", 1)
        except ValueError:
            # skip lines "Channel ipv4/Channel ipv6"
            continue
        value = value.strip()
        if field.lower() in field_map.keys():
            result[field_map[field.lower()]] = value

        if field.lower() == "routes":
            # routes_field_re = re.compile(r'(\d+) imported,.* (\d+) exported, (\d+) preferred')
            routes_field_re = re.compile(r'(\d+) imported, (\d+) filtered, (\d+) exported, (\d+) preferred')
            routes = routes_field_re.findall(value)[0]
            result['routes_imported'] = int(routes[0])
            result['routes_filtered'] = int(routes[1])
            result['routes_exported'] = int(routes[2])
            result['routes_preferred'] = int(routes[3])


        if field.lower() in route_change_fields:
            (received, rejected, filtered, ignored, accepted) = value.split()
            key_name_base = field.lower().replace(' ', '_')
            _parse_route_stats(
                result, key_name_base + '_received', received)
            _parse_route_stats(
                result, key_name_base + '_rejected', rejected)
            _parse_route_stats(
                result, key_name_base + '_filtered', filtered)
            _parse_route_stats(
                result, key_name_base + '_ignored', ignored)
            _parse_route_stats(
                result, key_name_base + '_accepted', accepted)

    print(result)
    return (result)



















@app.route('/get_peers_all/' , methods=['GET'])
def get_peers_all(*args, **kwargs):
        '''GET PEER INFO'''

        stdin, stdout, stderr = ssh.exec_command('sudo birdc show protocols')

        # data = {}
        json_array = []
        status = str()
        for line in stdout:
            SUMMARY_UNWANTED_PROTOS = ["bird", "name", "static4", "default4", "default6", "device1", "direct1", "kernel1" , "kernel2", "null4" , "null6"]
            if line.strip('\n').split(' ')[0].lower() not in SUMMARY_UNWANTED_PROTOS:
                # props = dict()
                peer =  line.strip('\n').split('  ')[0].lower()
                asn =  line.split('  ')[0].strip('AS').strip()[:-2]
                socket = ''
                # computed date  feeding format
                DateResponse = datetime.strptime(re.search(r'\d{4}-\d{2}-\d{2}', line).group(), '%Y-%m-%d').date()
                print(DateResponse)
                date =  str(DateResponse)

                TimeResponse = datetime.strptime(re.search(r'\d{2}:\d{2}:\d{2}', line).group(), '%H:%M:%S').time()
                print(TimeResponse)
                time =  str(TimeResponse)

                if "closed" in line.lower():
                    state =  "closed"
                elif "start" in line.lower():
                    state =  "start"
                elif "down" in line.lower():
                    state =  "down"
                elif "up" in line.lower():
                    state =  line.strip('\n').split('   ')[4].lower().strip(' ')

                    status = None
                if "idle" in line.lower():
                    status =  "idle"
                elif "connect" in line.lower():
                    status =  "connect"
                elif "active" in line.lower():
                    status = "active"
                elif "open sent" in line.lower():
                    status =  "open sent"
                elif "open confirm" in line.lower():
                    status =  "open confirm"
                elif "established" in line.lower():
                    status =  "established"

                if "Socket: Connection closed" in line:
                    socket = "Socket: Connection closed"
                elif "Socket: No route to host" in line:
                    socket = "Socket: No route to host"
                    # props["established"] =  ' '.join(line[5:1]) if len(line) > 5 else ""
                result = {
                'socket' : socket,
                'state' : state,
                'status' : status,
                'peer' : peer,
                'asn' : asn,
                'time' : time,
                'date' : date,

                }
                json_array.append(result)
        # data.append(props)
        # print(data)
        print(json_array)

        #
        return jsonify(json_array)
        # return (jsonify(json.loads(bson_json_util.dumps(data)) ))














### GOOD ####
@app.route('/get_protocol_list/' , methods=['GET'])
def get_protocol_list(*args, **kwargs):
        '''GET ROUTES'''
        stdin, stdout, stderr = ssh.exec_command('sudo birdc show protocols')
        SUMMARY_UNWANTED_PROTOS = ["bird", "name", "static4", "default4", "default6", "device1", "direct1", "kernel1" , "kernel2", "null4" , "null6"]

        data = []
        props = {}
        for line in stdout:
            if line.strip('\n').split(' ')[0].lower() not in SUMMARY_UNWANTED_PROTOS:

                props = line.rstrip().split(' ')[0].lower()
                data.append(props)
        print (bson_json_util.dumps(data))
        return jsonify((data))




##################################
#############  KEEP  #############
##################################
# @app.route('/show_protocol/' , methods=['GET'])
# def show_protocol(*args, **kwargs):
#         '''show protocol'''
#         stdin, stdout, stderr = ssh.exec_command('sudo birdc show protocols')
#         protocol_dict = {}
#
#         for line in stdout:
#             data = line.split(' ')[0].lower()
#             for r in (r for r in line.split("\n") if r):
#                 fields = (
#                     re.sub(r"(\n\r)", "", field).strip(" ") for field in r.split("|")
#                 )
#                 print (bson_json_util.dumps(fields))
#                 protocol_dict = fields
#         return (jsonify(bson_json_util.dumps(protocol_dict)) )
#         print (data)
#         # return (jsonify(fields) )






@app.route('/get_bird_status/' , methods=['GET'])
def get_bird_status(*args, **kwargs):
    """
    Get the status of the BIRD instance. Returns a dict with keys:
    version
    router_id
    up_down
    last_reconfig
    """
    api_key_hash = request.headers.get("X-Api-Key")

    stdin, stdout, stderr = ssh.exec_command('sudo birdc show status')
    raw_str = (stdout.readline(), "utf-8")
    print (f"raw bird results:\n{raw_str}")
    status_dict = {}

    for line in stdout:
        data = line.split(' ')[0].lower()
        if "bird" in data:
            parsed = line.strip('\n').split(' ')[1].lower()
            status_dict['version_full'] = parsed
            print('BIRD VERSION Full PARSED  :', parsed)

        if "bird" in data:
            parsed = line.strip('\n').split(' ')[1].lower()
            verlist_string = re.findall(r"\d+", parsed) # Extract numbers from string as list of numbers
            # Convert last 2 numbers in list to decimals
            verlist_string_dec = [
                verlist_string[0],
                verlist_string[1],
                verlist_string[2],
            ]

            status_dict['version'] =  verlist_string_dec
            print('BIRD VERSION PARSED  :', verlist_string_dec[0])

        if "router" in data:
            parsed = line.strip('\n').split(' ')[3].lower()
            status_dict['router_id'] = parsed
            print('Router number PARSED  :', parsed)

        if "hostname" in data:
            parsed = line.strip('\n').split(' ')[2].lower()
            status_dict['hostname'] = parsed
            print('Hostname PARSED  :', parsed)

        if "daemon" in data:
            parsed = line.split(' ')[2].lower()
            status_dict['up_down'] = parsed
            print('UP/DOWN PARSED  :', parsed)

        if "last" in data:
            # parsed =   line.strip().split(' ', 4)[-2].lower() ##### KEEP IF WE JUST WAN TO USE DATE NOTATION
            parsed =   line.strip().split(' ', 3)[-1].lower()
            mod_parse = datetime.strptime(parsed, '%Y-%m-%d %H:%M:%S')
            status_dict['last_reconfig'] = mod_parse
            print('Last Reconfig :', mod_parse)



    # clean_input_re = re.compile(r'\W+')
    # routes_field_re = re.compile(r'(\d+) imported,.* (\d+) exported')
    return jsonify(status_dict)


@app.route('/get_bird_memory/' , methods=['GET'])
def get_bird_memory(*args, **kwargs):
        stdin, stdout, stderr = ssh.exec_command('sudo birdc show memory')
        bgp_memory_fields = {
            'Routing tables': 'Routing_tables',
            'Route attributes': 'Route_attributes',
            'Protocols': 'Protocols',
            'Total': 'Total'
            }
        errors = [] #Todo add error capture and send response to return.
        data = []
        result = {}
        for line in stdout:
            try:
                (field, value) = line.split(":", 1)
                if field in bgp_memory_fields.keys():
                    result[bgp_memory_fields[field]] = value.strip(' ').strip('\n')
                data.append(result)
            except ValueError:
                continue
        print(result)
        return (result)








@app.route('/get_asn_irr_prefix/' , methods=['GET'])
def get_asn_irr_prefix(*args, **kwargs):
        ASN = request.args.get('ASN')

        stdin, stdout, stderr = ssh.exec_command('sudo bgpq3 -4 -J -l prefixes ' + ASN )
        data = []
        result = {}
        SUMMARY_UNWANTED_BGPq = ["policy-options", "replace:", "prefix-list prefixes {", "}" ]

        for line in stdout:
            if line.strip('\n').split(' ')[0].lower() not in SUMMARY_UNWANTED_BGPq:
                try:
                    print(line)
                    data.append(line.rstrip().strip(';').strip(" "))
                except ValueError:
                    continue
        print(data)
        return (data)






@app.route('/add_ASN/' , methods=['GET'])
def add_ASN( *args, **kwargs):
        '''ADD NEW ASN'''
        ADD_ASN = request.args.get('ASN')
        ADD_IP = request.args.get('IP')
        ADD_NAME = request.args.get('NAME')

        build_file_data = {}
        build_file_data['name'] = ADD_NAME
        build_file_data['peer_ip_address'] = ADD_IP
        build_file_data['peer_asn_number'] = ADD_ASN

# Use build_file_data to create bird config
        build_output = build_file(build_file_data)
        time =   epoc_time(datetime.now())
## TEST TO CONVERT EPOC TO day
        datetime_obj = datetime.fromtimestamp(time / 1000)
        datetime_str = datetime_obj.strftime("%m" "%d" "%Y")
        print (datetime_str )

        filter = { "asn": ADD_ASN}
        new_values = { "$set": { 'updated' : time ,  "ip":  ADD_IP } }
        Net44_db['bgp'].update_one(filter, new_values, upsert=True)

        cursor = Net44_db['bgp'].find({ "asn": ADD_ASN })

#convert cursor to the list of dictionaries
        list_cursor = list(cursor)
        print('>>>>>>>>>>>>LIST CURSOR :' , list_cursor)
#converting to JSON
        json_data = (bson_json_util.dumps(list_cursor, indent = 2))
        # mp = {}
        # for key, value in json_data.iteritems():
        #         if "_id" in key:
        #                 mp["id"] = str(value["$oid"])
        #         else:
        #                 mp[trimStr(key)] = parseList(value)
        completed_data = json.loads(json_data)
        print(completed_data)
        return (json.loads(bson_json_util.dumps(list_cursor)) )





@app.route('/delete_ASN/' , methods=['GET'])
def delete_ASN(*args, **kwargs):
        '''DEL ASN'''
        DELETE_ASN = request.args.get('ASN')
        DELETE_IP = request.args.get('IP')
        DELETNAME = request.args.get('NAME')

        filter = { "asn": DELETE_ASN }
        Net44_db['bgp'].delete_one(filter)

        ssh.exec_command('sudo rm /etc/bird/AS' + DELETE_ASN+'.conf')
        ssh.exec_command('sudo birdc conf')
        return Response(json.dumps('Delete Completed'), mimetype='application/json')





@app.route('/disable_ASN/' , methods=['GET'])
def disable_ASN(*args, **kwargs):
        '''DEL ASN'''
        DISABLE_ASN = request.args.get('ASN')

        stdin, stdout, stderr  =  ssh.exec_command('sudo birdc disable ' + DISABLE_ASN)
        print('log exec_send_printing: >>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>',  stdout)

        return Response(json.dumps('Disable Completed'), mimetype='application/json')





@app.route('/enable_ASN/' , methods=['GET'])
def enable_ASN(*args, **kwargs):
        '''ENABLE ASN'''
        ENABLE_ASN = request.args.get('ASN')

        stdin, stdout, stderr  =  ssh.exec_command('sudo birdc enable ' + ENABLE_ASN)
        raw_str = (stdout.readline(), "utf-8")
        print (f"raw bird results:\n{raw_str}")

        return Response(json.dumps('Enable Completed'), mimetype='application/json')





@app.route('/my_ip/' , methods=['GET'])
def my_ip(*args, **kwargs):
    '''my ip'''
    '''Returns current IP'''
    resolved = Helpers._resolve_remote_addr()
    return Response(json.dumps(resolved), mimetype='application/json')




@app.route("/cpu_stats", methods=['get'])
def stat():
    global cache_result

    cache_result = json.dumps(
    {
    'host': os.uname()[1],
    'cpu': System_Specs.cpu(),
    'gpu': System_Specs.gpu()
    }, indent=2, ensure_ascii=False)
    return (json.loads(cache_result))




@app.route("/api/v1/user", methods=['get'])
def list_users():
  return "user examples2"


@app.route('/arp_ip/', methods=['GET'])
def arp_ip(*args, **kwargs):
        #################################################
        ##TODO ADD SANITY ANS SANITISE EVERYTHING!!!@!!!!
        #################################################
        SUMMARY_UNWANTED = ['Starting arp-scan' ]
        data = []
        stdin, stdout, stderr = ssh.exec_command('sudo arp-scan -l')
        for line in stdout:
            if line.strip('\n').split(' ')[0].lower() not in SUMMARY_UNWANTED:
                try:
                    (field, value) = line.split("\t", 1)

                    print('>>>>>>>>>>>>>>>>', field + ' ' + value)
                    result = {
                    'ip': field,
                    'mac': value.split('\t')[0],
                    'device': value.split('\t')[1].strip('\n')
                    }
                    # data.append(line.rstrip().strip(';').strip(" "))
                    data.append(result)
                except ValueError:
                    continue
        print(data)
        return (data)





@app.route('/traceroute_ip/', methods=['GET'])
def traceroute_ip():
    try:
        # result = icmplib.traceroute('' + request.form['ip'] + '', first_hop=1, max_hops=30, count=1, fast=True)
        ip = request.args.get('ip')
                #################################################
                ##TODO ADD SANITY ANS SANITISE EVERYTHING!!!@!!!!
                #################################################
        result = icmplib.traceroute('' + ip + '', first_hop=1, max_hops=30, count=3, fast=True)
        returnjson = []
        last_distance = 0
        for hop in result:
            if last_distance + 1 != hop.distance:
                returnjson.append({"hop": "*", "ip": "*", "avg_rtt": "", "min_rtt": "", "max_rtt": ""})
            returnjson.append({"hop": hop.distance, "ip": hop.address, "avg_rtt": hop.avg_rtt, "min_rtt": hop.min_rtt,
                               "max_rtt": hop.max_rtt})
            last_distance = hop.distance
        return jsonify(returnjson)
    except Exception:
        return "Error"


@app.route('/ping_ip/', methods=['GET'])
def ping_ip():
    try:
        print('before ping request')
        ip = request.args.get('ip')
        #################################################
        ##TODO ADD SANITY AND SANITISE EVERYTHING!!!@!!!!
        #################################################
        # result = icmplib.ping('' + request.form['ip'] + '', count=1, privileged=True, source=None)
        result = icmplib.ping('' + ip + '', count=2, privileged=True, source=None)
        print(result)

        returnjson = {
            "address": result.address,
            "is_alive": result.is_alive,
            "min_rtt": result.min_rtt,
            "avg_rtt": result.avg_rtt,
            "max_rtt": result.max_rtt,
            "package_sent": result.packets_sent,
            "package_received": result.packets_received,
            "package_loss": result.packet_loss,
            "jitter": result.jitter,
            "randomMAC_test_remove": Helpers.randomMAC()
        }
        print(returnjson)
        if returnjson['package_loss'] == 1.0:
            returnjson['package_loss'] = returnjson['package_sent']


        return jsonify(returnjson)
    except Exception:
        return "Error"




@app.route('/get_proxmox_token/', methods=['GET'])
def get_token():
    result = Proxmox._get_proxmox_token(request)
    return result







@app.route('/get_proxmox_vm_file/', methods=['GET'])
def get_vm_agent_file():
    instanceID = request.args.get('vmID')
    host_node = request.args.get('host_node')
    result = Proxmox._relay('get', 'nodes/%s/qemu/%s/agent/file-read/?file=/etc/hosts' % (host_node, instanceID), None)
    return result


@app.route('/get_proxmox_vm_guest_os_info/', methods=['GET'])
def get_vm_guest_os_info():
    instanceID = request.args.get('vmID')
    host_node = request.args.get('host_node')
    result = Proxmox._relay('get', 'nodes/{0}/qemu/{1}/agent/get-osinfo'.format(host_node, instanceID), None)
    return result



@app.route('/get_proxmox_vm_info/', methods=['GET'])
def get_vm_info():
    instanceID = request.args.get('vmID')
    host_node = request.args.get('host_node')
    result = Proxmox._relay('get', 'nodes/{0}/qemu/{1}/agent/info'.format(host_node, instanceID), None)
    return result




@app.route('/get_proxmox_vm_agent_info/', methods=['GET'])
def get_vm_agent_info():
    instanceID = request.args.get('vmID')
    host_node = request.args.get('host_node')
    result = Proxmox._relay('get', 'nodes/{0}/qemu/{1}/agent/info'.format(host_node, instanceID), None)
    return result




@app.route('/get_proxmox_vm_interface/', methods=['GET'])
def get_vm_interface():
    instanceID = request.args.get('vmID')
    host_node = request.args.get('host_node')
    result = Proxmox._relay('get', 'nodes/{0}/qemu/{1}/agent/network-get-interfaces'.format(host_node, instanceID), None)
    return result




@app.route('/get_proxmox_all_vm_detail/', methods=['GET'])
def get_all_vm_node_detail():
    category = 'qemu'
    host_node = request.args.get('host_node')
    result = Proxmox._relay('get', 'nodes/{0}/{1}'.format(host_node, category), None)
    return result


@app.route('/get_proxmox_hypervisor_node/', methods=['GET'])
def get_nodes():
    result = Proxmox._relay('get', 'nodes', None)
    return result


@app.route('/get_promox_vm_detail/', methods=['GET'])
def get_vm_detail_config():
    category = 'qemu'
    instanceID = request.args.get('vmID')
    host_node = request.args.get('host_node')
    result = Proxmox._relay('get', 'nodes/{0}/{1}/{2}/config'.format(host_node, category, instanceID), None)
    return result



@app.route('/get_proxmox_vm_exec/', methods=['GET'])
def get_vm_agent_exec():
    instanceID = request.args.get('vmID')
    host_node = request.args.get('host_node')
    result = Proxmox._relay('post', 'nodes/{0}/qemu/{1}/agent/exec/'.format(host_node, instanceID), 'ip addr add 19.0.22.223 dev ens18' )
    return result



@app.route('/create_promox_vm/', methods=['GET'])
def create_vm():
    category = 'qemu'
    instanceID = request.args.get('vmID')
    host_node = request.args.get('host_node')
    data = {
        'vmid' : instanceID,
        'cores' : 1,
        'sockets' : 1,
        'cpulimit': 1,
        'memory' : 1024,
        'net0' : 'virtio,bridge=vmbr1,tag=3',
        'cdrom' : 'local:iso/debian-10.5.0-amd64-netinst.iso',
        'scsi0' : 'local-lvm:12',
        "scsihw": "virtio-scsi-pci",
        'name' : 'test',
        #'onboot' : 1,
        }
    result = Proxmox._relay('post', 'nodes/{0}/{1}'.format(host_node, category), data)
    return result



@app.route('/delete_promox_vm/', methods=['GET'])
def delete_vm():
    category = 'qemu'
    instanceID = request.args.get('vmID')
    host_node = request.args.get('host_node')
    result = Proxmox._relay('delete', 'nodes/{0}/{1}/{2}'.format(host_node, category, instanceID), None)
    return result






@app.route('/get_proxmox_vm_ping/', methods=['GET'])
def get_vm_agent_ping():
    #result = Proxmox._get_proxmox_vm_ping(request)
    instanceID = request.args.get('vmID')
    host_node = request.args.get('host_node')
    result = Proxmox._relay('get', 'nodes/%s/qemu/%s/agent/ping' % (host_node, instanceID), None)
    return result



# import schedule
# import time
#
# async def is_alive(address):
#     host = await icmplib.async_ping(address, count=4, interval=0.2)
#     if host.is_alive:
#         print(f'{host.address} is up!')
#         print(host.packets_received)
#         print(host.packet_loss)
#     else:
#         print(f'{host.address} is down!')
#         # Do something here
#
# def check_run():
#     return asyncio.run(is_alive('google.com'))
#
# schedule.every(10).seconds.do(check_run)
# while True:
#     schedule.run_pending()
#     time.sleep(1)


def  epoc_time(obj):
    """Default JSON serializer."""
    import calendar

    if isinstance(obj, datetime):
        if obj.utcoffset() is not None:
            obj = obj - obj.utcoffset()
        millis = int(
            calendar.timegm(obj.timetuple()) * 1000 +
            obj.microsecond / 1000
        )
        return millis
    raise TypeError('Not sure how to serialize %s' % (obj,))


def exec_send_print(*args, **kwargs):
    stdin, stdout, stderr = ssh.exec_command(*args)
    print('log exec_send_printing: >>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>',  stdout)
    return stdout


def build_file(build_data, *args, **kwargs):
    '''Build Bird file using jinja templating'''
    with open("templates/bgp.j2") as local_template_file:
        local_template = local_template_file.read()

    local = ""
    # for build in build_file:
    local += Template(local_template).render(
        name=build_data['name'],
        peer_ip_address = build_data['peer_ip_address'],
        peer_asn_number = build_data['peer_asn_number']
        )

    with open("HOLD/AS" + build_data["peer_asn_number"]+ '.conf', "w") as completed_file:
        completed_file.write(local)

    sftp = ssh.open_sftp()

    local_path = BGP_working_hold_DIR
    remote_path = '/etc/bird/'
    file_remote = remote_path + "AS" + build_data["peer_asn_number"] + ".conf"
    file_local = local_path + "AS" + build_data["peer_asn_number"] + ".conf"

    print(file_local + '>>>>>>>>>>>>>>>>>>>>>>>>>>>>' + file_remote)
    sftp.put(file_local, file_remote)
    sftp.close()
    stdin, stdout, stderr = ssh.exec_command('sudo birdc conf')
    print('OUTPUT: %s'  '>>>>>' 'ERROR: %s' , stdout.read() + stderr.read())



    print ('>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>.sent sudo birdc:' ,  stdout)
    return local









def init_system():
    # Set Default INI File
    if not os.path.isfile("system.ini"):
        conf_file = open("system.ini", "w+")

    config = configparser.ConfigParser(strict=False)
    config.read(system_conf)

    print('Starting server in PID :', os.getpid())


    if 'app_ip' not in config['Local_Server']:
        config['Local_Server']['app_ip'] = '0.0.0.0'
    if 'app_port' not in config['Local_Server']:
        config['Local_Server']['app_port'] = '10086'

    if 'userName' not in config['Account']:
        config['Account']['userName'] = 'root'

    if 'PassWord' not in config['Account']:
        config['Account']['PassWord'] = ''

    if 'sshPORT' not in config['Account']:
        config['Account']['sshPORT'] = ''

    if 'remote_ip' not in config['Remote_Server']:
        config['Remote_Server']['remote_ip'] = ''


    config.write(open(system_conf, "w"))
    #config.clear()


# main driver function
if __name__ == '__main__':
    init_system()

    config = configparser.ConfigParser(strict=False)
    config.read('system.ini')

    # Global app_ IP
    app_ip = config.get("Local_Server", "app_ip")
    app_port = config.get("Local_Server", "app_port")
    sshPORT = config.get("Account", "sshPORT")
    userName = config.get("Account", "userName")
    PassWord = config.get("Account", "PassWord")

    BGP_working_hold_DIR = config.get("BGP", "BGP_working_hold_DIR")

    MONGO_connection = config.get ("MongoDB", "MONGO_connection")

    remote_ip = config.get("Remote_Server", "remote_ip")
    remote_userName = config.get("Remote_Server", "remote_userName")

    # Create object of SSHClient and connecting to SSH
    ssh = paramiko.SSHClient()
    ssh.load_system_host_keys()

    # Adding new host key to the local
    # HostKeys object(in case of missing)
    # AutoAddPolicy for missing host key to be set before connection setup.
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())

    paramiko.util.log_to_file('/tmp/paramiko.log')
    paramiko.util.load_host_keys(os.path.expanduser('~/.ssh/known_hosts'))

    ssh.connect(remote_ip, port=sshPORT, username=userName,
        password=PassWord, timeout=3)
    #

    DB_client = MongoClient(MONGO_connection)
    Net44_db = DB_client["44netcloud"]


    #config.clear()


    app.run(host=app_ip, debug=True, port=app_port) #, ssl_context=("/etc/letsencrypt/live/portal.bgpvps.co/fullchain.pem", "/etc/letsencrypt/live/portal.bgpvps.com/privkey.pem"))
