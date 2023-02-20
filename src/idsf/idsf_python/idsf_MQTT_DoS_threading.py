import socket
from scapy.all import *
from scapy.all import ls,raw,load_layer
from scapy.contrib.gtp import GTPHeader
from scapy.layers.inet import IP, TCP, UDP
from scapy.layers.tls.record import TLS
from scapy.layers.tls.handshake import TLSServerHello
from scapy.contrib.mqtt import MQTT
from scapy.contrib.mqtt import *

import numpy as np
import pandas as pd
import joblib

import time
import atexit
import signal
import json
import traceback

import pycurl
from io import StringIO,BytesIO 


################################################################
load_layer('http')
load_layer('dns')
load_layer('tls')
load_layer('dhcp')

# config
maxMessageSize = 65535
UDP_IP = "127.0.0.25"
UDP_PORT = 2152

# bind socket
sock = socket.socket(socket.AF_INET, # Internet
                     socket.SOCK_DGRAM,
                     socket.IPPROTO_UDP) # UDP
sock.bind((UDP_IP, UDP_PORT))

print("binding to ip %s port %d" % (UDP_IP, UDP_PORT))

################################################################

#model folder
modelfolder = './mqttset/'

#load feature names
featurenamefile = modelfolder + 'Feature_name.dat'
with open(featurenamefile) as file:
    ftnames = [line.rstrip() for line in file]
file.close()

# load model
modelfile = 'IDSF_model_'
# modeltypes = ['DT','LSVC','SGDC','RBF_SVC_auto10','RBF_SVC_scale1','RBF_SVC_scale10','Neural']
modeltypes = ['DT','LSVC','SGDC','Neural','RF','XGBoost']
modelext = '.joblib'
model_dict = {}
for modeltype in modeltypes:
    filename = modelfolder + modelfile + modeltype + modelext
    model_dict[modeltype] = joblib.load(filename)

################################################################

# handle statistic 

main_stats = {}
main_stats['start_time'] = time.strftime("%d-%m-%Y %H:%M:%S %z")
main_stats['packet_count'] = 0

for modeltype in modeltypes:
    model_stats = { 'TP': 0,
                    'FP': 0,
                    'TN': 0,
                    'FN': 0,
                    'accuracy': 0 ,
                    'specificity': 0,
                    'sensitivity': 0,
                    'precision': 0,
                    'F_score': 0 }
    main_stats[modeltype] = model_stats

report_file = modelfolder + 'report.dat'

# before exit handle thread terminate, socket close, save stat to report file

def signal_handler(*args):
    
    print('Stop processing thread')
    global stop_AI 
    stop_AI = True
    packet_queue.put(None)
    processThread.join()
    print('Process thread exited')
    
    print('Stop capturing') 
    global stop_capture
    stop_capture = True
    # print('Shutdown and close socket')
    # sock.shutdown(socket.SHUT_RD)
    # sock.close()
    sock.sendto(b'\x00',(UDP_IP, UDP_PORT))
    captureThread.join()
    print('Capture thread exited')

    print('Dumping stat:', report_file )
    global main_stats
    main_stats['end_time'] = time.strftime("%d-%m-%Y %H:%M:%S %z")
    main_stats['packet_count'] = pk_count
    for modeltype in modeltypes:
        if main_stats['packet_count'][0] != 0:
            main_stats[modeltype]['accuracy'] = (main_stats[modeltype]['TP'] + main_stats[modeltype]['TN'])/main_stats['packet_count'][0]
        if (main_stats[modeltype]['TN']+main_stats[modeltype]['FP']) != 0:
            main_stats[modeltype]['specificity'] = main_stats[modeltype]['TN']/(main_stats[modeltype]['TN']+main_stats[modeltype]['FP'])
        if (main_stats[modeltype]['TP']+main_stats[modeltype]['FN']) !=0 :
            main_stats[modeltype]['sensitivity'] = main_stats[modeltype]['TP']/(main_stats[modeltype]['TP']+main_stats[modeltype]['FN'])
        if (main_stats[modeltype]['TP']+main_stats[modeltype]['FP']) != 0:
            main_stats[modeltype]['precision'] = main_stats[modeltype]['TP']/(main_stats[modeltype]['TP']+main_stats[modeltype]['FP'])
        if (main_stats[modeltype]['precision']+main_stats[modeltype]['sensitivity']) != 0:
            main_stats[modeltype]['F_score'] = (2*main_stats[modeltype]['precision']*main_stats[modeltype]['sensitivity'])/(main_stats[modeltype]['precision']+main_stats[modeltype]['sensitivity'])
    stat_json_str = json.dumps(main_stats) + '\n\n'
    with open(report_file,"a") as file:
        file.write(stat_json_str)
    print('Dumped stat before exit')

# atexit.register(exit_handler)
# atexit.register(signal_handler)
signal.signal(signal.SIGTERM, signal_handler)
signal.signal(signal.SIGINT, signal_handler)

################################################################

def ip_packet_to_dataframe(pk,feature_name,time_delta,time_rela):
    df = pd.DataFrame(0,index=[0], columns=feature_name)
    df['frame.time_delta'] = time_delta
    df['frame.time_relative'] = time_rela
    df['frame.len'] = pk[IP].len
    if pk.haslayer(TCP):
        df['tcp.srcport'] = pk[TCP].sport
        df['tcp.dstport'] = pk[TCP].dport 
    
    if pk.haslayer(MQTT):
        mqtt_pk = pk[MQTT]
        hdrflags = raw(mqtt_pk)
        df['mqtt.hdrflags'] = hdrflags[0]
        df['mqtt.msgtype'] = mqtt_pk.type
        df['mqtt.dupflag'] = mqtt_pk.DUP
        df['mqtt.qos'] = mqtt_pk.QOS
        df['mqtt.retain'] = mqtt_pk.RETAIN
        df['mqtt.len'] = 0 if mqtt_pk.len == None else mqtt_pk.len

        if mqtt_pk.len != 0 and mqtt_pk.haslayer(MQTTConnect):
            mqtt_con_pk = mqtt_pk[MQTTConnect]
            df['mqtt.proto_len'] = mqtt_con_pk.length
            if mqtt_con_pk.protoname != '':
                df['mqtt.protoname'] = 1 if mqtt_con_pk.protoname == "MQTT" else 0
            else:
                df['mqtt.protoname'] = 0
            df['mqtt.ver'] = mqtt_con_pk.protolevel
            
            df['mqtt.conflag.uname'] = mqtt_con_pk.usernameflag
            if mqtt_con_pk.usernameflag:
                df['mqtt.username_len'] = mqtt_con_pk.userlen
            
            df['mqtt.conflag.passwd'] = mqtt_con_pk.passwordflag
            if mqtt_con_pk.passwordflag:
                df['mqtt.passwd_len'] = mqtt_con_pk.passlen

            df['mqtt.conflag.willflag'] = mqtt_con_pk.willflag
            if mqtt_con_pk.willflag:
                df['mqtt.willtopic_len'] = mqtt_con_pk.wtoplen
                df['mqtt.willmsg_len'] = mqtt_con_pk.wmsglen

            df['mqtt.conflag.retain'] = mqtt_con_pk.willretainflag
            df['mqtt.conflag.qos'] = mqtt_con_pk.willQOSflag
            
            df['mqtt.conflag.cleansess'] = mqtt_con_pk.cleansess
            df['mqtt.conflag.reserved'] = mqtt_con_pk.reserved
            df['mqtt.kalive'] = mqtt_con_pk.klive
            df['mqtt.clientid_len'] = len(mqtt_con_pk.clientId)      
            
            conflags = mqtt_con_pk.cleansess*2 + mqtt_con_pk.willflag*4 + mqtt_con_pk.willQOSflag*8 \
                        + mqtt_con_pk.willretainflag*32 + mqtt_con_pk.passwordflag*64 + mqtt_con_pk.usernameflag*128
            df['mqtt.conflags'] = conflags

        if pk.haslayer(MQTTConnack):
            df['mqtt.conack.flags'] = pk[MQTTConnack].sessPresentFlag
            df['mqtt.conack.val'] = pk[MQTTConnack].retcode
            df['mqtt.conack.flags.reserved'] = 1 if pk[MQTTConnack].retcode >= 6 else 0
            df['mqtt.conack.flags.sp'] = pk[MQTTConnack].sessPresentFlag % 2

        if pk.haslayer(MQTTPublish):
            df['mqtt.topic_len'] = pk[MQTTPublish].length
        
        if pk.haslayer(MQTTSubscribe):
            if pk.haslayer(MQTTTopic):
                df['mqtt.sub.qos'] = pk[MQTTTopic].QOS
                df['mqtt.topic_len'] = pk[MQTTTopic].length

        if pk.haslayer(MQTTSuback):
            df['mqtt.suback.qos'] = pk[MQTTSuback].retcode

    # print(df)
    return df

################################################################

def ip_packet_to_mqttset_dataframe(pk,feature_name,time_delta,time_rela):
    df = pd.DataFrame(0,index=[0], columns=feature_name)
    df['tcp.time_delta'] = time_delta
    if pk.haslayer(TCP):
        df['tcp.flags'] = int(pk[TCP].flags)    
        df['tcp.len'] = pk[IP].len
    
    if pk.haslayer(MQTT):
        mqtt_pk = pk[MQTT]
        hdrflags = raw(mqtt_pk)
        df['mqtt.dupflag'] = mqtt_pk.DUP
        df['mqtt.hdrflags'] = hdrflags[0]
        df['mqtt.len'] = 0 if mqtt_pk.len == None else mqtt_pk.len
        df['mqtt.msgtype'] = mqtt_pk.type
        df['mqtt.qos'] = mqtt_pk.QOS
        df['mqtt.retain'] = mqtt_pk.RETAIN
        
        if mqtt_pk.len != 0 and mqtt_pk.haslayer(MQTTConnect):
            mqtt_con_pk = mqtt_pk[MQTTConnect]

            df['mqtt.conflag.cleansess'] = mqtt_con_pk.cleansess
            df['mqtt.conflag.passwd'] = mqtt_con_pk.passwordflag
            df['mqtt.conflag.qos'] = mqtt_con_pk.willQOSflag
            df['mqtt.conflag.reserved'] = mqtt_con_pk.reserved
            df['mqtt.conflag.retain'] = mqtt_con_pk.willretainflag
            df['mqtt.conflag.uname'] = mqtt_con_pk.usernameflag
            df['mqtt.conflag.willflag'] = mqtt_con_pk.willflag
            df['mqtt.kalive'] = mqtt_con_pk.klive
            conflags = mqtt_con_pk.cleansess*2 + mqtt_con_pk.willflag*4 + mqtt_con_pk.willQOSflag*8 \
                        + mqtt_con_pk.willretainflag*32 + mqtt_con_pk.passwordflag*64 + mqtt_con_pk.usernameflag*128
            df['mqtt.conflags'] = conflags
            df['mqtt.proto_len'] = mqtt_con_pk.length
            if mqtt_con_pk.protoname != '':
                df['mqtt.protoname'] = 1 if mqtt_con_pk.protoname == "MQTT" else 0
            else:
                df['mqtt.protoname'] = 0
            df['mqtt.ver'] = mqtt_con_pk.protolevel
            if mqtt_con_pk.willflag:
                df['mqtt.willtopic_len'] = mqtt_con_pk.wtoplen
                df['mqtt.willmsg_len'] = mqtt_con_pk.wmsglen

            # if mqtt_con_pk.usernameflag:
            #     df['mqtt.username_len'] = mqtt_con_pk.userlen
            # if mqtt_con_pk.passwordflag:
            #     df['mqtt.passwd_len'] = mqtt_con_pk.passlen
            # df['mqtt.clientid_len'] = len(mqtt_con_pk.clientId)      
            
        if pk.haslayer(MQTTConnack):
            df['mqtt.conack.flags'] = pk[MQTTConnack].sessPresentFlag
            df['mqtt.conack.flags.reserved'] = 1 if pk[MQTTConnack].retcode >= 6 else 0
            df['mqtt.conack.flags.sp'] = pk[MQTTConnack].sessPresentFlag % 2
            df['mqtt.conack.val'] = pk[MQTTConnack].retcode

        # if pk.haslayer(MQTTPublish):
        #     df['mqtt.topic_len'] = pk[MQTTPublish].length
        
        if pk.haslayer(MQTTSubscribe):
            if pk.haslayer(MQTTTopic):
                df['mqtt.sub.qos'] = pk[MQTTTopic].QOS
                df['mqtt.topic_len'] = pk[MQTTTopic].length

        if pk.haslayer(MQTTSuback):
            df['mqtt.suback.qos'] = pk[MQTTSuback].retcode

    # print(df)
    return df

################################################################

def AImodel_Detect_Abnormal(df,label,model_dict):
    global main_stats
    for modeltype in model_dict:
        pred = model_dict[modeltype].predict(df)
        if label != None:
            if pred[0] != 0 and pred[0] != 1:
                print('wrong output')
            if pred[0] != 0:
                if pred[0] == label:
                    main_stats[modeltype]['TP'] += 1
                else:
                    main_stats[modeltype]['FP'] += 1
            else:
                if pred[0] == label:
                    main_stats[modeltype]['TN'] += 1
                else:
                    main_stats[modeltype]['FN'] += 1
    return pred[0]

################################################################

def idsf_nsmf_send_session_release(ss_context_id):
    buffer = BytesIO()
    crl = pycurl.Curl()
    release_url = 'http://127.0.0.4:7777/nsmf-pdusession/v1/sm-contexts/'+str(ss_context_id)+'/release'
    release_url = bytes(release_url, 'utf-8')
    crl.setopt(pycurl.URL, release_url)
    crl.setopt(pycurl.HTTP_VERSION, pycurl.CURL_HTTP_VERSION_2_PRIOR_KNOWLEDGE)
    crl.setopt(pycurl.HTTPHEADER, ['Content-Type: application/json'])
    crl.setopt(pycurl.POST, 1)
    data = {
                "cause": "REL_DUE_TO_HO",
                "ngApCause": {
                    "group": 0,
                    "value": 0
                },
                "5gMmCauseValue": 0,
                "ueTimeZone": "-08:00+1",
                "vsmfReleaseOnly": False,
                "n2SmInfo": {
                    "contentId": "string"
                },
                "n2SmInfoType": "PDU_RES_SETUP_REQ",
                "ismfReleaseOnly": False
            }
    data_as_json_string = json.dumps(data)
    data_as_file_object = StringIO(data_as_json_string)
    crl.setopt(pycurl.READDATA, data_as_file_object) 
    crl.setopt(pycurl.POSTFIELDSIZE, len(data_as_json_string))
    crl.setopt(pycurl.WRITEDATA, buffer)    
    crl.perform()
    
    status_code = crl.getinfo(pycurl.RESPONSE_CODE)
    body = buffer.getvalue()

    crl.close()
    return status_code

################################################################

server_ip = '10.45.0.2'
legit_ip = '10.45.0.3'
atk_ip = '10.45.0.4'

label = None

start_time = time.time()
# total, atk, normal
pk_count = [0,0,0]
main_stats['packet_count'] = pk_count

################################################################
import threading, queue

stop_capture = False
packet_queue = queue.Queue()

def capture_packet():
    global stop_capture
    while stop_capture == False:
        # r_able, _, _ = select.select([sock],[],[])
        # if r_able:
        data, addr = sock.recvfrom(maxMessageSize)
        packet_queue.put(data)
    sock.close()
    return 0

captureThread = Thread(target=capture_packet)

stop_AI = False

def process_packet():
    global stop_AI
    while stop_AI == False:
        data = packet_queue.get()
        if data == None:
            break

        # extract IP packet
        gtp_packet = GTPHeader(data)
        if gtp_packet.haslayer(MQTT)==0:
            continue
        ss_context_ref = gtp_packet.teid

        # pk count
        pk_count[0] += 1
        if pk_count[0] == 1:
            lastpk_time=time.time()        

        # get duration
        now = time.time()
        pk_relative_time = (now - start_time) % 1000
        pkduration = now - lastpk_time
        lastpk_time = now 

        # get label and count packet.   pk_count= [total, attack, normal]
        ip_packet = gtp_packet[IP]
        label = 1 if ip_packet.src == atk_ip else 0
        if label == 0:
            pk_count[2] += 1
        else:
            pk_count[1] +=1

        # try:
        # df_packet = ip_packet_to_dataframe(ip_packet,ftnames,pkduration,pk_relative_time)
        df_packet = ip_packet_to_mqttset_dataframe(ip_packet,ftnames,pkduration,pk_relative_time)
        res = AImodel_Detect_Abnormal(df_packet,label, model_dict)
        # except Exception as e:
        # if res != label :
        #     ip_packet.show()
        #     print(df_packet.shape)
        #     for col in df_packet.columns:
        #         print(col,' ', df_packet[col])
            # traceback.print_exc()
            # break
        
        if ((pk_count[0] % 1000) ==0):
            strcnt = 'Checkpoint(' + time.strftime("%d-%m-%Y %H:%M:%S %z") + '):'+str(pk_count)+'\n'
            print(strcnt)

    return 0

processThread = Thread(target=process_packet)

processThread.start()
captureThread.start()

################################################################