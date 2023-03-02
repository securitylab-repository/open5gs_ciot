import socket
# from scapy.all import *
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
from datetime import datetime
import atexit
import signal
import json
import traceback

import pycurl
from io import StringIO,BytesIO 

from threading import Thread

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

#dataset folder
modelfolder = './emulation_data/'

dtime_str = datetime.now().strftime('%d-%m-%Y_%H%M')
csvfile = modelfolder + 'emulation_dataset_'+dtime_str+'.csv'

#feature to extract
featurenamefile = modelfolder + 'Feature_name.dat'
with open(featurenamefile) as file:
    ftnames = [line.rstrip() for line in file]
file.close()

################################################################

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

    print('Dumping data:', csvfile )
    dataset_df.to_csv(csvfile,index=False,columns=ftnames)
    print('Dumped data before exit')

# atexit.register(exit_handler)
# atexit.register(signal_handler)
signal.signal(signal.SIGTERM, signal_handler)
signal.signal(signal.SIGINT, signal_handler)

################################################################

def ip_packet_to_dataframe(pk,feature_name,time_delta,time_rela):
    #empty dataframe
    merge_df = pd.DataFrame(columns=feature_name)

    #packet IP, TCP
    df_template = pd.DataFrame(index=[0],columns=feature_name)
    df_template['frame.time_delta'] = time_delta
    df_template['frame.time_relative'] = time_rela
    df_template['ip.len'] = pk[IP].len
    df_template['ip.protocol'] = pk[IP].proto
    df_template['ip.src'] = pk[IP].src
    df_template['ip.dst'] = pk[IP].dst
    
    if pk.haslayer(TCP):
        df_template['tcp.srcport'] = pk[TCP].sport
        df_template['tcp.dstport'] = pk[TCP].dport 
    
    #check MQTT layer
    if pk.haslayer(MQTT) == False:
        merge_df = pd.concat([merge_df,df_template],ignore_index=True)
        return merge_df
    
    mqtt_pk = pk[MQTT]
    while mqtt_pk.haslayer(MQTT):
        mqtt_pk = mqtt_pk[MQTT]
        mqtt_pk = MQTT(mqtt_pk)
        # new row with same IP and TCP feature
        df_row = df_template.copy()
        # MQTT fixed header
        hdrflags = raw(mqtt_pk)
        df_row['mqtt.hdrflags'] = hdrflags[0]
        df_row['mqtt.msgtype'] = mqtt_pk.type
        df_row['mqtt.dupflag'] = mqtt_pk.DUP
        df_row['mqtt.qos'] = mqtt_pk.QOS
        df_row['mqtt.retain'] = mqtt_pk.RETAIN
        df_row['mqtt.len'] = 0 if mqtt_pk.len == None else mqtt_pk.len

        # MQTT variable header
        if mqtt_pk.len != None:
            if mqtt_pk.type == 1 and mqtt_pk.haslayer(MQTTConnect):
                mqtt_con_pk = mqtt_pk[MQTTConnect]
                df_row['mqtt.proto_len'] = 0 if mqtt_con_pk.length == None else mqtt_con_pk.length
                if mqtt_con_pk.length != None:
                    df_row['mqtt.protoname'] = 1 if b"MQTT" in mqtt_con_pk.protoname else 0
                else:
                    df_row['mqtt.protoname'] = 0
                df_row['mqtt.ver'] = mqtt_con_pk.protolevel
                
                df_row['mqtt.conflag.uname'] = mqtt_con_pk.usernameflag
                if mqtt_con_pk.usernameflag:
                    df_row['mqtt.username_len'] = mqtt_con_pk.userlen
                    df_row['mqtt.username'] = mqtt_con_pk.username
                
                df_row['mqtt.conflag.passwd'] = mqtt_con_pk.passwordflag
                if mqtt_con_pk.passwordflag:
                    df_row['mqtt.passwd_len'] = mqtt_con_pk.passlen
                    df_row['mqtt.passwd'] = mqtt_con_pk.password

                df_row['mqtt.conflag.willretain'] = mqtt_con_pk.willretainflag
                df_row['mqtt.conflag.willqos'] = mqtt_con_pk.willQOSflag

                df_row['mqtt.conflag.willflag'] = mqtt_con_pk.willflag
                if mqtt_con_pk.willflag:
                    df_row['mqtt.willtopic_len'] = mqtt_con_pk.wtoplen
                    df_row['mqtt.willtopic'] = mqtt_con_pk.willtopic
                    df_row['mqtt.willmsg_len'] = mqtt_con_pk.wmsglen 
                    df_row['mqtt.willmsg']     = mqtt_con_pk.willmsg    
                
                df_row['mqtt.conflag.cleansess'] = mqtt_con_pk.cleansess
                df_row['mqtt.conflag.reserved'] = mqtt_con_pk.reserved
                df_row['mqtt.kalive'] = mqtt_con_pk.klive

                conflags = mqtt_con_pk.reserved + mqtt_con_pk.cleansess*2 + mqtt_con_pk.willflag*4 + mqtt_con_pk.willQOSflag*8 \
                            + mqtt_con_pk.willretainflag*32 + mqtt_con_pk.passwordflag*64 + mqtt_con_pk.usernameflag*128
                df_row['mqtt.conflags'] = conflags

                df_row['mqtt.clientid_len'] = 0 if mqtt_con_pk.clientIdlen == None else mqtt_con_pk.clientIdlen
                if mqtt_con_pk.clientIdlen != None:
                    df_row['mqtt.clientid'] = mqtt_con_pk.clientId
                
            elif mqtt_pk.type == 2 and mqtt_pk.haslayer(MQTTConnack):
                df_row['mqtt.conack.flags'] = mqtt_pk[MQTTConnack].sessPresentFlag
                df_row['mqtt.conack.flags.sp'] = mqtt_pk[MQTTConnack].sessPresentFlag % 2
                df_row['mqtt.conack.val'] = mqtt_pk[MQTTConnack].retcode            

            elif mqtt_pk.type == 3 and mqtt_pk.haslayer(MQTTPublish):
                df_row['mqtt.topic_len'] = 0 if mqtt_pk[MQTTPublish].length == None else mqtt_pk[MQTTPublish].length
                if mqtt_pk[MQTTPublish].length != None:
                    df_row['mqtt.topic'] = mqtt_pk[MQTTPublish].topic
                    
                if mqtt_pk.QOS != 0 :
                    df_row['mqtt.msgid'] = 0 if mqtt_pk[MQTTPublish].msgid == None else mqtt_pk[MQTTPublish].msgid
                df_row['mqtt.msglen'] = df_row['mqtt.len'] - df_row['mqtt.topic_len']
                if df_row['mqtt.msglen'].sum() != 0 :
                    df_row['mqtt.msg'] = mqtt_pk[MQTTPublish].value
            
            elif mqtt_pk.type == 4 and mqtt_pk.haslayer(MQTTPuback):
                df_row['mqtt.msgid'] = mqtt_pk[MQTTPuback].msgid
            
            elif mqtt_pk.type == 5 and mqtt_pk.haslayer(MQTTPubrec):
                df_row['mqtt.msgid'] = mqtt_pk[MQTTPubrec].msgid
            
            elif mqtt_pk.type == 6 and mqtt_pk.haslayer(MQTTPubrel):
                df_row['mqtt.msgid'] = mqtt_pk[MQTTPubrel].msgid
            
            elif mqtt_pk.type == 7 and mqtt_pk.haslayer(MQTTPubcomp):
                df_row['mqtt.msgid'] = mqtt_pk[MQTTPubcomp].msgid

            elif mqtt_pk.type == 8 and mqtt_pk.haslayer(MQTTSubscribe):
                mqtt_sub_pk = mqtt_pk[MQTTSubscribe]
                df_row['mqtt.msgid'] = mqtt_sub_pk.msgid
                if mqtt_sub_pk.haslayer(MQTTTopicQOS):
                    df_row['mqtt.topic_len'] = 0 if mqtt_sub_pk[MQTTTopicQOS].length == None else mqtt_sub_pk[MQTTTopicQOS].length
                    if (mqtt_sub_pk[MQTTTopicQOS].length != None) and (mqtt_sub_pk[MQTTTopicQOS].length != 0):
                        df_row['mqtt.topic'] = mqtt_sub_pk[MQTTTopicQOS].topic
                    df_row['mqtt.sub.qos'] = mqtt_sub_pk[MQTTTopicQOS].QOS

            elif mqtt_pk.type == 9 and mqtt_pk.haslayer(MQTTSuback):
                df_row['mqtt.msgid'] = mqtt_pk[MQTTSuback].msgid
                df_row['mqtt.suback.retcode'] = mqtt_pk[MQTTSuback].retcode

            elif mqtt_pk.type == 10 and mqtt_pk.haslayer(MQTTUnsubscribe):
                mqtt_unsub_pk = mqtt_pk[MQTTUnsubscribe]
                df_row['mqtt.msgid'] = mqtt_unsub_pk.msgid
                if mqtt_unsub_pk.haslayer(MQTTTopic):
                    df_row['mqtt.topic_len'] = 0 if mqtt_unsub_pk[MQTTTopic].length == None else mqtt_unsub_pk[MQTTTopic].length
                    if (mqtt_unsub_pk[MQTTTopic].length != None) and (mqtt_unsub_pk[MQTTTopic].length != 0):
                        df_row['mqtt.topic'] = mqtt_unsub_pk[MQTTTopic].topic
            
            elif mqtt_pk.type == 11 and mqtt_pk.haslayer(MQTTUnsuback):
                df_row['mqtt.msgid'] = mqtt_pk[MQTTUnsuback].msgid
            
        merge_df = pd.concat([merge_df,df_row],ignore_index=True)
        mqtt_pk = mqtt_pk.payload
            
    return merge_df

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

dataset_df = pd.DataFrame(columns=ftnames)

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

################################################################

stop_AI = False

def process_packet():
    global stop_AI
    global dataset_df
    while stop_AI == False:
        data = packet_queue.get()
        if data == None:
            break

        # extract IP packet
        gtp_packet = GTPHeader(data)
        if gtp_packet.haslayer(IP)==0:
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

        # get label and count packet.  pk_count= [total, attack, normal]
        ip_packet = gtp_packet[IP]
        label = 1 if ip_packet.src == atk_ip else 0
        if label == 0:
            pk_count[2] += 1
        else:
            pk_count[1] +=1

        try:
            df_packet = ip_packet_to_dataframe(ip_packet,ftnames,pkduration,pk_relative_time)
            df_packet['label'] = label
        
            dataset_df = pd.concat([dataset_df,df_packet],ignore_index=True)
        # df_packet = ip_packet_to_mqttset_dataframe(ip_packet,ftnames,pkduration,pk_relative_time)
        # res = AImodel_Detect_Abnormal(df_packet,label, model_dict)
        except Exception as e:
        # if res != label :
            ip_packet.show()
        #     print(df_packet.shape)
        #     for col in df_packet.columns:
        #         print(col,' ', df_packet[col])
            traceback.print_exc()
            # break
        
        if ((pk_count[0] % 1000) ==0):
            strcnt = 'Checkpoint(' + time.strftime("%d-%m-%Y %H:%M:%S %z") + '):'+str(pk_count)+'\n'
            print(strcnt)

    return 0

processThread = Thread(target=process_packet)

processThread.start()
captureThread.start()

################################################################