import socket
from scapy.all import *
from scapy.all import ls,raw,load_layer
from scapy.contrib.gtp import GTPHeader
from scapy.layers.inet import IP, TCP, UDP
from scapy.layers.http import HTTP, HTTPRequest, HTTPResponse
from scapy.layers.dns import DNS,DNSQR
from scapy.layers.dhcp import DHCP
from scapy.layers.tls.record import TLS
from scapy.layers.tls.handshake import TLSServerHello
from scapy.contrib.mqtt import MQTT

import time
################################################################
# from scapy.contrib.http2 import 
# import cryptography
load_layer('http')
load_layer('dns')
load_layer('tls')
load_layer('dhcp')

# config
maxMessageSize = 65000
UDP_IP = "127.0.0.25"
UDP_PORT = 2152

# bind socket
sock = socket.socket(socket.AF_INET, # Internet
                     socket.SOCK_DGRAM) # UDP
sock.bind((UDP_IP, UDP_PORT))

print("binding to ip %s port %d" % (UDP_IP, UDP_PORT))

################################################################
# load IP dict
import json
import os.path

stat_file = 'stat_data.json' 
if os.path.exists(stat_file):
    with open(stat_file,'r') as file:
        stat_dict = json.load(file)
else:
    stat_dict = {}

# load feature names
# featurenamefile = 'Feature_name.dat'
# with open(featurenamefile) as file:
#     ftnames = [line.rstrip() for line in file]
# file.close()

# load model
import numpy as np
import pandas as pd
import pickle

# modelfile = 'IDSF_model.pickle'
# with open(modelfile,'rb') as file:
#     loaded_model = pickle.load(file)
# file.close()

# save function before exit
import atexit
def exit_handler():
    with open(stat_file, "w") as fp:
        json.dump(stat_dict,fp)
    print('Dumped stat before exit')

atexit.register(exit_handler)

################################################################

################################################################

################################################################

def ip_packet_to_dataframe(pk,feature_name,duration,stat_dict):
    df = pd.DataFrame(0,index=np.arange(1), columns=feature_name)
    if pk.haslayer(UDP) or pk.haslayer(TCP) or pk.haslayer(DNS):
        df['src_port'] = (pk.payload.sport - 1)/65535
        df['dst_port'] = (pk.payload.dport - 1)/65535
    df['duration'] = duration/93516
    df['src_bytes'] = pk[IP].len / 65535
    # df['dst_bytes'] = 0
    
    if pk.src in stat_dict:
        df['src_pkts'] = stat_dict[pk.src][0]/252181
        df['src_ip_bytes'] = stat_dict[pk.src][1]/47367248
    else:
        df['src_pkts'] = 0
        df['src_ip_bytes'] = 0
    if pk.dst in stat_dict:
        df['dst_pkts'] = stat_dict[pk.dst][0]/313943
        df['dst_ip_bytes'] = stat_dict[pk.dst][1]/86395523
    else:
        df['dst_pkts'] = 0
        df['dst_ip_bytes'] = 0

    
    df['proto_icmp'] = 1 if pk.proto == 1 else 0
    df['proto_tcp'] = 1 if pk.proto == 6 else 0
    df['proto_udp'] = 1 if pk.proto == 17 else 0

    # df['service_dce_rpc'] = 0
    df['service_dhcp'] = 1 if pk.haslayer(DHCP) else 0
    df['service_ftp'] = 1 if pk.haslayer(TCP) and (pk[TCP].sport == 21 or pk[TCP].dport == 21) else 0
    # df['service_gssapi'] = 0
    df['service_http'] = 1 if pk.haslayer(HTTP) else 0
    # df['service_smb'] = 0
    # df['conn_state_S1'] = 1
    if pk.haslayer(DNS):
        df['service_dns'] =  1
        if pk.haslayer(DNSQR):
            df['dns_qclass_1'] = 1 if pk[DNSQR].qclass == 1 else 0
            df['dns_qclass_32769'] = 1 if pk[DNSQR].qclass == 32769 else 0
            df['dns_qtype_1'] = 1 if pk[DNSQR].qtype == 1 else 0
            df['dns_qtype_2'] = 1 if pk[DNSQR].qtype == 2 else 0
            df['dns_qtype_6'] = 1 if pk[DNSQR].qtype == 6 else 0
            df['dns_qtype_12'] = 1 if pk[DNSQR].qtype == 12 else 0
            df['dns_qtype_16'] = 1 if pk[DNSQR].qtype == 16 else 0
            df['dns_qtype_28'] = 1 if pk[DNSQR].qtype == 28 else 0
            df['dns_qtype_32'] = 1 if pk[DNSQR].qtype == 32 else 0
            df['dns_qtype_33'] = 1 if pk[DNSQR].qtype == 33 else 0
            df['dns_qtype_43'] = 1 if pk[DNSQR].qtype == 43 else 0
            df['dns_qtype_48'] = 1 if pk[DNSQR].qtype == 48 else 0
            df['dns_qtype_255'] = 1 if pk[DNSQR].qtype == 255 else 0

            dns_qname = pk[DNSQR].qname.decode()
            dns_feature = dns_feature_extract(dns_qname)
            dns_feature_name = ['dns_domain_len','dns_subdomain_len','dns_label_no','dns_label_maxlen',
                    'dns_char_label','dns_www','dns_alpha_size','dns_upcase_no','dns_digit_ratio',
                    'dns_vowel_ratio','dns_under_ratio','dns_repeat_ratio','dns_reconso_ratio','dns_repdigit_ratio']

            for i,name in enumerate(dns_feature_name):
                df[name] = dns_feature[i]

        else:
            df['dns_qclass_0'] = 1
            df['dns_qtype_0'] = 1
        df['dns_rcode_0'] = 1 if pk[DNS].rcode == 0 else 0
        df['dns_rcode_1'] = 1 if pk[DNS].rcode == 1 else 0
        df['dns_rcode_2'] = 1 if pk[DNS].rcode == 2 else 0
        df['dns_rcode_3'] = 1 if pk[DNS].rcode == 3 else 0
        df['dns_rcode_5'] = 1 if pk[DNS].rcode == 5 else 0
        df['dns_AA_F'] = 1 if pk[DNS].aa == 0 else 0
        df['dns_AA_T'] = 1 if pk[DNS].aa == 1 else 0
        df['dns_RD_F'] = 1 if pk[DNS].rd == 0 else 0
        df['dns_RD_T'] = 1 if pk[DNS].rd == 1 else 0
        df['dns_RA_F'] = 1 if pk[DNS].ra == 0 else 0
        df['dns_RA_T'] = 1 if pk[DNS].ra == 1 else 0
        df['dns_rejected_F'] = 1 if pk[DNS].rcode == 0 else 0
        df['dns_rejected_T'] = 1 if pk[DNS].rcode == 5 else 0

    else:
        df['service_dns'] =  0
    
    if pk.haslayer(TLS):
        df['service_ssl'] = 1 
        df['ssl_version_TLSv10'] = 1 if pk[TLS].version == 769 else 0
        df['ssl_version_TLSv12'] = 1 if pk[TLS].version == 771 else 0
        df['ssl_version_TLSv13'] = 1 if pk[TLS].version == 772 else 0
        df['ssl_established_T'] =  1
        if pk.haslayer(TLSServerHello):
            df['ssl_cipher_TLS_AES_128_GCM_SHA256'] = 1 if pk[TLSServerHello].cipher == 4865 else 0
            df['ssl_cipher_TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256'] = 1 if pk[TLSServerHello].cipher == 49195 else 0
            df['ssl_cipher_TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256'] = 1 if pk[TLSServerHello].cipher == 49199 else 0
            df['ssl_cipher_TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA'] = 1 if pk[TLSServerHello].cipher == 49172 else 0
            df['ssl_cipher_TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384'] = 1 if pk[TLSServerHello].cipher == 49192 else 0
    else:
        df['service_ssl'] = 0
        df['ssl_established_F'] =  1
    
    if pk.haslayer(HTTPRequest):
        http_pk = pk[HTTPRequest]
        if http_pk.Content_Length:
            df['http_request_body_len'] = float(http_pk.Content_Length) / 2338
        df['http_orig_mime_types_application/soap+xml'] = 1 if http_pk.Content_Type == b'application/soap+xml' else 0
        df['http_orig_mime_types_application/xml'] = 1 if http_pk.Content_Type == b'application/xml' else 0
        df['http_trans_depth_1.0'] = 1
        df['http_method_GET'] =  1 if http_pk.Method == b'GET' else 0
        df['http_method_HEAD'] = 1 if http_pk.Method == b'HEAD' else 0
        df['http_method_POST'] = 1 if http_pk.Method == b'POST' else 0
        http_UA = pk[HTTPRequest].User_Agent.decode()
        if len(http_UA) !=0:
            http_UA = http_UA.split('/')[0].split()[-1]

        df['http_user_agent_APT-HTTP'] = 1 if http_UA == 'APT-HTTP' else 0
        df['http_user_agent_BITS'] = 1 if http_UA == 'BITS' else 0
        df['http_user_agent_Comos'] = 1 if http_UA == 'Comos' else 0
        df['http_user_agent_DAFUPnP'] = 1 if http_UA == 'DAFUPnP' else 0
        df['http_user_agent_DLNADOC'] = 1 if http_UA == 'DLNADOC' else 0
        df['http_user_agent_DataCha0s'] = 1 if http_UA == 'DataCha0s' else 0
        df['http_user_agent_MICROSOFT_DEVICE_METADATA_RETRIEVAL_CLIENT'] = 1 if http_UA == 'MICROSOFT_DEVICE_METADATA_RETRIEVAL_CLIENT' else 0
        df['http_user_agent_Microsoft-CryptoAPI'] = 1 if http_UA == 'Microsoft-CryptoAPI' else 0
        df['http_user_agent_Microsoft-Delivery-Optimization'] = 1 if http_UA == 'Microsoft-Delivery-Optimization' else 0
        df['http_user_agent_Microsoft-WNS'] = 1 if http_UA == 'Microsoft-WNS' else 0
        df['http_user_agent_Microsoft-Windows'] = 1 if http_UA == 'Microsoft-Windows' else 0
        df['http_user_agent_Mozilla'] = 1 if http_UA == 'Mozilla' else 0
        df['http_user_agent_NCSI'] = 1 if http_UA == 'NCSI' else 0
        df['http_user_agent_Ruby'] = 1 if http_UA == 'Ruby' else 0
        df['http_user_agent_Windows-Update-Agent'] = 1 if http_UA == 'Windows-Update-Agent' else 0
        df['http_user_agent_Windows98SE'] = 1 if http_UA == 'Windows98SE' else 0
        df['http_user_agent_hacking'] = 1 if http_UA == 'hacking' else 0
        df['http_user_agent_sqlmap'] = 1 if http_UA == 'sqlmap' else 0

        http_uri = pk[HTTPRequest].Path.decode()
        uri_feature = uri_feature_extract(http_uri)

        uri_numeric_feature = ['URI_len','URI_num','URI_maxlen','param_len','param_num','name_maxlen',
                                'value_maxlen','digit_percent','letter_percent','URL_unknown']

        uri_nominal_feature = ['URI_type','name_type','value_type']
        
        for i,name in enumerate(uri_numeric_feature):
            df[name] = uri_feature[i]
        
        df['URI_type_0.0'] = 1 if uri_feature[-3] == 0 else 0
        df['URI_type_1.0'] = 1 if uri_feature[-3] == 1 else 0
        df['URI_type_2.0'] = 1 if uri_feature[-3] == 2 else 0
        df['name_type_0.0'] = 1 if uri_feature[-2] == 0 else 0
        df['name_type_1.0'] = 1 if uri_feature[-2] == 1 else 0
        df['value_type_0.0'] = 1 if uri_feature[-1] == 0 else 0
        df['value_type_1.0'] = 1 if uri_feature[-1] == 1 else 0
        df['value_type_2.0'] = 1 if uri_feature[-1] == 2 else 0


    elif pk.haslayer(HTTPResponse):
        http_pk = pk[HTTPResponse]
        if http_pk.Content_Length:
            df['http_response_body_len'] = float(http_pk.Content_Length) / 13424384
        df['http_trans_depth_1.0'] = 1

        df['http_status_code_0'] = 1 if http_pk.Status_Code == b'0' else 0
        df['http_status_code_101'] = 1 if http_pk.Status_Code == b'101' else 0
        df['http_status_code_200'] = 1 if http_pk.Status_Code == b'200' else 0
        df['http_status_code_206'] = 1 if http_pk.Status_Code == b'206' else 0
        df['http_status_code_302'] = 1 if http_pk.Status_Code == b'302' else 0
        df['http_status_code_403'] = 1 if http_pk.Status_Code == b'403' else 0
        df['http_status_code_404'] = 1 if http_pk.Status_Code == b'404' else 0

        df['http_resp_mime_types_application/ocsp-response'] = 1 if http_pk.Content_Type == b'application/ocsp-response' else 0
        df['http_resp_mime_types_application/vnd.ms-cab-compressed'] = 1 if http_pk.Content_Type == b'application/vnd.ms-cab-compressed' else 0
        df['http_resp_mime_types_application/xml'] = 1 if http_pk.Content_Type == b'application/xml' else 0
        df['http_resp_mime_types_image/jpeg'] = 1 if http_pk.Content_Type == b'image/jpeg' else 0
        df['http_resp_mime_types_image/png'] = 1 if http_pk.Content_Type == b'image/png' else 0
        df['http_resp_mime_types_text/html'] = 1 if http_pk.Content_Type == b'text/html' else 0
        df['http_resp_mime_types_text/json'] = 1 if http_pk.Content_Type == b'text/json' or http_pk.Content_Type == b'application/json' else 0
        df['http_resp_mime_types_text/plain'] = 1 if http_pk.Content_Type == b'text/plain' else 0

    
    # print(df)
    return df

################################################################

def AImodel_Detect_Abnormal(df,model):
    preds = model.predict(df)
    return preds

################################################################
import pycurl
from io import StringIO,BytesIO 
import json

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
    print(body.decode('iso-8859-1'))

    crl.close()
    return status_code

################################################################
# Main Function
lastpackettime = time.time()
release = True
while True:
    data, addr = sock.recvfrom(maxMessageSize) # buffer size is 65000 bytes
    # print("received",len(data)," bytes")

    # get duration
    now = time.time()
    pkduration = now - lastpackettime
    lastpackettime = now 

    # extract IP packet
    gtp_packet = GTPHeader(data)
    # gtp_packet.show()
    # print("TEID",gtp_packet.teid)
    ss_context_ref = gtp_packet.teid
    if gtp_packet.haslayer(IP)==0:
        continue
    ip_packet = gtp_packet[IP]
    if ip_packet.haslayer(MQTT):
        ip_packet[MQTT].show()
    
    # record IP packet statistic
    if ip_packet.src in stat_dict:
        stat_dict[ip_packet.src][0] += 1
        stat_dict[ip_packet.src][1] += ip_packet.len
    else:
        stat_dict[ip_packet.src] = [1,ip_packet.len]

    # ip_dst = ip_packet.dst
    # if ip_dst in stat_dict:
    #     stat_dict[ip_dst][2] += 1
    #     stat_dict[ip_dst][3] += ip_packet.len
    # else:
    #     stat_dict[ip_dst] = [0,0,1,ip_packet.len]

    # df_packet = ip_packet_to_dataframe(ip_packet,ftnames,pkduration,stat_dict)
    # res = AImodel_Detect_Abnormal(df_packet,loaded_model)
    # print(res)
    
    res = [0]
    if res[0]:
        print('Malicious Packet Detected')
        ip_packet.show()
        print('Send session release request: ',ss_context_ref)
        # response = idsf_nsmf_send_session_release(ss_context_ref)

    # if release == True:
    #     release = False
    #     print('Send session release request: ',ss_context_ref)
    #     response = idsf_nsmf_send_session_release(ss_context_ref)
        

################################################################
