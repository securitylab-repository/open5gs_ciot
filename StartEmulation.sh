#!/usr/bin/bash

WORKDIR = `pwd`
# Start open5gs and gnb
echo "Start open5gs-gnb"
./misc/run5gNF.sh -r
sleep 10s

# Start IDSF
echo "Start IDSF"
cd src/idsf/idsf_python
python3 idsf_MQTT_DoS_finalize.py &
sleep 5s

cd WORKDIR

# Check VM node-red
ping -c 1 192.168.10.101 &> /dev/null
while [[ $? != 0 ]]; do
	ping -c 1 192.168.10.101 &> /dev/null
done
ping -c 1 192.168.10.102 &> /dev/null
while [[ $? != 0 ]]; do
	ping -c 1 192.168.10.102 &> /dev/null
done
# ping -c 1 192.168.56.7 &> /dev/null
# while [[ $? != 0 ]]; do
# 	ping -c 1 192.168.56.7 &> /dev/null
# done


# ssh vagrant@192.168.56.5 "sleep 5s; date" > test.out  &
# ssh vagrant@192.168.56.5 "sleep 5s; sudo tail -f testsudofile.txt; sleep 5s; echo 'finish'" > mosquitto_server.out &
sleep 5s
echo "Start mosquitto server"
ssh vagrant@192.168.56.5 "./runUEsimtun.sh -r; exit" &
sleep 10s
echo "Start node-red"
ssh vagrant@192.168.56.6 "./runUEsimtun.sh -r; exit" &
sleep 10s
echo "Start attacker"
ssh vagrant@192.168.56.7 "./runUEsimtun.sh -r; exit" &
