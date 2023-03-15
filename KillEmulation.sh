#!/usr/bin/bash

restart_all_services() 
{
	cd ~
	ssh vagrant@192.168.56.5 "sudo ./runUEsimtun.sh -s; exit" &
	ssh vagrant@192.168.56.6 "sudo ./runUEsimtun.sh -s; exit" &
	ssh vagrant@192.168.56.7 "sudo ./runUEsimtun.sh -s; exit" &
	pkill python3
	/home/nlag/phD/open5gs_ciot/misc/run5gNF.sh -s
	sleep 10s
}

reset_VM() {
	ssh vagrant@192.168.56.5 "sudo reboot" &
	ssh vagrant@192.168.56.6 "sudo reboot" &
	ssh vagrant@192.168.56.7 "sudo reboot" &
}

echo "Turn off services and open5gs + gnb"
restart_all_services