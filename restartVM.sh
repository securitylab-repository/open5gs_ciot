#!/usr/bin/bash

reset_VM() {
	ssh vagrant@192.168.56.5 "sudo reboot" &
	ssh vagrant@192.168.56.6 "sudo reboot" &
	ssh vagrant@192.168.56.7 "sudo reboot" &
}

echo "restart VM"
reset_VM