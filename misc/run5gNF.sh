Help()
{
   # Display Help
   echo "Description: run 5G network functions only"
   echo
   echo "Syntax: scriptTemplate [-d|h|s]"
   echo "options:"
   echo "-r     run open5gs NFs."
   echo "-d     run with debug log."
   echo "-h     Print this Help."
   echo "-s     stop open5gs."
   echo
}

run-gNB() {
  sleep 5
  echo "STARING UERANSIM gNB"
  cd ~/phD/UERANSIM_CIOT
  ./build/nr-gnb -c config/open5gs-gnb.yaml &
}

cd ~/phD/open5gs_ciot
cd install/bin

while getopts ":hrds" option; do
    case $option in
        r) # run normal
	    echo "STARTING 5G NFs"
            ./open5gs-amfd &
            ./open5gs-smfd &
            ./open5gs-upfd &
            ./open5gs-nrfd &
            ./open5gs-ausfd &
            ./open5gs-udmd &
            ./open5gs-pcfd &
            ./open5gs-nssfd &
            ./open5gs-bsfd &
            ./open5gs-udrd &
            ./open5gs-scpd &
            ./open5gs-idsfd &
	    run-gNB
            ;;
        d) # run with debug log level
            ./open5gs-amfd  &
            ./open5gs-smfd -d &
            ./open5gs-upfd -d &
            ./open5gs-nrfd  &
            ./open5gs-ausfd  &
            ./open5gs-udmd  &
            ./open5gs-pcfd  &
            ./open5gs-nssfd  &
            ./open5gs-bsfd  &
            ./open5gs-udrd  &
            ./open5gs-scpd  &
            ./open5gs-idsfd &
	    run-gNB
            ;;
        s) # stop open5gs
            echo "Killing open5gs NF"
            pkill open5gs
	    echo "Killing UERANSIM gNB"
	    pkill nr-gnb
            ;;
	 h|*) # display Help as default behavior
            Help
            ;;
        \?) # Invalid option
            echo "Error: Invalid option"
            ;;
    esac
done

# ./open5gs-amfd &
# ./open5gs-smfd &
# ./open5gs-upfd &
# ./open5gs-nrfd &
# ./open5gs-ausfd &
# ./open5gs-udmd &
# ./open5gs-pcfd &
# ./open5gs-nssfd &
# ./open5gs-bsfd &
# ./open5gs-udrd &
# ./open5gs-scpd &


