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

cd ..
cd install/bin

while getopts ":hrds" option; do
    case $option in
        h) # display Help
            Help
            exit;;
        r) # run normal
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
            exit;;
        d) # run with debug log level
            ./open5gs-amfd -d &
            ./open5gs-smfd -d &
            ./open5gs-upfd -d &
            ./open5gs-nrfd -d &
            ./open5gs-ausfd -d &
            ./open5gs-udmd -d &
            ./open5gs-pcfd -d &
            ./open5gs-nssfd -d &
            ./open5gs-bsfd -d &
            ./open5gs-udrd -d &
            ./open5gs-scpd -d &
            exit;;
        s) # stop open5gs
            echo "Killing open5gs NF"
            pkill open5gs
            exit;;
        \?) # Invalid option
            echo "Error: Invalid option"
            exit;;
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