if [[ $# < 2 ]]; then
   echo "Usage: ./install.sh [command] [eid]"
   exit
fi
eid=$2

if [[ $1 == "install" ]]; then
    # On a blank AWS Ubuntu 16 instance, do
    # set variable eid to this escrow's id between 1 and n
    git clone git@github.com:venkatarun95/SecureMultipartyComputation
    sudo apt-get update
    sudo apt-get install -y default-jdk libmysql-java libssl1.0.0 libssl-dev mysql-server python
    echo "export LD_LIBRARY_PATH=/home/ubuntu/SecureMultipartyComputation/assets:$LD_LIBRARY_PATH" >>~/.bashrc
    source ~/.bashrc
    cd SecureMultipartyComputation/src
    echo "CREATE USER escrow$eid IDENTIFIED BY 'e$eid'; GRANT ALL PRIVILEGES ON *.* to escrow$eid;" | mysql -u root -ppassword
    ./compile
    # If compiling scapi from source, in makefile, add -std=c++0x to the CXXFLAGS variable

elif [[ $1 == "setup" ]]; then
    # Machines
    # OpenStack 128.52.160.213
    # London 35.177.75.79
    # Singapore 54.255.211.76
    if [[ $# != 4 ]]; then
        echo "Usage: ./install.sh setup <eid> <machines> <parallelism>"
        exit
    fi
    machines=$3
    parallelism=$4
    #machines='"52.91.191.177" "52.221.251.241" "35.177.138.132"'
    i=1
    this_addr=
    other_addr="["
    for x in $machines; do
        port=$(( 8000 + $i + 1 ))
        addr="[$x, $port]"
        if [[ $i == $eid ]]; then
            this_addr=$addr
        else
            other_addr="$other_addr $addr, "
        fi
        i=$(( $i + 1 ))
    done
    other_addr="$other_addr]"
    echo $this_addr " - " $other_addr
    other_addr=`python -c "import json; print(json.dumps($other_addr))"`

    ./setup-servers.py --remote -p $parallelism -a "$this_addr" -o "$other_addr"

    # Running
    # OpenStack, London, Singapore
    # ./setup-servers.py --remote -p 1 -a '["35.177.75.79", 8003]' -o '[["128.52.160.213", 8001], ["54.255.211.76", 8002]]'
    # ./setup-servers.py --remote -p 1 -a '["54.255.211.76", 8002]' -o '[["128.52.160.213", 8001], ["35.177.75.79", 8003]]'
    # ./setup-servers.py --remote -p 1 -a '["128.52.160.213", 8001]' -o '[["54.255.211.76", 8002], ["35.177.75.79", 8003]]'

elif [[ $1 == "reset_db" ]]; then
    echo "drop database escrow$eid; show databases;" | mysql -u root -ppassword

else
    echo "Unrecognized command '$1'"
fi
