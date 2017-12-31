#!/bin/bash

function init_remote() {
    # Cleans up the remote, given as the first argument (eg. 'ubuntu@pc'). Expects $parallelism, $this_addr and $other_addr to be set appropriately
    remote=$1
    ssh -A $remote  'bash -s' <<EOF
sudo pkill -9 -f python
sudo pkill -9 -f java


# Create missing users
# for i in {1..11}; do
#     echo "DROP USER escrow\$i" | mysql -u root -ppassword
# done
echo "select User from mysql.user" | mysql -u root -ppassword >/tmp/run-real.users 2>/dev/null
for i in {1..11}; do
    if ! grep escrow\$i /tmp/run-real.users >/dev/null; then
       echo Creating user escrow\$i;
       echo "CREATE USER escrow\$i IDENTIFIED BY 'e\$i'; GRANT ALL PRIVILEGES ON *.* to escrow\$i;" | mysql -u root -ppassword 2>/dev/null
    fi
done

cd SecureMultipartyComputation
git pull

# Start the servers
cd benchmark
export LD_LIBRARY_PATH=/home/ubuntu/SecureMultipartyComputation/assets:
./setup-servers.py --remote -p $parallelism -a '$this_addr' -o '$other_addr' >log 2>&1
if [[ -d /var/www/html ]]; then
   for x in server-addrs-*.pkl; do
       sudo cp \$x /var/www/html
   done
fi
echo "Server $this_addr finished initializing"

EOF
}

function start_servers() {
    # Takes a list of IP addresses and starts servers at those addresses as 'ip1 ip2 ...o'
    # Second argument gives degree of parallelism
    machines=$1
    parallelism=$2
    delete=$3
    echo `echo $machines | wc -w`
    echo $machines
    for ((eid=`echo $machines | wc -w`; eid >= 1; eid--)); do
        i=1
        this_addr=
        other_addr="[ "
        this_login=
        for x in $machines; do
            port=$(( 8000 + $i ))
            addr="[\"$x\", $port]"
            if [[ $i == $eid ]]; then
                this_addr=$addr
                this_login=ubuntu@$x
            else
                other_addr="$other_addr $addr, "
            fi
            i=$(( $i + 1 ))
        done
        other_addr="$other_addr ]"
        other_addr=`python -c "import json; print(json.dumps($other_addr))"`
        echo $this_addr " - " $other_addr
        if [[ $delete == 'yes' ]]; then
            # Delete all escrow databases
            ssh $this_login 'echo "show databases" | mysql -u root -ppassword | grep escrow | sed "s/\(\(escrow[0-9]\+\)\?\).*/drop database \1;/" | mysql -u root -ppassword 2>/dev/null'
        fi
        init_remote $this_login &
        sleep 5

#     ssh $remote 'bash -s' <<EOF
# cd SecureMultipartyComputation/benchmark
# echo \$PWD
# ls
# ./setup-servers.py --remote -p $parallelism -a '$this_addr' -o '$other_addr'
# if [[ -d /var/www/html ]]; then
#    cp server-addrs-\*.pkl /var/www/html
# fi
# echo "Server $eid finished initializing"
# EOF
    done
}

#init_remote $1
if [[ $1 == "setup" ]]; then
    start_servers "$2" $3 $4
elif [[ $1 == "populate_db" ]]; then
    machines=$2
    eid=1
    for x in $machines; do
        remote=ubuntu@$x
        ssh $remote "python -c \"print('USE escrow$eid;' + ' '.join(['INSERT INTO Allegations VALUES (\'dummy%d\', \'dummy\', 2, 3, \'dummy\', \'dummy\'); ' % i for i in range(1000000)]))\" | mysql -u root -ppassword" &
        eid=$(( $eid + 1 ))
    done
    wait
fi
