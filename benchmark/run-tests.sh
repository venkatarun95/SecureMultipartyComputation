#!/bin/bash

output_dir=results
interface=lo
HZ=100 # HZ value of kernel
parallelism=1

# Set the network emulator. Arguments -
#  - link rate in Mbits/s
#  - one-way delay in ms
#  - % loss rate
#  - queue length in bytes
function set_netem() {
    rate=$1
    delay=$2
    loss=$3
    queue_length=$4
    echo "Setting up rate=$rate Mbits/s, delay=$delay ms, loss=$loss %, queue length=$queue_length bytes"
    op_netem=add
    op_tbf=add
    if tc qdisc show dev $interface | grep -q netem; then op_netem=change; fi
    if tc qdisc show dev $interface | grep -q tbf; then op_tbf=change; fi

    # Note: the variable r here is link rate in Mbits/s
    #burst=`awk -v r=$rate -v hz=$HZ 'END{print 2*r*1e6/(hz*8)}' /dev/null`
    sudo ifconfig $interface mtu 1600 # Otherwise MTU is 100kbytes in local loopback, which can cause problems in tbf
    sudo tc qdisc $op_netem dev $interface root handle 1:1 netem delay $(echo $delay)ms loss $loss
    sudo tc qdisc $op_tbf   dev $interface parent 1:1 handle 10: tbf rate $(echo $rate)mbit limit $queue_length burst $queue_length
}


if [[ ! -d $output_dir ]]; then
    mkdir $output_dir
fi

tpt=100
parallelism=1
export LD_LIBRARY_PATH=../assets
for num_escrows in 3 11 19; do
    # Setup the servers
    wait_pids=
    base=`python -c 'import random; print(random.randint(8000,50000))'`
    echo $base
    for (( i=0; $i < $num_escrows; ++i )); do
        python setup-servers.py $base $i &
        wait_pids="$wait_pids $!"
    done
    wait $wait_pids
    sleep 10
    echo "Server setup complete ================================================="

    # Run the clients
    for delay in 1 50 150; do
        queue_length=`awk "BEGIN{print int($tpt * 1e6 * $delay * 2e-3 / 8 + 0.5);}"`
        echo $queue_length
        set_netem $tpt $delay 0 $queue_length
        python run-client.py -c server-addrs-0.pkl -m register -d keydir -n 30 --no-prime >$output_dir/reg-$num_escrows-$delay-$tpt-$parallelism 2>&1
        echo "Registration complete ================================================="
        python run-client.py -c server-addrs-0.pkl -m file -d keydir -n 100 --prime >$output_dir/file-$num_escrows-$delay-$tpt-$parallelism 2>&1
        echo "Filing complete ================================================="
    done
    pkill -9 java

    # Delete the databases
    sql_str=""
    for (( i=1; $i <= $num_escrows; ++i )); do
        sql_str="$sql_str DROP DATABASE escrow$i;"
    done
    echo $sql_str | mysql -u root -ppassword
    #trash keydir
    #mkdir keydir
    exit
done
