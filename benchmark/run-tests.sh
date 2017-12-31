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
    sudo tc qdisc del dev lo root
    # if tc qdisc show dev $interface | grep -q netem; then op_netem=change; fi
    # if tc qdisc show dev $interface | grep -q tbf; then op_tbf=change; fi

    # Note: the variable r here is link rate in Mbits/s
    #burst=`awk -v r=$rate -v hz=$HZ 'END{print 2*r*1e6/(hz*8)}' /dev/null`
    sudo ifconfig $interface mtu 1600 # Otherwise MTU is 100kbytes in local loopback, which can cause problems in tbf
    sudo tc qdisc $op_netem dev $interface root handle 1:1 netem delay $(echo $delay)ms loss $loss
    #sudo tc qdisc $op_tbf   dev $interface parent 1:1 handle 10: tbf rate $(echo $rate)mbit limit $queue_length burst $queue_length
}


if [[ ! -d $output_dir ]]; then
    mkdir $output_dir
fi

if [[ $1 == "run" ]]; then
    tpt=100
    parallelism=1
    export LD_LIBRARY_PATH=../assets
    for num_escrows in 3 7 9; do # 11 19; do
	# Setup the servers
	wait_pids=
	base=`python -c 'import random; print(random.randint(8000,50000))'`
	echo $base
	for (( i=0; $i < $num_escrows; ++i )); do
            python setup-servers.py -b $base -i $i -p $parallelism -n $num_escrows &
            wait_pids="$wait_pids $!"
	done
	wait $wait_pids
	echo "Server setup complete ================================================="

	if [[ -d keydir ]]; then
            trash keydir
	fi
	mkdir keydir
	
	# Run the clients
	for delay in 0 5 10 20 40 80 160; do
            queue_length=`awk "BEGIN{q=int($tpt * 1e6 * $delay * 2e-3 * 2 / 8 + 0.5); if (q > 10000) print q; else print 10000}"`
            echo $queue_length
            set_netem $tpt $delay 0 $queue_length
            python run-client.py -c server-addrs-0.pkl -m register -d keydir -n 1 --no-prime >$output_dir/reg-$num_escrows-$delay-$tpt-$parallelism 2>&1
            echo "Registration complete ================================================="
            python run-client.py -c server-addrs-0.pkl -m file -d keydir -n 5 --no-prime >$output_dir/file-$num_escrows-$delay-$tpt-$parallelism 2>&1
            echo "Filing complete ================================================="
	done
	pkill -9 -f java
	pkill -9 -f python

	# Delete the databases
	sql_str=""
	for (( i=1; $i <= $num_escrows; ++i )); do
            sql_str="$sql_str DROP DATABASE escrow$i;"
	done
	echo $sql_str | mysql -u root -ppassword
    done

elif [[ $1 == "graph" ]]; then
    if [[ -d $output_dir/graphdir ]]; then
	trash $output_dir/graphdir
    fi
    mkdir $output_dir/graphdir
    
    for file in $output_dir/*; do
	op=`echo $file | sed 's/.*\/\([a-z]*\)-\([0-9]*\)-\([0-9]*\)-\([0-9]*\)-\([0-9]*\)/\1/'`
	nsrvr=`echo $file | sed 's/.*\/\([a-z]*\)-\([0-9]*\)-\([0-9]*\)-\([0-9]*\)-\([0-9]*\)/\2/'`
	del=`echo $file | sed 's/.*\/\([a-z]*\)-\([0-9]*\)-\([0-9]*\)-\([0-9]*\)-\([0-9]*\)/\3/'`
	tpt=`echo $file | sed 's/.*\/\([a-z]*\)-\([0-9]*\)-\([0-9]*\)-\([0-9]*\)-\([0-9]*\)/\4/'`
	par=`echo $file | sed 's/.*\/\([a-z]*\)-\([0-9]*\)-\([0-9]*\)-\([0-9]*\)-\([0-9]*\)/\5/'`

	lat=`awk '{if ($6=="LAT") {sum += $7; n += 1}} END{print sum/n;}' $file`
	echo $lat $op $nsrvr $del ms $tpt Mbits/s $par
	echo $del $lat >>$output_dir/graphdir/$op-$nsrvr
    done

    # gnu_file_plt="plot"
    # gnu_reg_plt="plot"
    cd $output_dir/graphdir/
    for file in *; do
	cp $file $file.tmp
	sort -n $file.tmp >$file
	rm $file.tmp

	nsrvr=`echo $file | sed 's/\([a-z]*\)-\([0-9]*\)/\2/'`
	echo $file

	if [[ $file =~ .*file.* ]]; then
	    gnu_file_plt="'$file' using (2*\$1):2 with linespoints title '$nsrvr servers', $gnu_file_plt"
	fi
	if [[ $file =~ .*reg.* ]]; then
	    gnu_reg_plt="'$file' using (2*\$1):(\$2/5) with linespoints title '$nsrvr servers', $gnu_reg_plt"
	fi
    done
    gnu_file_plt="plot $gnu_file_plt"
    gnu_reg_plt="plot $gnu_reg_plt"

    cat >vary-rtt.gnuplot <<_EOF_
    set terminal svg;
    set output 'vary-rtt.svg';

    set multiplot layout 2, 1;
    set xlabel '';
    set ylabel 'Latency for registering a key (sec)';
    set yrange [0:]
    set key left top
    set xtics ('0' 0, '10' 10, '20' 20, '40' 40, '80' 80, '160' 160, '320' 320);

    $gnu_reg_plt

    set xlabel 'Round Trip Time (ms)';
    set ylabel 'Latency for filing an allegation (sec)';
    
    $gnu_file_plt
_EOF_

    gnuplot -p vary-rtt.gnuplot
    inkscape -A vary-rtt.pdf vary-rtt.svg
    cd ../..

else
    echo "Unrecognized option $1. Expected 'run' or 'graph'"
fi
