#!/bin/bash

for (( i=0; i<$1; i=i+1 )); do
    file=socketProps$i
    echo "NumOfParties = $1" >$file

    for (( j=0; j<$1; j=j+1 )); do
    	echo "IP$j = 127.0.0.1" >>$file
    done

    echo "Port0 = $(( 8000 + $i ))" >>$file
    var=0
    ctr=0
    for (( j=0; j<$1; j=j+1 )); do
    	if [[ $j == $i ]]; then continue; fi
	ctr=$(( $ctr + 1 ))
    	if [[ $j -ge $i ]]; then
    	    var=$(( $j - 1 ))
    	else
    	    var=$j
    	fi
    	echo "Port$ctr = $(( 8000 + $j ))" >>$file
    done
done
