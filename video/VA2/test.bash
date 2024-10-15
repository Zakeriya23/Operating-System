#!/bin/bash
FAIL_COUNT=0

for NUM in 1 2 3 4 5
do
    ./vector -i ~rchaney/Classes/cs333/VideoAssignments/data/v${NUM}.txt -o v${NUM}-o.txt

    diff -q ~rchaney/Classes/cs333/VideoAssignments/data/v${NUM}-o.txt v${NUM}-o.txt
    if [ $? -ne 0 ]
    then
        echo "Output files number ${NUM} differ. This is sad"
        ((FAIL_COUNT+=1))
    fi
done

if [ ${FAIL_COUNT} -eq 0 ]
then
    echo "looks all good"
else
    echo "you should check your code for correctness"
fi
