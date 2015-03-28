#!/bin/bash

. ../testhelper.sh

PROXY_ADDR="127.0.0.1"
PROXY_PORT=5060

UAC1_IP="127.0.0.1"
UAC1_PORT="5061"
UAC1_USER=100
UAC1_CTRL_PORT=8881
UAC1_CTRL_IP="127.0.0.1"

UAC2_IP="127.0.0.1"
UAC2_PORT="5062"
UAC2_USER=200
UAC2_CTRL_PORT=8882
UAC2_CTRL_IP="127.0.0.1"

REPORT_FILE="../report_001.txt"

init_report "Testsuite 001: Registraion and basic call"

testnum=0

# REGISTER UAC1
testnum=$(($testnum + 1 ))
test_command="$SIPP -sf 01-uac-register.xml -ap protected -s $UAC1_USER -i $UAC1_IP -p $UAC1_PORT -m 1 -default_behaviors -bye $PROXY_ADDR:$PROXY_PORT"
run_test $testnum "$UAC1_USER Registration" "$test_command"

# REGISTER UAC2
testnum=$(($testnum + 1 ))
test_command="$SIPP -sf 01-uac-register.xml -ap protected -s $UAC2_USER -i $UAC2_IP -p $UAC2_PORT -m 1 -default_behaviors -bye $PROXY_ADDR:$PROXY_PORT"
run_test $testnum "$UAC2_USER Registration" "$test_command"

# RUN UAS SIPp instance in screen
run_in_screen "UAS" $SIPP -sf 01-uas.xml -ci $UAC1_CTRL_IP -cp $UAC1_CTRL_PORT -i $UAC1_IP -p $UAC1_PORT -s $UAC1_USER -m 1

# RUN the scenario
testnum=$(($testnum + 1 ))
test_command="$SIPP -set ua $UAC2_USER -sf 01-uac.xml -i $UAC2_IP -p $UAC2_PORT -s $UAC1_USER -m 1 -default_behaviors -bye $PROXY_ADDR:$PROXY_PORT"
run_test $testnum "SIPp scenario 01-uac.xml" "$test_command"

# DEREGISTER  UAC1
testnum=$(($testnum + 1 ))
test_command="$SIPP -sf 01-uac-deregister.xml -ap protected -s $UAC1_USER -i $UAC1_IP -p $UAC1_PORT -m 1 -default_behaviors -bye $PROXY_ADDR:$PROXY_PORT"
run_test $testnum "$UAC1_USER De-Registration" "$test_command"

# REGISTER UAC2
testnum=$(($testnum + 1 ))
test_command="$SIPP -sf 01-uac-deregister.xml -ap protected -s $UAC2_USER -i $UAC2_IP -p $UAC2_PORT -m 1 -default_behaviors -bye $PROXY_ADDR:$PROXY_PORT"
run_test $testnum "$UAC2_USER De-Registration" "$test_command"
