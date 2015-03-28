#!/bin/bash

. ../testhelper.sh

PROXY_ADDR="127.0.0.1"
PROXY_PORT=5060
PROXY_OPTS="-t"

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

REPORT_FILE="../report_002.txt"
DUMP_EXT=dump
init_report "Testsuite 002: Registraion and basic call with Contact params"

# UAC1 and UAC2 registers using custom params in Contact Header.
# UAC1 runs a uas SIPp instance, this instance Parse the request URI
# Each URI components are insterted in X-Reflected-* headers in the 200 OK
# UAC2 saves the value of X-Reflected-* headers in dump files.

testnum=0

# REGISTER UAC1
testnum=$(($testnum + 1 ))
test_command="$SIPP -set params custom=xyz$UAC1_USER -sf 02-uac-register.xml -ap protected -s $UAC1_USER -i $UAC1_IP -p $UAC1_PORT -m 1 -default_behaviors -bye $PROXY_ADDR:$PROXY_PORT"
run_test $testnum "$UAC1_USER Registration" "$test_command"


# REGISTER UAC2
testnum=$(($testnum + 1 ))
test_command="$SIPP -set params custom=xyz$UAC1_USER -sf 02-uac-register.xml -ap protected -s $UAC2_USER -i $UAC2_IP -p $UAC2_PORT -m 1 -default_behaviors -bye $PROXY_ADDR:$PROXY_PORT"
run_test $testnum "$UAC2_USER Registration" "$test_command"

# RUN UAS SIPp instance in screen
run_in_screen "UAS" $SIPP -set ua $UAC1_USER -sf 02-uas.xml -ci $UAC1_CTRL_IP -cp $UAC1_CTRL_PORT -i $UAC1_IP -p $UAC1_PORT -s $UAC1_USER -m 1

# RUN the scenario
testnum=$(($testnum + 1 ))
test_command="$SIPP -set ua $UAC2_USER -sf 02-uac.xml -i $UAC2_IP -p $UAC2_PORT -s $UAC1_USER -m 1 -default_behaviors -bye $PROXY_ADDR:$PROXY_PORT"
run_test $testnum "SIPp scenario 02-uac.xml" "$test_command"

# let to create the dump files
sleep 1
testnum=$(($testnum + 1 ))
test_command="test -f X-Reflected-Domain.$DUMP_EXT"
run_test $testnum "X-Reflected-Domain.$DUMP_EXT exists" "$test_command"

testnum=$(($testnum + 1 ))
test_command="test -f X-Reflected-Params.$DUMP_EXT"
run_test $testnum "X-Reflected-Params.$DUMP_EXT exists" "$test_command"

testnum=$(($testnum + 1 ))
test_command="test \"$(cat X-Reflected-Params.$DUMP_EXT)\" = \"X-Reflected-Params: custom=xyz$UAC1_USER\""
run_test $testnum "Check param values" "$test_command"

# clean dump files
rm -f *dump

kill_screen UAS

# DEREGISTER  UAC1
testnum=$(($testnum + 1 ))
test_command="$SIPP -set params custom=xyz$UAC1_USER -sf 02-uac-deregister.xml -ap protected -s $UAC1_USER -i $UAC1_IP -p $UAC1_PORT -m 1 -default_behaviors -bye $PROXY_ADDR:$PROXY_PORT"
run_test $testnum "$UAC1_USER De-Registration" "$test_command"

# REGISTER UAC2
testnum=$(($testnum + 1 ))
test_command="$SIPP -set params custom=xyz$UAC1_USER -sf 02-uac-deregister.xml -ap protected -s $UAC2_USER -i $UAC2_IP -p $UAC2_PORT -m 1 -default_behaviors -bye $PROXY_ADDR:$PROXY_PORT"
run_test $testnum "$UAC2_USER De-Registration" "$test_command"
