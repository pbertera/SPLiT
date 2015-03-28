#!/bin/bash

SIPP=/opt/sipp-master/sipp
SCREEN=screen
NETCAT=nc

parse_tpl(){
    # read from stdin and
    # replace any occurence of ${TPL_XXX} tockens with TPL_XXX variable value
    while IFS= read -r line ; do
        while [[ "$line" =~ (\$\{TPL_[a-zA-Z_0-9][a-zA-Z_0-9]*\}) ]] ; do
            LHS=${BASH_REMATCH[1]}
            RHS="$(eval echo "\"$LHS\"")"
            [[ -n $RHS ]] || error "$LHS is not set"
            line=${line//$LHS/$RHS}
        done
        echo "$line"
    done
}

run_in_screen(){
    # spawn a new screen session with command
    # Params:
    # $1: the session name
    # $2* command

    local session=$1
    shift
    local cmd=$@

    log Spawnig a new screen session \"$session\": $cmd
    $SCREEN -dmS $session $cmd
}

kill_sipp(){
    # Send the quit command to an IP/port SIPP control
    # Params:
    # $1: SIPP control IP
    # $2: SIPP control PORT
    log Killing SIPp session using $1:$2
    echo -ne "Q" | $NETCAT -n -w 2 -u $1 $2
}

kill_screen(){
    # kill a screen session
    # Params:
    # $1 session name

    log Killing screen session \"$1\"
    #$SCREEN -S "$1" -X kill
    $SCREEN -S "$1" -X quit
}

log(){
    # print a message
    # Params:
    # $@ the messge to write
    echo "MESSAGE: $@"
}

init_report(){
    # write the report file header
    # 
    # $REPORT_FILE var is needed

    echo "$@" >> $REPORT_FILE
    echo >> $REPORT_FILE
    echo >> $REPORT_FILE
    log $@
    log
}

log_report(){
    # Write a line in the report file
    # Params:
    # $@ the messge to write
    # $REPORT_FILE var is needed
    
    echo "$@" >> $REPORT_FILE
    log $@
}

test_report(){
    # Write a test report
    # Params:
    # $1: return code (numeric, if 0 test OK)
    # $2: test command
    # $3: testID
    # $4: test description

    local ret=$1
    local test_command=$2
    local test_id=$3
    local desc=$4

    log_report "TEST $test_id: $desc"    
    log_report "    TEST_COMMAND: $test_command"
    [ "$ret" -eq 0 ] && log_report "    TEST $test_id: OK" 
    [ "$ret" -eq 0 ] || log_report "    TEST $test_id: KO"
    log_report
}

die(){
    # Print a message and exit
    # Params:
    # $@: the message
    echo "ERROR: $@"
    exit -1
}

run_or_die(){
    # Exec a command, if command fails (return code != 0) die
    # Params:
    # $@ the command
    local ret=-1

    eval $@
    ret=$?
    [ "$ret" == 0 ] || die "Command '$@' failed, returned $ret"
}

run_test(){
    # Run a test case
    # Params: 
    # $1: the testID
    # $2: test description
    # $3: the command

    local test_id=$1
    local test_description=$2
    local test_command=$3

    log "Running test $test_id ($test_description)"
    eval $test_command > /dev/null 2>&1
    test_report $? "$test_command" "$test_id" "$test_description"
}
