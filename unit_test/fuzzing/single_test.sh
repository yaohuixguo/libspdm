#!/bin/bash


if [[ $1 = "mbedtls" || $1 = "openssl" ]]; then
    echo "<CRYPTO> parameter is $1"
else
    echo "Usage: $0 <CRYPTO> <GCOV> <duration>"
    echo "<CRYPTO> means selected Crypto library: mbedtls or openssl"
    echo "<GCOV> means enable Code Coverage or not: ON or OFF"
    echo "<duration> means the duration of every program keep fuzzing: NUMBER seconds"
    exit
fi

export duration1=300
export duration2=1200
export duration3=2400
export duration4=7200
export duration5=43200
export duration6=86400

echo "start fuzzing in Linux with AFLTurbo"

echo '123' | sudo -S sudo pkill screen

export script_path="$(cd "$(dirname $0)";pwd)"
export libspdm_path=$script_path/../..
export fuzzing_path=$libspdm_path/unit_test/fuzzing
export fuzzing_seeds=$libspdm_path/unit_test/fuzzing/seeds
export TIMESTAMP=`date +%Y-%m-%d_%H-%M-%S`

# Here '~/aflturbo/' is the AFLTurbo PATH, replace it with yours.
export AFL_PATH=~/aflturbo/
export PATH=$PATH:$AFL_PATH

if [[ $PWD!=$libspdm_path ]];then
    pushd $libspdm_path
    latest_hash=`git log --pretty="%h" -1`
    export fuzzing_out=$libspdm_path/unit_test/fuzzing/out_$1_$latest_hash-$TIMESTAMP
    export build_fuzzing=$libspdm_path/build_fuzz_$1_$latest_hash-$TIMESTAMP
fi

if [ ! -d "$fuzzing_out" ];then
    mkdir $fuzzing_out
fi

for i in $fuzzing_out/*;do
    if [[ ! -d $i/crashes ]] && [[ ! -d $i/hangs ]];then
        continue
    fi

    if [[ "`ls -A $i/crashes`" != "" ]];then
        echo -e "\033[31m There are some crashes \033[0m"
        echo -e "\033[31m Path in $i/crashes \033[0m"
        exit
    fi

    if [[ "`ls -A $i/hangs`" != "" ]];then
        echo -e "\033[31m There are some hangs \033[0m"
        echo -e "\033[31m Path in $i/hangs \033[0m"
        exit
    fi
done

rm -rf $fuzzing_out/*

if [[ "core" != `cat /proc/sys/kernel/core_pattern` ]];then
    # Here 'test' is the sudo password, replace it with yours.
    echo 'test' | sudo -S bash -c 'echo core >/proc/sys/kernel/core_pattern'
    pushd /sys/devices/system/cpu/
    echo 'test' | sudo -S bash -c 'echo performance | tee cpu*/cpufreq/scaling_governor'
    popd
fi

if [ -d "$build_fuzzing" ];then
    rm -rf $build_fuzzing
fi

mkdir $build_fuzzing
pushd $build_fuzzing

cmake -DARCH=x64 -DTOOLCHAIN=AFL -DTARGET=Release -DCRYPTO=$1 -DGCOV=ON ..
make copy_sample_key
make
pushd bin

cmds=(
test_spdm_transport_mctp_encode_message
test_spdm_transport_mctp_decode_message
test_spdm_transport_pci_doe_encode_message
test_spdm_transport_pci_doe_decode_message
test_spdm_decode_secured_message
test_spdm_requester_encap_digests
test_spdm_responder_encap_challenge
test_spdm_responder_version
test_spdm_responder_digests
test_spdm_responder_heartbeat_ack
test_spdm_responder_key_update
test_spdm_responder_end_session
test_spdm_responder_if_ready
test_spdm_requester_get_csr
test_spdm_responder_chunk_get
)
cmds2=(
test_spdm_encode_secured_message
test_spdm_requester_encap_certificate
test_spdm_requester_encap_key_update
test_spdm_requester_get_version
test_spdm_requester_get_capabilities
test_spdm_responder_encap_get_digests
test_spdm_responder_set_certificate
)
cmds3=(
test_spdm_responder_encap_key_update
test_spdm_responder_encap_response
test_spdm_responder_capabilities
test_spdm_responder_psk_finish_rsp
)
cmds4=(
test_spdm_requester_get_digests
test_spdm_responder_certificate
test_spdm_requester_chunk_send
)
cmds5=(
test_spdm_responder_algorithms
test_spdm_responder_csr
)
cmds6=(
test_spdm_requester_encap_challenge_auth
test_spdm_requester_encap_request
test_spdm_requester_negotiate_algorithms
test_spdm_requester_get_certificate
test_spdm_requester_challenge
test_spdm_requester_get_measurements
test_spdm_requester_key_exchange
test_spdm_requester_finish
test_spdm_requester_psk_exchange
test_spdm_requester_psk_finish
test_spdm_requester_heartbeat
test_spdm_requester_key_update
test_spdm_requester_end_session
test_spdm_responder_encap_get_certificate
test_spdm_responder_challenge_auth
test_spdm_responder_measurements
test_spdm_responder_key_exchange
test_spdm_responder_finish_rsp
test_spdm_responder_psk_exchange_rsp
test_x509_certificate_check
test_spdm_requester_set_certificate
test_spdm_requester_chunk_get
test_spdm_responder_chunk_send_ack
)

export FUZZ_START_TIME=`date +%Y-%m-%d_%H:%M:%S`

for ((i=0;i<${#cmds[*]};i++))
do
    echo ${cmds[$i]}
    screen -ls | grep ${cmds[$i]}
    if [[ $? -ne 0 ]]
    then
    screen -dmS ${cmds[$i]}
    fi
    screen -S ${cmds[$i]} -p 0 -X stuff "afl-turbo-fuzz -i $fuzzing_seeds/${cmds[$i]} -o $fuzzing_out/${cmds[$i]} ./${cmds[$i]} @@"
    screen -S ${cmds[$i]} -p 0 -X stuff $'\n'

    let i+=1
    echo ${cmds[$i]}
    if [ $i -lt ${#cmds[*]} ]
    then
    screen -dmS ${cmds[$i]}
    screen -S ${cmds[$i]} -p 0 -X stuff "afl-turbo-fuzz -i $fuzzing_seeds/${cmds[$i]} -o $fuzzing_out/${cmds[$i]} ./${cmds[$i]} @@"
    screen -S ${cmds[$i]} -p 0 -X stuff $'\n'
    fi

    let i+=1
    echo ${cmds[$i]}
    if [ $i -lt ${#cmds[*]} ]
    then
    screen -dmS ${cmds[$i]}
    screen -S ${cmds[$i]} -p 0 -X stuff "afl-turbo-fuzz -i $fuzzing_seeds/${cmds[$i]} -o $fuzzing_out/${cmds[$i]} ./${cmds[$i]} @@"
    screen -S ${cmds[$i]} -p 0 -X stuff $'\n'
    fi

    sleep $duration1
    echo '123' | sudo -S sudo pkill screen
    sleep 5
done


for ((i=0;i<${#cmds2[*]};i++))
do
    echo ${cmds2[$i]}
    screen -ls | grep ${cmds2[$i]}
    if [[ $? -ne 0 ]]
    then
    screen -dmS ${cmds2[$i]}
    fi
    screen -S ${cmds2[$i]} -p 0 -X stuff "afl-turbo-fuzz -i $fuzzing_seeds/${cmds2[$i]} -o $fuzzing_out/${cmds2[$i]} ./${cmds2[$i]} @@"
    screen -S ${cmds2[$i]} -p 0 -X stuff $'\n'

    let i+=1
    echo ${cmds2[$i]}
    if [ $i -lt ${#cmds2[*]} ]
    then
    screen -dmS ${cmds2[$i]}
    screen -S ${cmds2[$i]} -p 0 -X stuff "afl-turbo-fuzz -i $fuzzing_seeds/${cmds2[$i]} -o $fuzzing_out/${cmds2[$i]} ./${cmds2[$i]} @@"
    screen -S ${cmds2[$i]} -p 0 -X stuff $'\n'
    fi

    let i+=1
    echo ${cmds2[$i]}
    if [ $i -lt ${#cmds2[*]} ]
    then
    screen -dmS ${cmds2[$i]}
    screen -S ${cmds2[$i]} -p 0 -X stuff "afl-turbo-fuzz -i $fuzzing_seeds/${cmds2[$i]} -o $fuzzing_out/${cmds2[$i]} ./${cmds2[$i]} @@"
    screen -S ${cmds2[$i]} -p 0 -X stuff $'\n'
    fi

    sleep $duration2
    echo '123' | sudo -S sudo pkill screen
    sleep 5
done


for ((i=0;i<${#cmds3[*]};i++))
do
    echo ${cmds3[$i]}
    screen -ls | grep ${cmds3[$i]}
    if [[ $? -ne 0 ]]
    then
    screen -dmS ${cmds3[$i]}
    fi
    screen -S ${cmds3[$i]} -p 0 -X stuff "afl-turbo-fuzz -i $fuzzing_seeds/${cmds3[$i]} -o $fuzzing_out/${cmds3[$i]} ./${cmds3[$i]} @@"
    screen -S ${cmds3[$i]} -p 0 -X stuff $'\n'

    let i+=1
    echo ${cmds3[$i]}
    if [ $i -lt ${#cmds3[*]} ]
    then
    screen -dmS ${cmds3[$i]}
    screen -S ${cmds3[$i]} -p 0 -X stuff "afl-turbo-fuzz -i $fuzzing_seeds/${cmds3[$i]} -o $fuzzing_out/${cmds3[$i]} ./${cmds3[$i]} @@"
    screen -S ${cmds3[$i]} -p 0 -X stuff $'\n'
    fi

    sleep $duration3
    echo '123' | sudo -S sudo pkill screen
    sleep 5
done

for ((i=0;i<${#cmds4[*]};i++))
do
    echo ${cmds4[$i]}
    screen -ls | grep ${cmds4[$i]}
    if [[ $? -ne 0 ]]
    then
    screen -dmS ${cmds4[$i]}
    fi
    screen -S ${cmds4[$i]} -p 0 -X stuff "afl-turbo-fuzz -i $fuzzing_seeds/${cmds4[$i]} -o $fuzzing_out/${cmds4[$i]} ./${cmds4[$i]} @@"
    screen -S ${cmds4[$i]} -p 0 -X stuff $'\n'

    let i+=1
    echo ${cmds4[$i]}
    if [ $i -lt ${#cmds4[*]} ]
    then
    screen -dmS ${cmds4[$i]}
    screen -S ${cmds4[$i]} -p 0 -X stuff "afl-turbo-fuzz -i $fuzzing_seeds/${cmds4[$i]} -o $fuzzing_out/${cmds4[$i]} ./${cmds4[$i]} @@"
    screen -S ${cmds4[$i]} -p 0 -X stuff $'\n'
    fi

    let i+=1
    echo ${cmds4[$i]}
    if [ $i -lt ${#cmds4[*]} ]
    then
    screen -dmS ${cmds4[$i]}
    screen -S ${cmds4[$i]} -p 0 -X stuff "afl-turbo-fuzz -i $fuzzing_seeds/${cmds4[$i]} -o $fuzzing_out/${cmds4[$i]} ./${cmds4[$i]} @@"
    screen -S ${cmds4[$i]} -p 0 -X stuff $'\n'
    fi
    sleep $duration4
    echo '123' | sudo -S sudo pkill screen
    sleep 5
done


for ((i=0;i<${#cmds5[*]};i++))
do
    echo ${cmds5[$i]}
    screen -ls | grep ${cmds5[$i]}
    if [[ $? -ne 0 ]]
    then
    screen -dmS ${cmds5[$i]}
    fi
    screen -S ${cmds5[$i]} -p 0 -X stuff "afl-turbo-fuzz -i $fuzzing_seeds/${cmds5[$i]} -o $fuzzing_out/${cmds5[$i]} ./${cmds5[$i]} @@"
    screen -S ${cmds5[$i]} -p 0 -X stuff $'\n'

    let i+=1
    echo ${cmds5[$i]}
    if [ $i -lt ${#cmds5[*]} ]
    then
    screen -dmS ${cmds5[$i]}
    screen -S ${cmds5[$i]} -p 0 -X stuff "afl-turbo-fuzz -i $fuzzing_seeds/${cmds5[$i]} -o $fuzzing_out/${cmds5[$i]} ./${cmds5[$i]} @@"
    screen -S ${cmds5[$i]} -p 0 -X stuff $'\n'
    fi

    sleep $duration5
    echo '123' | sudo -S sudo pkill screen
    sleep 5
done

for ((i=0;i<${#cmds6[*]};i++))
do
    echo ${cmds6[$i]}
    screen -ls | grep ${cmds6[$i]}
    if [[ $? -ne 0 ]]
    then
    screen -dmS ${cmds6[$i]}
    fi
    screen -S ${cmds6[$i]} -p 0 -X stuff "afl-turbo-fuzz -i $fuzzing_seeds/${cmds6[$i]} -o $fuzzing_out/${cmds6[$i]} ./${cmds6[$i]} @@"
    screen -S ${cmds6[$i]} -p 0 -X stuff $'\n'

    let i+=1
    echo ${cmds6[$i]}
    if [ $i -lt ${#cmds6[*]} ]
    then
    screen -dmS ${cmds6[$i]}
    screen -S ${cmds6[$i]} -p 0 -X stuff "afl-turbo-fuzz -i $fuzzing_seeds/${cmds6[$i]} -o $fuzzing_out/${cmds6[$i]} ./${cmds6[$i]} @@"
    screen -S ${cmds6[$i]} -p 0 -X stuff $'\n'
    fi

    let i+=1
    echo ${cmds6[$i]}
    if [ $i -lt ${#cmds6[*]} ]
    then
    screen -dmS ${cmds6[$i]}
    screen -S ${cmds6[$i]} -p 0 -X stuff "afl-turbo-fuzz -i $fuzzing_seeds/${cmds6[$i]} -o $fuzzing_out/${cmds6[$i]} ./${cmds6[$i]} @@"
    screen -S ${cmds6[$i]} -p 0 -X stuff $'\n'
    fi

    sleep $duration6
    echo '123' | sudo -S sudo pkill screen
    sleep 5
done


    cd $fuzzing_out
    mkdir coverage_log
    cd coverage_log
    lcov --capture --directory $build_fuzzing --output-file coverage.info
    genhtml coverage.info --output-directory . --title "Started at : $FUZZ_START_TIME | Crypto lib : $1 | AFL Turbo Fuzzing | The time of per testcase is different"


function walk_dir(){
    for file in `ls $1`
    do
        if [[ -d $1"/"$file ]]
        then
            walk_dir $1"/"$file
        elif [[ $file = "fuzzer_stats" ]]
        then
            echo $1"/"$file
            unique_crashes=''
            unique_hangs=''
            afl_banner=''
            while read line
                do
                    if [[ $line =~ "unique_crashes" ]]
                    then
                        unique_crashes=${line##*:}
                    elif [[ $line =~ "unique_hangs" ]]
                    then
                        unique_hangs=${line##*:}
                    elif [[ $line =~ "afl_banner" ]]
                    then
                        afl_banner=${line##*:}
                    fi
                done < $1"/"$file
            echo $afl_banner,$unique_crashes,$unique_hangs >> $fuzzing_out"/SummaryList.csv"
        fi
    done
}

echo afl_banner,unique_crashes,unique_hangs > $fuzzing_out"/SummaryList.csv"
walk_dir $fuzzing_out