#!/bin/bash

all_test_dirs=`ls -d */`

dir_count=`echo $all_test_dirs | wc -w`

dir_number=1

for current_dir in $all_test_dirs
do
    pushd $current_dir > /dev/null

    all_tests=`ls run_*.sh`
    test_count=`echo $all_tests | wc -w`
    test_number=1

    for current_test in $all_tests
    do
        echo -en "[DIR: $dir_number/$dir_count   TEST: $test_number/$test_count] ($current_dir$current_test) ... "

        ./$current_test > /dev/null

        if [ $? -eq 0 ]; then
            echo -e '\033[32m OK \033[0m'
        else
            echo -e '\033[31m FAILED \033[0m'
        fi

        test_number=$(($test_number+1))
    done
    popd > /dev/null
    dir_number=$(($dir_number+1))
done
