#!/bin/bash

SCRIPTS_PATH="/mswg/projects/fw/fw_ver/hca_fw_tools"
#SCRIPTS_PATH="/fwgwork/natano/hca_fw_tools"
. ${SCRIPTS_PATH}/inner_steering_debug.sh
. ${SCRIPTS_PATH}/.fwvalias

mst_dev=${1:?missing dev}
gvmi=${2:?missing gvmi}
port=${3:?missing port}
index=${4:?missing index}

function read_flow_counter() {
    echo FLOW COUNTER: gvmi: $gvmi, portid: $port, flow_counter_index: $index
    echo
    icmd_start_addr="0x2000"
    for i in {0..15} ; do
        mcra $mst_dev $((icmd_start_addr + i*4)) 0x0
    done
    if [[ "$project" != "golan" ]] ;then
        port=0
    fi
    rx_counter=`get_gvmi_counter $mst_dev $port $gvmi 1 $index`
    sx_counter=`get_gvmi_counter $mst_dev $port $gvmi 0 $index`
    rx_p=`echo $rx_counter | awk '{print $6}'`
    rx_b=`echo $rx_counter | awk '{print $8}'`
    sx_p=`echo $sx_counter | awk '{print $6}'`
    sx_b=`echo $sx_counter | awk '{print $8}'`
    total_p=`printf "0x%x" $(( rx_p + sx_p ))`
    total_b=`printf "0x%x" $(( rx_b + sx_b ))`
    echo "                           :     Packets        |      Bytes         "
    echo "-----------------------------------------------------------------------"
    echo $rx_counter
    echo "-----------------------------------------------------------------------"
    echo $sx_counter
    echo "-----------------------------------------------------------------------"
    printf "TOTAL                      : 0x%.16x | 0x%.16x\n" $total_p $total_b
}

read_flow_counter
