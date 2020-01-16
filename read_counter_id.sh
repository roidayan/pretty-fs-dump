#!/bin/bash
counter_id=${1:?need counter id}
/mswg/projects/fw/fw_ver/hca_fw_tools/steering_basic_debug.sh -d /dev/mst/mt4121_pciconf0 --read_flow_counter -g 1 -p 0 -i $counter_id
