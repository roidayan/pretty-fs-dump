#!/bin/bash
id=${1:?need encap id}
# 0xb3 encap header type
# before galil use encap_id and from galil onwards use encap_id/2
HW_DMFS_ENCAP_H="0xb3"
ENCAP_ID=`python -c "print hex($id/2)"`
fw/./bin/galil_basic_debug.sh -d /dev/mst/mt4121_pciconf0 --read_res_type -t $HW_DMFS_ENCAP_H -n $ENCAP_ID -g 0
