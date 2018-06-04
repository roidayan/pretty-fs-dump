# pretty fs dump

## Dump rules from port 1
`mlxdump -d /dev/mst/mt4117_pciconf0 fsdump --type FT --no_zero > /tmp/dump_demo`

## Dump rules from port 2
`mlxdump -d /dev/mst/mt4117_pciconf0 fsdump --type FT --no_zero --gvmi=1 > /tmp/dump_demo`
