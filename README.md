# pretty fs dump

````
usage: pretty_dump.py [-h] -s SAMPLE [-v] [-n] [-t] [--nocolor]

optional arguments:
  -h, --help            show this help message and exit
  -s SAMPLE, --sample SAMPLE
                        Input sample file
  -v, --verbose         Increase verbosity
  -n, --network         Use network prefix instead of netmask
  -t, --tree            Print tree style
  --nocolor             No color output
````

## Dump rules from port 1
`mlxdump -d /dev/mst/mt4117_pciconf0 fsdump --type FT --no_zero > /tmp/dump_demo`

## Dump rules from port 2
`mlxdump -d /dev/mst/mt4117_pciconf0 fsdump --type FT --no_zero --gvmi=1 > /tmp/dump_demo`
