#!/usr/bin/python

import re
import sys
import argparse

fts = {}
fgs = {}
ftes = []


FT_ESW_FDB = '0x4'


class Flow():
    def __init__(self, attr):
        self.attr = attr

    def __getitem__(self, key):
        return self.attr[key]


class FlowGroup(Flow):
    pass


class FlowTable(Flow):
    pass


class FlowTableEntry(Flow):
    @property
    def group(self):
        try:
            return fgs[self['group_id']]
        except KeyError:
            #print 'ERROR: fte without group id'
            return None

    def __str__(self):
        return 'FTE. my group is %s' % self.group


def parse_args():
    
    parser = argparse.ArgumentParser()
    parser.add_argument('--sample', required=True,
                        help='Inpurt sample file')
    return parser.parse_args()


def main():
    args = parse_args()

    # - FG :gvmi=0x0,table_id=8,group_id=0x0 -
    group_re = re.compile('\s*- ([\w]+) :([\w,=]+)')
    group_keys_re = re.compile('(?:(\w+)=(\w+)),?')

    # action                                                                          :0x4
    # valid                                                                           :0x1
    # group_id                                                                        :0x00000004
    # destination_list_size                                                           :0x1
    # destination[0].destination_id                                                   :0x89
    # destination[0].destination_type                                                 :TIR (0x2)

    with open(args.sample, 'r') as f:
        data = f.read().split("\n\n")

    # parse data
    for block in data:
        block = block.strip()
        m = re.match(group_re, block)
        if not m:
            continue
        group = m.groups()[0]
        keys = re.findall(group_keys_re, m.groups()[1])
        attr = {}
        for item in keys:
            attr[item[0]] = item[1]
        block1 = '\n'.join(block.splitlines()[1:])
        d = re.findall('([^\s]+)\s+:(.*)', block1)
        for item in d:
            attr[item[0]]= item[1]

        if 'group_id' in attr:
            attr['group_id'] = int(attr['group_id'], 0)

        if group == 'FG':
            fg = FlowGroup(attr)
            fgs[fg['group_id']] = fg
        elif group == 'FT':
            ft = FlowTable(attr)
            fts[ft['table_id']] = ft
        elif group == 'FTE':
            fte = FlowTableEntry(attr)
            ftes.append(fte)
        else:
            print 'ERROR: unknown type %s' % group

    # dump
    for fte in ftes:
        if len(fte['table_id']) < 4:
            # TODO: we currently only want the rules we add from ovss
            # we create new fdb table which gets a high id number.
            continue

        print fte


if __name__ == "__main__":
    main()
