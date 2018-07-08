#!/usr/bin/python

import re
import sys
import argparse
import socket
import struct

try:
    from termcolor import colored
    use_color = True
except ImportError:
    use_color = False

try:
    from netaddr import IPNetwork
    NETADDR = True
except ImportError:
    NETADDR = False

__authors__ = ['Roi Dayan', 'Shahar Klein', 'Paul Blakey']

verbose = 0

fts = {}
fgs = {}
ftes = []

FDB_UPLINK_VPORT = '0xffff'

# table type
FT_ESW_FDB = '0x4'

# actions
FT_ACTION_ALLOW   = 1 << 0
FT_ACTION_DROP    = 1 << 1
FT_ACTION_FWD     = 1 << 2
FT_ACTION_COUNT   = 1 << 3
FT_ACTION_ENCAP   = 1 << 4
FT_ACTION_DECAP   = 1 << 5


class Flow():
    def __init__(self, attr):
        self.attr = attr

    @property
    def attrs(self):
        return self.attr.copy()

    def __getitem__(self, key):
        return self.attr.get(key, None)


class FlowGroup(Flow):
    pass


class FlowTable(Flow):
    pass


class FlowTableEntry(Flow):
    @property
    def table_id(self):
        if verbose < 3:
            return
        return 'table_id(0x%x)' % self.attr['table_id']

    def get_mask(self, key):
        return self.group[key] or '0x0'

    @property
    def group(self):
        try:
            return fgs[self['group_id']]
        except KeyError:
            #print 'ERROR: fte without group id'
            return None

    @property
    def ethertype(self):
        k = '%s.ethertype' % self.get_headers()
        ethertype = self[k]
        if not ethertype:
            return ''
        self._ignore.append(k)
        eth_type = '0x' + ethertype[2:].zfill(4)
        # TODO: in verbose print tcp,udp,arp,etc
        return 'eth_type(%s)' % eth_type

    @property
    def ipv4(self):
        items = []

        def get_ip(k):
            self._ignore.append(k)
            ip = self[k]
            ip_mask = self.get_mask(k)
            if not ip:
                ip = '0'
            if ip_mask != '0x0':
                ip = int2ip(int(ip, 0))
                if ip_mask != '0xffffffff':
                    ip += '/' + int2ip(int(ip_mask, 0))
                if NETADDR:
                    ip = str(IPNetwork(ip))
                return ip
            else:
                return None

        src = get_ip(self.get_headers() + '.src_ip_31_0')
        dst = get_ip(self.get_headers() + '.dst_ip_31_0')

        try:
            ip_proto = str(int(self[self.get_headers() + '.ip_protocol'], 0))
            ip_proto_mask = self.get_mask(self.get_headers() + '.ip_protocol')
            if ip_proto_mask != '0xff':
                ip_proto += '/' + ip_proto_mask
            self._ignore.append(self.get_headers() + '.ip_protocol')
        except TypeError:
            ip_proto = None

        if src:
            items.append('src='+src)
        if dst:
            items.append('dst='+dst)
        if ip_proto:
            items.append('proto=%s' % ip_proto)

        frag_mask = self.get_mask(self.get_headers() + '.frag')
        if frag_mask != '0x0':
            frag = self[self.get_headers() + '.frag']
            if frag:
                items.append('frag=yes')
            else:
                items.append('frag=no')
        self._ignore.append(self.get_headers() + '.frag')

        if not items:
            return

        return 'ipv4(%s)' % ','.join(items)

    def get_port(self, k):
        try:
            port = str(int(self[k], 0))
            port_mask = self.get_mask(k)
            self._ignore.append(k)
            if port_mask != '0xffff':
                port += '/' + port_mask
            return port
        except TypeError:
            return

    @property
    def ports(self):
        out = ''
        for p in ['udp', 'tcp']:
            items = []
            sport = self.get_port('%s.%s_sport' % (self.get_headers(), p))
            if sport:
                items.append('src=%s' % sport)
            dport = self.get_port('%s.%s_dport' % (self.get_headers(), p))
            if dport:
                items.append('dst=%s' % dport)
            if not items:
                continue
            out += ',%s(%s)' % (p, ','.join(items))

        # udp(src=,dst=)
        # tcp(src=,dst=)
        return out.lstrip(',')

    @property
    def mac(self):
        """
        eth(src=xxxx,dst=xxxx)
        """
        items = []

        def get_mac_helper(low, high):
            mac1 = low or '00'
            mac1 = mac1[2:].zfill(4)
            mac2 = high

            if mac2:
                mac2 = mac2[2:].zfill(8)
            else:
                mac2 = '00000000'

            mac = mac2 + mac1
            mac = re.sub(r'(..)', r'\1:', mac).rstrip(':')
            return mac

        def get_mac(low, high):
            low = self.get_headers() + '.' + low
            high = self.get_headers() + '.' + high
            mac = get_mac_helper(self[low], self[high])
            mac_mask = get_mac_helper(self.get_mask(low), self.get_mask(high))
            if mac_mask == '00:00:00:00:00:00':
                return
            if mac_mask != 'ff:ff:ff:ff:ff:ff':
                mac += '/' + mac_mask
            self._ignore.append(low)
            self._ignore.append(high)
            return mac

        smac = get_mac('smac_15_0', 'smac_47_16')
        dmac = get_mac('dmac_15_0', 'dmac_47_16')

        if smac:
            items.append('src='+smac)
        if dmac:
            items.append('dst='+dmac)

        if not items:
            return

        return 'eth(%s)' % ','.join(items)

    @property
    def is_vlan(self):
        return self.get_mask('outer_headers.cvlan_tag') != '0x0'

    @property
    def vlan(self):
        if not self.is_vlan:
            return

        self._ignore.append('outer_headers.cvlan_tag')

        def get_vlan():
            vid = self['outer_headers.first_vid']
            if not vid:
                return
            vlan_id = str(int(vid, 0))
            vlan_mask = self.get_mask('outer_headers.first_vid')
            if vlan_mask != '0xfff':
                vlan_id += '/' + vlan_mask
            self._ignore.append('outer_headers.first_vid')
            return vlan_id

        def get_prio():
            try:
                prio = str(int(self['outer_headers.first_prio'], 0))
            except TypeError:
                prio = '0'
            prio_mask = self.get_mask('outer_headers.first_prio')
            if prio_mask != '0x7':
                prio += '/' + prio_mask
            self._ignore.append('outer_headers.first_prio')
            return prio

        v = get_vlan()
        p = get_prio()
        return 'vlan(vid=%s,pcp=%s)' % (v, p)

    @property
    def is_vxlan(self):
        return self['misc_parameters.vxlan_vni'] is not None

    @property
    def vxlan(self):
        """
        tunnel(tun_id=0x01,src=1.2.3.4,dst=1.2.3.4,tp_src=4789,tp_dst=4789,ttl=128)
        """

        if not self.is_vxlan:
            return

        items = []

        def get(t, k, size):
            v = self[k]
            m = self.get_mask(k)
            if m != '0x0' and m[2:] != 'f' * size * 2:
                v += '/' + m
            if v:
                v = t + '=' + v
            self._ignore.append(k)
            return v

        vni = get('tun_id', 'misc_parameters.vxlan_vni', 3)
        items.append(vni)

        items.append(self.mac)
        items.append(self.ipv4)
        # no need to show outer ethertype for tunnel.
        self.ethertype

        sport = self.get_port('outer_headers.udp_sport')
        if sport:
            items.append('tp_src=%s' % sport)
        dport = self.get_port('outer_headers.udp_dport')
        if dport:
            items.append('tp_dst=%s' % dport)

        items = list(filter(None, items))

        if not items:
            return

        return 'tunnel(%s)' % ','.join(items)

    def port_name(self, port):
        if verbose < 1:
            return port

        if not port:
            return 'PortNone'

        if port.lower() == FDB_UPLINK_VPORT.lower():
            port = 'uplink'
        else:
            port = 'vport%s' % int(port, 0)
        return port

    @property
    def in_esw(self):
        self._ignore.append('misc_parameters.src_esw_owner_vhca_id')
        esw = self['misc_parameters.src_esw_owner_vhca_id']
        esw_mask = self.get_mask('misc_parameters.src_esw_owner_vhca_id')

        if esw_mask == '0x0':
            return

        if not esw:
            esw = '0x0'

        return 'esw(%s)' % esw

    @property
    def in_port(self):
        self._ignore.append('misc_parameters.source_port')

        port = self['misc_parameters.source_port']
        if not port:
            if self.group['misc_parameters.source_port']:
                port = '0'
            else:
                return ''
        return 'in_port(%s)' % self.port_name(port)

    @property
    def counter(self):
        self._ignore.extend([
            'flow_counter_list_size',
            'flow_counter[0].flow_counter_id',
            'flow_counter[1].flow_counter_id',
        ])

        if verbose < 2:
            return

        counter_id = (self['flow_counter[0].flow_counter_id'] or
                      self['flow_counter[1].flow_counter_id'])
        if not counter_id:
            return

        return ' counter:%s' % counter_id

    @property
    def action(self):
        self._ignore.append('action')
        act = int(self['action'], 16)
        act &= ~FT_ACTION_COUNT
        act1 = []

        if self.is_vlan:
            act1.append('pop_vlan')
        if act & FT_ACTION_ENCAP:
            act &= ~FT_ACTION_ENCAP
            self._ignore.append('encap_id')
            encap_id = self['encap_id'] or '0x0'
            act1.append('set(tunnel(encap_id=%s))' % encap_id)
        if act & FT_ACTION_DECAP:
            act &= ~FT_ACTION_DECAP
        if act & FT_ACTION_DROP:
            act &= ~FT_ACTION_DROP
            act1.append('drop')
        if act & FT_ACTION_FWD:
            self._ignore.append('destination_list_size')
            act &= ~FT_ACTION_FWD
            for i in range(int(self['destination_list_size'], 0)):
                self._ignore.append('destination[%d].destination_id' % i)
                self._ignore.append('destination[%d].destination_type' % i)
                self._ignore.append('destination[%d].dst_esw_owner_vhca_id' % i)
                dst_id = self['destination[%d].destination_id' % i] or '0x0'
                dst_type = self['destination[%d].destination_type' % i]
                dst_type0 = dst_type.split()[0]
                dst_esw_owner_vhca_id = self['destination[%d].dst_esw_owner_vhca_id' % i]
                if dst_esw_owner_vhca_id:
                    act1.append('esw(%s)' % dst_esw_owner_vhca_id)
                if dst_type0 == 'VPORT':
                    act1.append(self.port_name(dst_id))
                elif dst_type0 == 'TIR':
                    act1.append('TIR(%s)' % dst_id)
                elif dst_type0 == 'FLOW_TABLE_':
                    act1.append('FLOW_TABLE(%s)' % dst_id)
                else:
                    print 'ERROR: unsupported dst type %s dst id %s' % (dst_type, dst_id)
                    continue
        if act:
            print 'ERROR: unknown action %s' % act

        return ' action:%s' % ','.join(act1)

    def get_headers(self):
        return '%s_headers' % self._headers

    def set_headers(self, val):
        self._headers = val

    def colorize(self, out):
        ccc = {
            'table_id': 'yellow',
            'esw': 'green',
            'tunnel': 'blue',
            'in_port': 'yellow',
            'eth': 'blue',
            'eth_type': 'blue',
            'ipv4': 'green',
            'udp': 'magenta',
            'tcp': 'magenta',
            'action': 'red',
            'src': 'cyan',
            'dst': 'cyan',
        }

        if use_color:
            for word in ccc:
                word2 = colored(word, ccc[word])
                out = re.sub(r'\b(%s)\b' % word, word2, out)

        return out

    def __str__(self):
        a = self.attrs

        self._ignore = [
            'group_id',
            'table_id',
            'flow_index',
            'gvmi',
            'valid',
        ]

        x = []
        x.append(self.table_id)
        x.append(self.in_esw)
        self.set_headers('outer')
        x.append(self.vxlan)
        if self.is_vxlan:
            self.set_headers('inner')
        x.append(self.in_port)
        x.append(self.mac)
        x.append(self.vlan)
        y = []
        y.append(self.ethertype)
        y.append(self.ipv4)
        y.append(self.ports)
        y = list(filter(None, y))
        if self.is_vlan and y:
            x.append('encap(' + ','.join(y) + ')')
        else:
            x.extend(y)

        x.append(self.counter)
        x = list(filter(None, x))
        if not x:
            x.append('[No Match]')
        x.append(self.action)

        # find unmatches attrs
        for i in self._ignore:
            if i in a:
                del a[i]

        if a:
            print '  -Missed: %s' % ', '.join(a)

        x = list(filter(None, x))

        out = ','.join(x)

        if use_color:
            out = self.colorize(out)

        return out


def int2ip(addr):
    return socket.inet_ntoa(struct.pack("!I", addr))


def parse_args():
    parser = argparse.ArgumentParser()
    parser.add_argument('-s', '--sample', required=True,
                        help='Input sample file')
    parser.add_argument('-v', '--verbose', default=0, action='count',
                        help='Increase verbosity')
    parser.add_argument('-c', '--color', action='store_true',
                        help='Color output')
    parser.add_argument('-n', '--network', action='store_true', default=False,
                        help='Use network prefix instead of netmask')
    return parser.parse_args()


def parse_fs(sample):
    # - FG :gvmi=0x0,table_id=8,group_id=0x0 -
    group_re = re.compile('\s*- ([\w]+) :([\w,=]+)')
    group_keys_re = re.compile('(?:(\w+)=(\w+)),?')

    # action                                                                          :0x4
    # valid                                                                           :0x1
    # group_id                                                                        :0x00000004
    # destination_list_size                                                           :0x1
    # destination[0].destination_id                                                   :0x89
    # destination[0].destination_type                                                 :TIR (0x2)

    with open(sample, 'r') as f:
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
        if 'table_id' in attr:
            attr['table_id'] = int(attr['table_id'], 0)

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


def dump_all_ftes():
    _ftes = sorted(ftes, key = lambda r:r['table_id'])

    for fte in _ftes:
        if fte['table_id'] < 1000:
            # TODO: we currently only want the rules we add from userspace
            # ovs/tc. we create new fdb table which gets a high id number.
            continue

        try:
            print fte
        except Exception:
            print fte.attrs
            raise


def main():
    global verbose, use_color, NETADDR

    args = parse_args()

    if not (args.color and use_color):
        use_color = False
    if not (args.network and NETADDR):
        NETADDR = False
    if not sys.stdout.isatty():
        use_color = False

    verbose = args.verbose
    parse_fs(args.sample)
    dump_all_ftes()


if __name__ == "__main__":
    main()
