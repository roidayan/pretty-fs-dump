#!/usr/bin/python

from __future__ import print_function

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

# actions
FT_ACTION_ALLOW   = 1 << 0
FT_ACTION_DROP    = 1 << 1
FT_ACTION_FWD     = 1 << 2
FT_ACTION_COUNT   = 1 << 3
FT_ACTION_ENCAP   = 1 << 4
FT_ACTION_DECAP   = 1 << 5
FT_ACTION_MOD_HDR = 1 << 6

FT_ACTION_VLAN_POP  = 0x80
FT_ACTION_VLAN_PUSH = 0x100
FT_ACTION_VLAN_POP_2  = 0x400
FT_ACTION_VLAN_PUSH_2 = 0x800


# table types
NIC_RX = '0x0'
NIC_TX = '0x1'
ESwitch_egress_ACL = '0x2'
ESwitch_ingress_ACL = '0x3'
ESwitch_FDB = '0x4'
Nic_Sniffer_Rx = '0x5'
Nic_Sniffer_Tx = '0x6'
NIC_RX_RDMA = '0x7'
NIC_TX_RDMA = '0x8'

def table_type_str(ft_type):
    types = {
        '0x0': 'NIC_RX',
        '0x1': 'NIC_TX',
        '0x2': 'ESwitch_egress_ACL',
        '0x3': 'ESwitch_ingress_ACL',
        '0x4': 'ESwitch_FDB',
        '0x5': 'Nic_Sniffer_Rx',
        '0x6': 'Nic_Sniffer_Tx',
        '0x7': 'NIC_RX_RDMA',
        '0x8': 'NIC_TX_RDMA',
    }
    if not ft_type:
        ft_type = '0x0'
    return types.get(ft_type)


def default_miss_table(ft_type):
    types = {
        '0x0': 'drop',
        '0x1': 'fwd(NIC_vport,tx)',
        '0x2': 'fwd(NIC_vport,rx)',
        '0x3': 'fwd(FDB)',
        '0x4': 'default(ESwitch_FDB)',
        '0x5': 'drop',
        '0x6': 'drop',
        '0x7': 'RDMA_Transport_Offload',
        '0x8': 'transmit',
    }
    if not ft_type:
        ft_type = '0x0'
    return types.get(ft_type)


def colorize(out):
    if not use_color:
        return out

    ccc = {
        'table_id':   'yellow',
        'table_type': 'yellow',
        'FLOW_TABLE': 'yellow',
        'default':    'yellow',
        'level':      'yellow',
        'esw':      'green',
        'uplink':   'green',
        'vport':    'green',
        'vport0':   'green',
        'vport1':   'green',
        'vport2':   'green',
        'vport3':   'green',
        'vport4':   'green',
        'vport5':   'green',
        'tunnel':   'blue',
        'encap_id':   'green',
        'mod_hdr_id': 'green',
        'flow_tag':   'green',
        'allow':      'yellow',
        'set':        'yellow',
        'unset':      'yellow',
        'reg_c_0':    'yellow',
        'reg_c_1':    'yellow',
        'reg_c_2':    'yellow',
        'reg_c_3':    'yellow',
        'reg_c_4':    'yellow',
        'reg_c_5':    'yellow',
        'in_port':    'yellow',
        'source_sqn': 'yellow',
        'eth':        'blue',
        'eth_type':   'blue',
        'ipv4':       'green',
        'ipv6':       'green',
        'udp':        'magenta',
        'tcp':        'magenta',
        'tcp_flags':  'magenta',
        'action':   'red',
        'src':      'cyan',
        'dst':      'cyan',
        'tp_src':   'cyan',
        'tp_dst':   'cyan',
        'tun_id':   'cyan',
        'geneve':   'cyan',
        'tos':      'cyan',
        'frag':     'cyan',
        'proto':    'cyan',
        'dscp':     'cyan',
        'encap_en': 'yellow',
        'decap_en': 'yellow',
        'reformat_en': 'yellow',
    }

    for word in ccc:
        word2 = colored(word, ccc[word])
        out = re.sub(r'\b(%s)\b' % word, word2, out)

    # special
    out = re.sub(r'\?', colored('?', 'red'), out)

    return out


class Flow(object):
    def __init__(self, attr):
        self.attr = attr
        self.fgs = [] # hold related fgs
        self.ftes = [] # hold related ftes
        self.tree = False
        self._skip = []

    def skip(self, key):
        self._skip.append(key)

    @property
    def attrs(self):
        return self.attr.copy()

    def __getitem__(self, key):
        return self.attr.get(key, None)

    @property
    def table_id(self):
        if 'table_id' in self._skip:
            return
        return 'table_id(0x%x)' % self.attr['table_id']


class FlowTable(Flow):
    def __init__(self, attr):
        super(FlowTable, self).__init__(attr)
        if 'table_type' not in attr:
            attr['table_type'] = '0x0'

    def add_fg(self, fg):
        self.fgs.append(fg)

    def add_fte(self, fte):
        self.ftes.append(fte)

    @property
    def ft_type(self):
        return 'table_type(%s)' % table_type_str(self['table_type'])

    @property
    def level(self):
        level = self['level'] or '0x0'
        return 'level(%s)' % level

    @property
    def action(self):
        act1 = []

        if self['table_miss_mode'] == '0x1':
            dst_id = self['table_miss_id'] or '0x0'
            dst_id = 'FLOW_TABLE(%s)' % dst_id
        else:
            dst_id = default_miss_table(self['table_type'])

        act1.append(dst_id)

        return ' action:%s' % ','.join(act1)

    @property
    def en_attrs(self):
        en = []
        for key in self.attr.keys():
            if key.endswith('_en'):
                en.append('%s(%s)' % (key, self[key]))

        return en

    def get_ftes(self):
        out = ""
        for fte in self.ftes:
            fte.skip('table_id')
            out += "\n  |_%s" % fte
        return out

    def __str__(self):
        out = []
        out.append(self.ft_type)
        out.append(self.table_id)
        out.append(self.level)
        out.extend(self.en_attrs)
        out.append(self.action)
        out = ','.join(out)
        out = colorize(out)
        if self.tree:
            out += self.get_ftes()
        return out


class FlowGroup(Flow):
    pass


class FlowTableEntry(Flow):
    def get_mask(self, key):
        try:
            return self.group[key] or '0x0'
        except KeyError:
            return '0x0'

    @property
    def group(self):
        try:
            return fgs[self['group_id']]
        except KeyError:
            #print('ERROR: canot find group id 0x%x' % self['group_id'])
            return {}

    @property
    def ethertype_raw(self):
        k = '%s.ethertype' % self.get_headers()
        self._ignore.append(k)
        ethertype = self[k]
        if not ethertype:
            return
        return ethertype

    @property
    def ethertype(self):
        ethertype = self.ethertype_raw
        if not ethertype:
            return
        eth_type = '0x' + ethertype[2:].zfill(4)
        # TODO: in verbose print tcp,udp,arp,etc
        return 'eth_type(%s)' % eth_type

    @property
    def ip_dscp(self):
        k = '%s.ip_dscp' % self.get_headers()
        self._ignore.append(k)
        dscp = self[k]
        if not dscp:
            return
        mask = self.get_mask(k)
        return 'dscp=%s/%s' % (dscp, mask)

    @property
    def ip_version_raw(self):
        k = self.get_headers() + '.ip_version'
        self._ignore.append(k)
        ip_ver_mask = self.get_mask(k)
        if not ip_ver_mask or ip_ver_mask == '0x0':
            return
        ip_ver = self[k]
        ip_ver = int(ip_ver, 0)
        return ip_ver

    @property
    def ip_version(self):
        ip_ver = self.ip_version_raw
        if not ip_ver:
            return
        ip_proto = self.ip_proto
        items = []
        if ip_proto:
            items.append('proto=%s' % ip_proto)
        return 'ipv%s(%s)' % (ip_ver, ','.join(items))

    @property
    def ip_proto(self):
        try:
            ip_proto = str(int(self[self.get_headers() + '.ip_protocol'], 0))
            ip_proto_mask = self.get_mask(self.get_headers() + '.ip_protocol')
            if ip_proto_mask != '0xff':
                ip_proto += '/' + ip_proto_mask
            self._ignore.append(self.get_headers() + '.ip_protocol')
        except TypeError:
            ip_proto = None
        return ip_proto

    @property
    def ipv4(self):
        if not self.ip_version_raw and not self.ethertype_raw:
            return

        items = []

        def get_ip6(x):
            headers = self.get_headers()
            key1 = headers + '.' + x + '_ip_31_0'
            key2 = headers + '.' + x + '_ip_63_32'
            key3 = headers + '.' + x + '_ip_95_64'
            key4 = headers + '.' + x + '_ip_127_96'
            self._ignore.append(key1)
            self._ignore.append(key2)
            self._ignore.append(key3)
            self._ignore.append(key4)
            p1 = self[key1] or '0x00000000'
            p2 = self[key2] or '0x00000000'
            p3 = self[key3] or '0x00000000'
            p4 = self[key4] or '0x00000000'
            p1 = p1[2:].lstrip('0')
            p2 = p2[2:].lstrip('0')
            p3 = p3[2:].lstrip('0')
            p4 = p4[2:].lstrip('0')
            return "%s:%s:%s:%s" % (p4, p3, p2, p1)

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

        def get_frag():
            frag = None
            frag_mask = self.get_mask(self.get_headers() + '.frag')
            if frag_mask != '0x0':
                frag = 'yes' if self[self.get_headers() + '.frag'] else 'no'
            self._ignore.append(self.get_headers() + '.frag')
            return frag

        def get_ip_ver():
            ip_ver = self.ip_version_raw
            if not ip_ver:
                ethertype = self.ethertype_raw
                if ethertype == '0x86dd':
                    return 'ipv6'
                return 'ipv4'
            if ip_ver == 6:
                return 'ipv6'
            return 'ipv4'

        ip_ver = get_ip_ver()
        ip_proto = self.ip_proto
        frag = get_frag()

        if ip_ver == 'ipv6':
            src = get_ip6('src')
            dst = get_ip6('dst')
        else:
            src = get_ip(self.get_headers() + '.src_ip_31_0')
            dst = get_ip(self.get_headers() + '.dst_ip_31_0')

        if src:
            items.append('src='+src)
        if dst:
            items.append('dst='+dst)
        if ip_proto:
            items.append('proto=%s' % ip_proto)
        if frag:
            items.append('frag=%s' % frag)

        ip_dscp = self.ip_dscp
        if ip_dscp:
            items.append(ip_dscp)

        if items:
            ip_ver += '(%s)' % ','.join(items)

        return ip_ver

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
    def tcp_flags(self):
        flags = None
        mask = self.get_mask(self.get_headers() + '.tcp_flags')
        if mask != '0x0':
            flags = self[self.get_headers() + '.tcp_flags'] or '0'
            flags = 'tcp_flags(%s/%s)' % (flags, mask)
        self._ignore.append(self.get_headers() + '.tcp_flags')
        return flags

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
    def flow_tag(self):
        self._ignore.append('flow_tag')
        return self['flow_tag']

    @property
    def is_vlan(self):
        return (self.get_mask('outer_headers.cvlan_tag') != '0x0' and
                self['outer_headers.first_vid'])

    @property
    def vlan(self):
        if not self.is_vlan:
            return

        self._ignore.append('outer_headers.cvlan_tag')

        def get_vlan():
            vid = self['outer_headers.first_vid']
            if not vid:
                return 0
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
    def is_geneve(self):
        return self['misc_parameters.geneve_vni'] is not None

    @property
    def is_tunnel(self):
        return self.is_vxlan or self.is_geneve

    @property
    def tos(self):
        ecn = int(self['outer_headers.ip_ecn'] or '0', 0)
        ecn_mask = int(self.get_mask('outer_headers.ip_ecn'), 0)
        dscp = int(self['outer_headers.ip_dscp'] or '0', 0)
        dscp_mask = int(self.get_mask('outer_headers.ip_dscp'), 0)
        key = hex((dscp << 2) | ecn)
        mask = hex((dscp_mask << 2) | ecn_mask)
        if key != '0x0' or mask != '0x0':
            return 'tos=%s/%s' % (key, mask)

    @property
    def tunnel(self):
        """
        tunnel(tun_id=0x01,src=1.2.3.4,dst=1.2.3.4,tp_src=4789,tp_dst=4789,ttl=128)
        """

        if not self.is_tunnel:
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

        if self.is_vxlan:
            vni = get('tun_id', 'misc_parameters.vxlan_vni', 3)
        else:
            vni = get('tun_id', 'misc_parameters.geneve_vni', 3)

        items.append(vni)
        items.append(self.tos)
        items.append(self.mac)
        items.append(self.ip_version)
        items.append(self.ipv4)
        # no need to show outer ethertype for tunnel.
        self.ethertype

        sport = self.get_port('outer_headers.udp_sport')
        if sport:
            items.append('tp_src=%s' % sport)
        dport = self.get_port('outer_headers.udp_dport')
        if dport:
            items.append('tp_dst=%s' % dport)

        if self.is_geneve:
            proto = get('protocol_type', 'misc_parameters.geneve_protocol_type', 3)
            geneve_opts = ''
            items.append('geneve(%s)' % geneve_opts)

        items = list(filter(None, items))
        if not items:
            return
        return 'tunnel(%s)' % ','.join(items)

    def port_name(self, port):
        if verbose < 1:
            return 'vport(%s)' % port

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
    def source_sqn(self):
        self._ignore.append('misc_parameters.source_sqn')

        val = self['misc_parameters.source_sqn']
        if not val:
            if self.get_mask('misc_parameters.source_sqn') != '0x0':
                val = '0'
            else:
                return ''
        return 'source_sqn(%s)' % val

    @property
    def metadata_reg_c(self):
        regs = []
        for i in range(8):
            reg = 'reg_c_%s' % i
            k = 'misc_2_parameters.metadata_%s' % reg
            self._ignore.append(k)
            m = self.get_mask(k)
            if m != '0x0':
                regs.append('%s(%s/%s)' % (reg, '?', m))
        return regs

    @property
    def in_port(self):
        self._ignore.append('misc_parameters.source_port')

        port = self['misc_parameters.source_port']
        if not port:
            if self.get_mask('misc_parameters.source_port') != '0x0':
                port = '0'
            else:
                return ''
        return 'in_port(%s)' % self.port_name(port)

    @property
    def counter(self):
        self._ignore.append('flow_counter_list_size')
        counters = []

        # counter id starts from last destination id
        dst_size = int(self['destination_list_size'] or '0', 0)
        size = int(self['flow_counter_list_size'] or '0', 0)
        for i in range(dst_size, size+dst_size):
            self._ignore.append('flow_counter[%d].flow_counter_id' % i)
            counters.append(self['flow_counter[%d].flow_counter_id' % i])

        if verbose < 2 or not counters:
            return

        return ' counters:%s' % ','.join(counters)

    @property
    def action(self):
        self._ignore.append('action')
        act = int(self['action'], 16)
        act &= ~FT_ACTION_COUNT
        act1 = []

        if self.flow_tag:
            act1.append('set(flow_tag=%s)' % self.flow_tag)
        if act & FT_ACTION_VLAN_POP:
            act &= ~FT_ACTION_VLAN_POP
            act1.append('pop_vlan')
        if act & FT_ACTION_VLAN_POP_2:
            act &= ~FT_ACTION_VLAN_POP_2
            act1.append('pop_vlan2')
        if act & FT_ACTION_VLAN_PUSH:
            act &= ~FT_ACTION_VLAN_PUSH
            self._ignore.append('push_vlan_tag.tpid')
            self._ignore.append('push_vlan_tag.vid')
            tpid = self['push_vlan_tag.tpid']
            vid = str(int(self['push_vlan_tag.vid'], 0))
            act1.append('push_vlan(vid=%s,tpid=%s)' % (vid, tpid))
        if act & FT_ACTION_ENCAP:
            act &= ~FT_ACTION_ENCAP
            self._ignore.append('encap_id')
            encap_id = self['encap_id'] or '0x0'
            act1.append('set(tunnel(encap_id=%s))' % encap_id)
        if act & FT_ACTION_DECAP:
            act &= ~FT_ACTION_DECAP
            act1.append('unset(tunnel)')
        if act & FT_ACTION_MOD_HDR:
            act &= ~FT_ACTION_MOD_HDR
            self._ignore.append('modify_header_id')
            mod_hdr_id = self['modify_header_id'] or '0x0'
            act1.append('set(mod_hdr_id=%s)' % mod_hdr_id)
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
                self._ignore.append('destination[%d].dst_esw_owner_vhca_id_valid' % i)
                dst_id = self['destination[%d].destination_id' % i] or '0x0'
                dst_type = self['destination[%d].destination_type' % i]
                dst_type0 = dst_type.split()[0]
                dst_esw_owner_vhca_id = self['destination[%d].dst_esw_owner_vhca_id' % i]
                dst_esw_owner_vhca_id_valid = self['destination[%d].dst_esw_owner_vhca_id_valid' % i]
                if dst_esw_owner_vhca_id_valid == '0x1' and not dst_esw_owner_vhca_id:
                    dst_esw_owner_vhca_id = '0x0'
                if dst_esw_owner_vhca_id:
                    act1.append('esw(%s)' % dst_esw_owner_vhca_id)
                if dst_type0 == 'VPORT':
                    act1.append(self.port_name(dst_id))
                elif dst_type0 == 'TIR':
                    act1.append('TIR(%s)' % dst_id)
                elif dst_type0 == 'FLOW_TABLE_':
                    act1.append('FLOW_TABLE(%s)' % dst_id)
                else:
                    print('ERROR: unsupported dst type %s dst id %s' % (dst_type, dst_id))
                    continue
        if act & FT_ACTION_ALLOW:
            act &= ~FT_ACTION_ALLOW
            act1.append('allow')

        if act:
            print('ERROR: unknown action %s' % hex(act))

        return ' action:%s' % ','.join(act1)

    def get_headers(self):
        return '%s_headers' % self._headers

    def set_headers(self, val):
        self._headers = val

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
        x.append(self.tunnel)
        if self.is_tunnel:
            self.set_headers('inner')
        x.extend(self.metadata_reg_c)
        x.append(self.in_port)
        x.append(self.source_sqn)
        x.append(self.mac)
        x.append(self.vlan)
        y = []
        y.append(self.ethertype)
        y.append(self.ip_version)
        y.append(self.ipv4)
        y.append(self.ports)
        y.append(self.tcp_flags)
        # check also inner headers even if not tunnel
        if not self.is_tunnel:
            self.set_headers('inner')
            y.append(self.ip_version)
            y.append(self.ipv4)
            y.append(self.tcp_flags)

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
            print('  -Missed: %s' % ', '.join(a))

        x = list(filter(None, x))

        out = ','.join(x)
        out = colorize(out)
        return out


def int2ip(addr):
    return socket.inet_ntoa(struct.pack("!I", addr))


def parse_args():
    parser = argparse.ArgumentParser()
    parser.add_argument('-s', '--sample', required=True,
                        help='Input sample file')
    parser.add_argument('-v', '--verbose', default=0, action='count',
                        help='Increase verbosity')
    parser.add_argument('-n', '--network', action='store_true', default=False,
                        help='Use network prefix instead of netmask')
    parser.add_argument('-t', '--tree', action='store_true', default=False,
                        help='Print tree style')
    parser.add_argument('--nocolor', action='store_true',
                        help='No color output')
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

    try:
        with open(sample, 'r') as f:
            data = f.read().split("\n\n")
    except IOError as e:
        print(e)
        sys.exit(1)

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
            fts[fg['table_id']].add_fg(fg)
        elif group == 'FT':
            ft = FlowTable(attr)
            fts[ft['table_id']] = ft
        elif group == 'FTE':
            attr.setdefault('group_id', 0)
            fte = FlowTableEntry(attr)
            ftes.append(fte)
            fts[fte['table_id']].add_fte(fte)
        else:
            print('ERROR: unknown type %s' % group)


def dump_all_fts(tree=False):
    _fts = sorted(fts, key=lambda r:(fts[r]['table_type'], r))

    for ft_id in _fts:
        if ft_id < 1000 and verbose < 4:
            continue
        ft = fts[ft_id]
        try:
            if tree:
                ft.tree = True
            print(ft)
        except Exception:
            print(ft.attrs)
            raise


def dump_all_ftes():
    _ftes = sorted(ftes, key=lambda r:r['table_id'])

    for fte in _ftes:
        if fte['table_id'] < 1000 and verbose < 4:
            # TODO: we currently only want the rules we add from userspace
            # ovs/tc. we create new fdb table which gets a high id number.
            continue

        try:
            print(fte)
        except Exception:
            print(fte.attrs)
            raise


def main():
    global verbose, use_color, NETADDR

    args = parse_args()

    if args.nocolor:
        use_color = False
    if not (args.network and NETADDR):
        NETADDR = False
    if not sys.stdout.isatty():
        use_color = False

    verbose = args.verbose
    parse_fs(args.sample)
    dump_all_fts(args.tree)
    if not args.tree:
        dump_all_ftes()


if __name__ == "__main__":
    main()
