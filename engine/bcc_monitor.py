'''
START OF LICENSE STUB
    FineLame: Detecting Application-Layer Denial-of-Service Attacks
    Copyright (C) 2019 University of Pennsylvania

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <http://www.gnu.org/licenses/>.
END OF LICENSE STUB
'''

#!/usr/bin/python

from __future__ import print_function
from bcc import BPF, PerfType, PerfHWConfig
from bcc import DEBUG_SOURCE, DEBUG_PREPROCESSOR, DEBUG_LLVM_IR, DEBUG_BPF_REGISTER_STATE, DEBUG_BPF
from time import sleep, strftime
import argparse
from logger import *
import time
import pandas as pd
from ctypes import c_uint8, c_uint32

class FLMonitorException(Exception):
    pass

# p: probe, t: tracepoint
# k: kernel, u: user

class Monitor(object):
    def __init__(self, event, fn_name, is_ret, side='u', ptype='p', exec_path=None, sample_period=None):
        ''' A single EBPF probe on a single function
        side: 'k':kernel OR 'u':user
        type: 'p':probe OR 't':tracepoint
        '''
        if side == 'u':
            if ptype != 'p':
                raise FLMonitorException("Can only use probes on user-space functions")
            if exec_path is None:
                raise FLMonitorException("Must provide exec_path for user probes")

        if (ptype == 't' or side == 'k') and is_ret:
            raise FLMonitorException("RetProbes not available for kernel or tracepoints")

        if side not in ('k','u'):
            raise FLMonitorException("Side must be one of 'k', 'u', not %s" % side)

        if ptype not in ('p','t'):
            raise FLMonitorException("Type must be one of 'p', 't' not %s" % type)

        self.event = event
        self.fn_name = fn_name
        self.is_ret = is_ret
        self.exec_path = exec_path
        self.type = ptype
        self.side = side
        self.sp = sample_period

    def attach(self, ebpf):
        if self.side == 'k':
            if self.type == 'p':
                ebpf.attach_kprobe(event=self.event, fn_name=self.fn_name)
                log_info("Attached kprobe on %s", self.event)
            elif self.type == 't':
                ebpf.attach_tracepoint(tp=self.event, fn_name=self.fn_name)
                matched = ebpf.num_open_tracepoints()
                if matched < 0:
                    raise FLMonitorException("No function matched by %s", self.event)
                log_info("Attached tracepoint on %s", self.event)
            else:
                raise FLMonitorException("Unhandled type %s" % self.type)

        elif self.side == 'u':
            if self.is_ret:
                ebpf.attach_uretprobe(name=self.exec_path,
                                      sym=self.event,
                                      fn_name=self.fn_name)
                log_info("Attached uretprobe on %s", self.event)
            else:
                ebpf.attach_uprobe(name=self.exec_path,
                                   sym=self.event,
                                   fn_name=self.fn_name)
                log_info("Attached probe on %s", self.event)
        else:
            raise FLMonitorException("Unhandled side: %s" % self.side)

    def detach(self, ebpf):
        if self.side == 'k':
            if self.type == 'p':
                ebpf.detach_kprobe(event=self.event)
                log_info("Detached kprobe from %s", self.event)
            elif self.type == 't':
                ebpf.detach_tracepoint(tp=self.event)
                log_info("Detached tracepoint on %s", self.event)

        elif self.side == 'u':
            if self.is_ret:
                ebpf.detach_uretprobe(name=self.exec_path, sym=self.event)
                log_info("Detached uretprobe from %s", self.event)
            else:
                ebpf.detach_uprobe(name=self.exec_path, sym=self.event)
                log_info("Detached uprobe from %s", self.event)

    def attach_hw(self, ebpf):
        if self.sp is None:
            log_warn('No sample period given for this perf event. Setting it to 100')
            self.sp = 100
        try:
            ebpf.attach_perf_event(ev_type=PerfType.HARDWARE,
                                   ev_config=eval('PerfHWConfig.'+self.event), #XXX I think this is bad
                                   fn_name=self.fn_name, sample_period=self.sp, cpu=1)
        except Expection:
            log_error('Failed to attach hardware event {}'.format(self.event))

    def detach_hw(self, ebpf):
        ebpf.detach_perf_event(ev_type=PerfType.HARDWARE,
                               ev_config=eval('PerfHWConfig.'+self.event))
        log_info('Detached hardware monitor ({})'.format('PerfHWConfig.'+self.event))

class BCCMonitor():
    def __init__(self, ebpf_prog, request_stats, max_stats=1024):
        self.max_stats = max_stats
        self.monitors = []
        self.hw_monitors = []
        self.request_stats = request_stats
        try:
            self.ebpf = BPF(src_file=ebpf_prog, cflags=['-Wall'])
            #self.ebpf = BPF(src_file=ebpf_prog, cflags=['-Wall'], debug=DEBUG_BPF)#, '-Wsign-conversion'])#, '-ftrapv'])
        except Exception as e:
            log_info("ERROR WHEN PARSING EBPF PROG {}".format(ebpf_prog))
            raise

    def attach_hardware_monitor(self, cfg):
        log_info("Attaching a hardware monitor%s", cfg)

        monitor = Monitor(cfg['event'], cfg['fn_name'], False,
                          side='k', sample_period=cfg['sample_period'])
        monitor.attach_hw(self.ebpf)
        self.hw_monitors.append(monitor)

    def attach_resource_monitor(self, cfg):
        log_info("Attaching system monitor %s", cfg)
        if 'in_fn_name' in cfg:
            monitor = Monitor(cfg['event'], cfg['in_fn_name'], False,
                              cfg['side'], cfg['type'], cfg.get('exec_path', None))
            monitor.attach(self.ebpf)
            self.monitors.append(monitor)

        if 'ret_fn_name' in cfg:
            monitor = Monitor(cfg['event'], cfg['ret_fn_name'], True,
                              cfg['side'], cfg['type'], cfg.get('exec_path', None))
            monitor.attach(self.ebpf)
            self.monitors.append(monitor)

    def attach_application_monitor(self, exec_path, cfg):
        if 'in_fn_name' in cfg:
            monitor = Monitor(cfg['event'], cfg['in_fn_name'], False, exec_path=exec_path)
            monitor.attach(self.ebpf)
            self.monitors.append(monitor)
        if 'ret_fn_name' in cfg:
            monitor = Monitor(cfg['event'], cfg['ret_fn_name'], True, exec_path=exec_path)
            monitor.attach(self.ebpf)
            self.monitors.append(monitor)

    def detach_all_monitors(self):
        for monitor in self.monitors:
            monitor.detach(self.ebpf)
        for monitor in self.hw_monitors:
            monitor.detach_hw(self.ebpf)

    def get_request_stats(self):
        record_start = time.time()

        datapoints = self.ebpf['datapoints']

        buffer = []
        for dp_k, dp_v in datapoints.items():
            datapoint = dict(req_id = dp_k.value)
            for req_stat_name, req_stat in self.request_stats.items():
                datapoint[req_stat_name] = getattr(dp_v, req_stat['datapoint'])

            buffer.append(datapoint)

        log_info("Recorded data from eBPF map in %.1f seconds", time.time() - record_start)

        df = pd.DataFrame(buffer)

        return df
