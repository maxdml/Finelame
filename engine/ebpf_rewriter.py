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

import os

def sub_debug(src, debug):
    return src.replace("$DEBUG_PRINTK", "bpf_trace_printk" if debug else "IGNORE")

def sub_k(src, detector):
    return src.replace("$K", str(detector.k))

def sub_mscale(src, detector):

    if detector.scale_method == 'exponent':
        insertion = ' * %d ' % detector.m_scale
    elif detector.scale_method == 'bitshift':
        insertion = ' << %d ' % detector.m_scaler

    while '$MSCALE(' in src:
        start = src.find("$MSCALE(")
        endparens = src.find(')', start)
        src = src[:endparens+1] + insertion + src[endparens+1:]
        src = src.replace("$MSCALE", "", 1)
    return src


def rewrite_ebpf(src_file, detector, debug, suffix="_rewritten"):
    with open(src_file) as f:
        src = f.read()

    src = sub_debug(src, debug)
    src = sub_k(src, detector)
    src = sub_mscale(src, detector)

    path, ext = os.path.splitext(src_file)
    dst_file = path+suffix+ext

    with open(dst_file, 'w') as f:
        f.write(src)

    return dst_file
