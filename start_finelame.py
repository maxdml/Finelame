#!/usr/bin/python
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

import sys
import os
import argparse

if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('config_file', help='config file')
    parser.add_argument('run_label', help='label for output data files')
    parser.add_argument('--out', default='.', help='Output directory')
    parser.add_argument('--train-time', default=None, type=float, help='Number of seconds to train')
    parser.add_argument('--debug', action="store_true",  default=False, help='Turn on /sys/kernel/debug/tracing/trace_pipe debugging')
    parser.add_argument('--ano-detect', action="store_true",  default=False, help='Perform anomaly detection')
    args = parser.parse_args()

    sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    from engine.finelame import Finelame

    FL = Finelame(cfg_file=args.config_file,
                  run_label=args.run_label,
                  outdir=args.out,
                  train_time = args.train_time,
                  debug=args.debug,
                  ano_detect = args.ano_detect)
    FL.start()
