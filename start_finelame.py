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
    args = parser.parse_args()

    sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    from engine.finelame import Finelame

    FL = Finelame(cfg_file=args.config_file,
                  run_label=args.run_label,
                  outdir=args.out,
                  train_time = args.train_time,
                  debug=args.debug)
    FL.start()
