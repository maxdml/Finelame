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

import yaml
import traceback
import pandas as pd
import numpy as np
import time
import os
import stat
import csv
import ctypes as ct
import signal
import sys
import shutil


#Finelame libs
from logger import *
from .bcc_monitor import BCCMonitor as BM, Monitor
from .notification import open_notify_buffer, poll_notification
from .ebpf_rewriter import rewrite_ebpf

#ML libs
from sklearn.cluster import KMeans
from sklearn.preprocessing import StandardScaler


class FinelameDetector():

    PCT_TRAIN_CLEAN = 99.99
    DEFAULT_M_SCALE = 10
    DEFAULT_S_SCALE = 6

    def __init__(self, model_params):
        log_info("Configuring Finelame anomaly detector")
        if 'k' not in model_params or 'features' not in model_params:
            raise Exception('FinelameDetector needs features description and model params (k for kmeans)')
        self.outlier_scores = dict()
        self.k = model_params['k']
        self.model = KMeans(n_clusters = model_params['k'])
        self.features = model_params['features']
        self.X_train_columns = ['req_id', "origin_ip", 'origin_ts', 'completion_ts'] + self.features
        self.X_train = None
        self.X_test = None

        self.scale_method = model_params.get('scale_method', 'exponent')
        self.m_scaler = model_params.get('m_scale', self.DEFAULT_M_SCALE)
        self.s_scaler = model_params.get('s_scale', self.DEFAULT_S_SCALE)

        if self.scale_method == 'exponent':
            self.m_scale = 10 ** self.m_scaler
            self.s_scale = 10 ** self.s_scaler
        elif self.scale_method == 'bitshift':
            self.m_scale = 1 << self.m_scaler
            self.s_scale = 1 << self.s_scaler
        else:
            raise Exception("Unknown scale method: %s" % scale_method)

    def set_train_data(self, x_train, do_clean=True):
        self.X_train = x_train

        if do_clean:
            for col in self.features:
                self.X_train = self.X_train[self.X_train[col] <=
                                            np.percentile(self.X_train[col], self.PCT_TRAIN_CLEAN)]

    def train_model(self, x_train=None):
        if x_train is None:
            self.model.fit(self.X_train)
        else:
            self.model.fit(x_train)

        self.X_train['cluster_label'] = self.model.labels_
        log_info('Trained KMeans model')

class Finelame():
    def __init__(self, cfg_file, run_label, outdir,
                 train_time=None, debug=False, ano_detect=False):
        self.outdir = outdir
        if not os.path.isdir(outdir):
            os.makedirs(outdir)

        self.cfg_file = cfg_file
        with open(cfg_file, 'r') as f:
            self.cfg = yaml.load(f)
        self.run_label = run_label

        self.FD = None
        self.train_time = None
        if ano_detect:
            ''' Anomaly detector params '''
            self.FD = FinelameDetector(model_params=self.cfg['model_params'])

            if train_time is not None and 'train_time' in self.cfg:
                log_warn("Warning: Ignoring config train time in favor of argument")
                self.train_time = train_time
            else:
                self.train_time = self.cfg.get('train_time', train_time)
            log_info("Setting train time to %d", self.train_time)
            self.mode = 'train'
        self.mode = 'monitoring'

        ''' Data collection params '''
        #XXX Finelame is made mostly for a single application as of now (hence the [0])
        ebpf_prog = rewrite_ebpf(self.cfg['ebpf_prog'], self.cfg['applications'][0], debug, detector=self.FD)
        self.BM = BM(ebpf_prog, self.cfg['request_stats'])

        self.resource_monitors = {}
        if 'resource_monitors' in self.cfg:
            self.resource_monitors = self.cfg['resource_monitors']
        self.hardware_monitors = {}
        if 'hardware_monitors' in self.cfg:
            self.hardware_monitors = self.cfg['hardware_monitors']
        if 'resource_monitors' not in self.cfg \
           and \
           'hardware_monitors' in self.cfg:
            log_error("Finelame needs events to monitor")
            sys.exit()

        self.applications = self.cfg['applications']
        self.start_ts = time.time() # in sec
        self.outlier_reports = list()

        ''' Register SIGINT handler '''
        signal.signal(signal.SIGINT, self._stop)
        self.is_running = False

    def _train_and_share_model(self):
        log_info('Training and sharing the model...')

        # Standardize data
        cols = self.FD.features
        scaler = StandardScaler()
        X_train = scaler.fit_transform(self.FD.X_train[cols])
        for i, feature in enumerate(cols):
            mean = scaler.mean_[i]
            std = scaler.scale_[i]
            log_info('Appending mean {} and std {} for feature {}'.format(mean, std, feature))
            mean *= self.FD.m_scale
            std *= self.FD.s_scale
            self.BM.ebpf['train_set_params'][i*2] = ct.c_ulonglong(int(mean))
            self.BM.ebpf['train_set_params'][i*2+1] = ct.c_ulonglong(int(std))

        c_scale = self.FD.m_scale / self.FD.s_scale

        #Train kmeans
        self.FD.train_model(x_train=X_train)

        #Share the (scaled) centroids with  the eBPF programs
        model = self.FD.model
        centroids = model.cluster_centers_
        centroids *= c_scale
        log_info('Scaled centroids:')
        log_info(centroids)
        thresholds = list()
        centroid_l1s = list()

        self.BM.ebpf['centroid_offset'][0] = ct.c_ulonglong(int(sum(scaler.mean_ / scaler.scale_) * c_scale))
        for k in range(0, len(centroids)):
            cluster_l1s = np.sum(X_train[model.labels_ == k], axis=1)
            precise_threshold = abs(cluster_l1s.mean() + 5 * cluster_l1s.std()) * c_scale
            threshold = ct.c_ulonglong(int(precise_threshold))
            log_info('Scaled [{}] threshold: {}'.format(k, precise_threshold))
            log_info('Shared [{}] threshold: {}'.format(k, threshold))
            centroid_l1 = ct.c_longlong(int(sum(centroids[k])))
            log_info('Centroid l1: {}'.format(sum(centroids[k])))
            thresholds.append(threshold)
            centroid_l1s.append(centroid_l1)

        log_info('Setting centroid L1 & cluster thresholds')
        for k in range(len(centroids)):
            self.BM.ebpf['cluster_thresholds'][k] = thresholds[k]
            self.BM.ebpf['centroid_l1s'][k] = centroid_l1s[k]

    '''
    Periodically pull data from eBPF map
    '''
    def _loop_iteration(self):
        if self.mode == 'train' \
           and time.time() - self.start_ts > self.train_time:

            self.mode = 'detection'
            x_train = self.BM.get_request_stats()

            if x_train.empty:
                log_info('Did not record any data. Resetting timer')
                self.mode = 'train'
                self.start_ts = time.time()
                return

            self.FD.set_train_data(x_train)

            self._train_and_share_model()

    def _loop(self):
        self.is_running = True
        while self.is_running:
            time.sleep(1)
            self._loop_iteration()
        log_info('Shutting down')

    '''
    Load config and start Finelame in training mode
    Initially we only know if sock_loc
    '''
    def start(self):
        log_info('Starting Finelame!')
        ''' Configure and deploy a monitor per statistic '''

        for monitor in self.resource_monitors:
            self.BM.attach_resource_monitor(monitor)

        for monitor in self.hardware_monitors:
            self.BM.attach_hardware_monitor(monitor)

        for application in self.applications:
            for monitor in application['monitors']:
                self.BM.attach_application_monitor(application['exec_path'], monitor)

        self._loop()

    def _stop(self, signal, frame):
        log_info('Stopping Finelame')
        self.BM.detach_all_monitors()

        '''
        #Check cache data
        for v in self.BM.ebpf['datapoints'].values():
            print("cputime: {}, cache misses: {}, cache refs: {}\n".format(
                v.cputime, v.cache_misses, v.cache_refs))
        '''

        #Retrieve request data if we are in monitoring mode only
        if self.mode == 'monitoring':
            data = self.BM.get_request_stats()
            if data.empty:
                log_info('Did not record any data. Resetting timer')
            #XXX dump those data to file

        # We might have training data if we are in either of those modes
        if self.mode == 'train' or self.mode == 'detection':
            #Dump training data to csv
            if self.FD.X_train is not None:
                fname = os.path.join(self.outdir, 'train_{}.csv'.format(self.run_label))
                log_info('Dumping train data into {}...'.format(fname))
                self.FD.X_train.to_csv(fname, index=False)

        #If we are in detection mode, we might have some AD data
        if self.mode == 'detection':
            record_start = time.time()
            log_info('Gathering test datapoints...')
            #Collect datapoints

            x_test = self.BM.get_request_stats()
            if not x_test.empty:
                fname = os.path.join(self.outdir, 'test_{}.csv'.format(self.run_label))
                log_info('Dumping test data into {}...'.format(fname))
                x_test.to_csv(fname, index=False)

            fname = os.path.join(self.outdir, 'scores_{}.csv'.format(self.run_label))
            log_info('Gathering outlier scores into {}...'.format(fname))
            with open(fname, 'w') as f:
                cols = "req_id,score,detection_ts,detection_cputime,last_ts,is_outlier,"
                cols += ','.join(['score_%d' % i for i in range(self.FD.k)])
                f.write(cols + '\n')
                for k, v in self.BM.ebpf['outlier_scores_m'].items():
                    dists = v.distances
                    abs_dists = np.array([abs(d) for d in dists])
                    idx = np.where(abs_dists == min(abs_dists))[0][0]
                    min_dist = dists[idx]

                    f.write(','.join([str(x) for x in
                        [int(k.value), min_dist, v.detection_ts,v.detection_cputime,v.last_ts, v.is_outlier] + list(dists)
                    ]) + '\n')

            fname = os.path.join(self.outdir, 'normalization_{}.csv'.format(self.run_label))
            log_info("Gathering normalization data into {}".format(fname))
            with open(fname, 'w') as f:
                f.write("feature,mean,std\n")
                mean_std = [v.value for v in self.BM.ebpf['train_set_params'].values()]
                for i, ft_name in enumerate(self.FD.features):
                    f.write('{},{},{}\n'.format(ft_name, mean_std[i*2], mean_std[i*2+1]))

            fname =os.path.join(self.outdir, "clusters_{}.csv".format(self.run_label))
            log_info("Gathering cluster data into {}".format(fname))
            with open(fname, 'w') as f:
                f.write('l1,threshold\n')
                for thresh, l1 in zip(self.BM.ebpf['cluster_thresholds'].values(),
                                      self.BM.ebpf['centroid_l1s'].values()):
                    f.write('{},{}\n'.format(l1.value, thresh.value))

            fname = os.path.join(self.outdir, 'model_params_{}.csv'.format(self.run_label))
            log_info('Gathering model parameters into {}...'.format(fname))
            with open(fname, 'w') as f:
                mean_std = [v.value for v in self.BM.ebpf['train_set_params'].values()]
                f.write('{}\n'.format(mean_std))
                for k, v in self.BM.ebpf['cluster_thresholds'].items():
                    f.write('[k{}] {}\n'.format(k, v))

            shutil.copyfile(self.cfg_file,
                            os.path.join(self.outdir, 'fl_cfg_{}.yml'.format(self.run_label)))

        self.is_running = False
