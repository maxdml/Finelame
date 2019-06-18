/*
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
*/

#include <uapi/linux/ptrace.h>
#include <linux/sched.h>
#include <uapi/linux/bpf.h>
#include <net/sock.h>

/**
 * Features order:
        - 'REQ_CPUTIME'
        - 'REQ_MEM_MALLOC'
        - 'REQ_PGFLT'
        - 'REQ_IDLE_TIME'
        - 'REQ_TCP_SENT'
        - 'REQ_TCP_RCVD'
 */

#define MAX_TIDS 32
#define K $K
#define N_FEATURES 6
#define MAX_DATAPOINTS 4194304

// DO NOT REMOVE: Used for ebpf_rewriter
#define IGNORE(...)

struct datapoint {
    u64 latest_ts_update;
    u64 cputime;
    u64 pgfaults;
    size_t tcp_sent;
    size_t tcp_rcvd;
    u64 last_tcp_rcv_ts;
    u64 tcp_idle_time;
    size_t mem_malloc;
    u64 first_ts;
    u32 saddr;
    int n_cputime_updates;
};

#define CPUTIME_OFFSET 0
#define MALLOC_OFFSET 1
#define PGFAULT_OFFSET 2
#define IDLE_TIME_OFFSET 3
#define TCP_SENT_OFFSET 4
#define TCP_RCVD_OFFSET 5

struct outlier_score {
    long long distances[K];
    u8 is_outlier;
    u64 detection_ts;
    u64 last_ts;
    u64 detection_cputime;
};

BPF_ARRAY(max_rid, int, 1);
BPF_HASH(assoc_to_rid, unsigned long, int, MAX_DATAPOINTS);
BPF_HASH(tid_to_rid, u32, int);
BPF_HASH(start, u32, u64);
BPF_HASH(datapoints, int, struct datapoint, MAX_DATAPOINTS);
BPF_HASH(outlier_scores_m, int, struct outlier_score, MAX_DATAPOINTS);

/** Model params */
BPF_ARRAY(cluster_thresholds, u64, K);
BPF_ARRAY(centroid_l1s, long long, K);
BPF_ARRAY(centroid_offset, long long, 1);
BPF_ARRAY(train_set_params, u64, N_FEATURES * 2); // Mean and std of each feature in the training set

static inline long long normalize_datapoint(long long dp, int offset) {
    //$DEBUG_PRINTK("to normalize dp: %lld\n", dp);
    if (dp == 0) {
        return 0;
    }

    u64 *mean, *std_p;
    int meanidx = offset * 2;
    int stdidx = offset * 2 + 1;
    mean = train_set_params.lookup(&meanidx);
    std_p = train_set_params.lookup(&stdidx);

    if (!mean || !std_p) {
        return 0;
    }

    u64 std = *std_p;
    if (std == 0) {
        std = 10000;
    }

    long long scaled = $MSCALE(dp);
    //$DEBUG_PRINTK("Scaled dp: %lld, mean: %lld, std: %lld\n", scaled, *mean, std);
    //scaled -= *mean;
    //$DEBUG_PRINTK("-mean: %lld\n", scaled);
    if (scaled < 0) {
        scaled *= -1;
        scaled /= std;
        scaled *= -1;
    } else {
        scaled /= std;
    }
    //$DEBUG_PRINTK("/std: %lld\n", scaled);

    return scaled;
}

static inline int centroids_defined() {
    int idx = 0;
    long long *k0_l1 = centroid_l1s.lookup(&idx);
    return k0_l1 && *k0_l1;
}

static inline int update_outlier_score(struct pt_regs *ctx, int req_id, long long delta, u64 ts, u64 cputime) {
    //$DEBUG_PRINTK("Delta is %lld\n", delta);
    struct outlier_score *out = outlier_scores_m.lookup(&req_id);
    if (!out) {
        struct outlier_score init_out = {};
        int off_i = 0;
        long long *centroid_offset_p = centroid_offset.lookup(&off_i);
        if (!centroid_offset_p) {
            return -1;
        }

#pragma unroll
        for (int i = 0; i < K; i++) {
            // Must assign i to new variable, else reference to i
            // makes it so loop can't be unrolled
            int j = i;
            long long *centroid = centroid_l1s.lookup(&j);
            if (centroid) {
                init_out.distances[i] = -(*centroid) - (*centroid_offset_p);
            } else {
                $DEBUG_PRINTK("Centroid %d not defined", i);
            }
        }
        out = outlier_scores_m.lookup_or_init(&req_id, &init_out);
    }

    long long min_dist = (1LL) << 62; // A very large number...
    int is_outlier = 0;

#pragma unroll
    for (int idx = 0; idx < K; idx++) {
        int idx_cp = idx;
        //$DEBUG_PRINTK("dist[0]: %lld + delta = %lld\n", out->distances[0], out->distances[0]+delta);
        // I don't know why two threads would be running this code concurrently,
        // but this locking prevents discrepancies between cluster scores
        lock_xadd(&out->distances[idx], delta);
        //$DEBUG_PRINTK("dist[0]: is now %lld\n", out->distances[0]);
        if (abs(out->distances[idx]) < abs(min_dist)) {
            u64 *threshold = cluster_thresholds.lookup(&idx_cp);
            if (threshold && *threshold != 0) {
                min_dist = out->distances[idx];
                if (min_dist > 0 && min_dist > *threshold) {
                    is_outlier = 1;
                } else {
                    is_outlier = 0;
                }
                $DEBUG_PRINTK("Distance to %d(%lld) is: %lld\n", idx, *threshold, min_dist);
                $DEBUG_PRINTK("[%d] is outlier? %d.\n", req_id, is_outlier);
            }
        }
    }

    $DEBUG_PRINTK("[%d] final decision: %d\n", req_id, is_outlier);

    out->is_outlier = is_outlier;

    if (out->detection_ts == 0 && is_outlier) {
        out->detection_ts = ts;
        out->detection_cputime = cputime;
    }

    out->last_ts = ts;

    return 0;
}

static struct datapoint * lookup_or_init_dp(int req_id, u64 ts) {
    struct datapoint *dp = datapoints.lookup(&req_id);
    if (dp) {
        dp->latest_ts_update = ts;
        return dp;
    }
    struct datapoint new_dp = {};
    new_dp.first_ts = ts;
    new_dp.latest_ts_update = ts;
    return datapoints.lookup_or_init(&req_id, &new_dp);
}

static inline int update_array(struct pt_regs *ctx, u32 pid, u64 ts, int req_id) {
    u64 *tsp = start.lookup(&pid);
    if (tsp == 0) {
        return -1;
    }
    if (ts < *tsp) {
        // Probably a clock issue where the recorded on-CPU event had a
        // timestamp later than the recorded off-CPU event, or vice versa.
        return -1;
    }

    u64 delta = ts - *tsp;

    struct datapoint *dp = lookup_or_init_dp(req_id, ts);
    if (!dp) {
        return -1;
    }

    lock_xadd(&dp->n_cputime_updates, 1);
    lock_xadd(&dp->cputime, delta);

    $DEBUG_PRINTK("RID [%d]: CPUTIME: %lld\n", req_id, dp->cputime);
    if (centroids_defined()) {
        long long delta_scaled = normalize_datapoint(delta, CPUTIME_OFFSET);
        update_outlier_score(ctx, req_id, delta_scaled, ts, dp->cputime);
    }
    return 0;
}

int update_cputime(struct pt_regs *ctx) {
    u32 pid = bpf_get_current_pid_tgid();
    int *req_id = tid_to_rid.lookup(&pid);
    if (!req_id) {
        return 0;
    }
    u64 ts = bpf_ktime_get_ns();
    update_array(ctx, pid, ts, *req_id);
    start.update(&pid, &ts);
    return 0;
}

int sched_switch(struct pt_regs *ctx, struct task_struct *prev) {
    //PID is stored in the first 32 LS bytes. (TGID are the next 32 bytes)
    u32 prev_pid = prev->pid;
    int *prev_req_id = tid_to_rid.lookup(&prev_pid);
    if (prev_req_id) {
        u64 ts = bpf_ktime_get_ns();
        update_array(ctx, prev_pid, ts, *prev_req_id);
    }
    u32 pid = bpf_get_current_pid_tgid();
    int *req_id = tid_to_rid.lookup(&pid);
    if (req_id) {
        u64 ts = bpf_ktime_get_ns();
        start.update(&pid, &ts);
    }
    return 0;
}

int handle_pg_fault(struct pt_regs *ctx) {
    u32 pid = bpf_get_current_pid_tgid();
    int *req_id = tid_to_rid.lookup(&pid);

    if (!req_id) {
        return 0;
    }

    u64 ts = bpf_ktime_get_ns();

    struct datapoint *dp = lookup_or_init_dp(*req_id, ts);
    if (!dp) {
        return 0;
    }
    dp->pgfaults++;

    $DEBUG_PRINTK("RID: [%d] PGFAULTS: %d\n", *req_id, dp->pgfaults);
    if (centroids_defined()) {
        long long delta = normalize_datapoint(1, PGFAULT_OFFSET);
        update_outlier_score(ctx, *req_id, delta, ts, dp->cputime);
    }
    return 0;
}


int ap_probe_malloc(struct pt_regs *ctx) {
    u32 pid = bpf_get_current_pid_tgid();
    int *req_id_p = tid_to_rid.lookup(&pid);

    if (!req_id_p) {
        return 0;
    }
    int req_id = *req_id_p;

    size_t malloc_size;
    bpf_probe_read(&malloc_size, sizeof(malloc_size), (void*)&PT_REGS_PARM1(ctx));
    u64 ts = bpf_ktime_get_ns();
    struct datapoint *dp = lookup_or_init_dp(req_id, ts);
    if (!dp) {
        return 0;
    }
    dp->mem_malloc += malloc_size;

    $DEBUG_PRINTK("RID: [%d] MALLOC: %d\n", req_id, dp->mem_malloc);
    if (centroids_defined()) {
        long long delta = normalize_datapoint(malloc_size, MALLOC_OFFSET);
        update_outlier_score(ctx, req_id, delta, ts, dp->cputime);
    }
    return 0;
};

int probe_realloc(struct pt_regs *ctx) {
    u32 pid = bpf_get_current_pid_tgid();
    int *req_id = tid_to_rid.lookup(&pid);

    if (!req_id) {
        return 0;
    }

    size_t malloc_size = (size_t) PT_REGS_PARM2(ctx);
    u64 ts = bpf_ktime_get_ns();

    struct datapoint *dp = lookup_or_init_dp(*req_id, ts);
    if (!dp) {
        return 0;
    }
    dp->mem_malloc += malloc_size;

    $DEBUG_PRINTK("RID: [%d] MEM_MALLOC: %d\n", *req_id, dp->mem_malloc);
    if (centroids_defined()) {
        long long delta = normalize_datapoint(malloc_size, MALLOC_OFFSET);
        update_outlier_score(ctx, *req_id, delta, ts, dp->cputime);
    }
    return 0;
};


int probe_malloc(struct pt_regs *ctx) {
    u32 pid = bpf_get_current_pid_tgid();
    int *req_id = tid_to_rid.lookup(&pid);

    if (!req_id) {
        return 0;
    }

    size_t malloc_size = (size_t) PT_REGS_PARM1(ctx);
    u64 ts = bpf_ktime_get_ns();

    struct datapoint *dp = lookup_or_init_dp(*req_id, ts);
    if (!dp) {
        return 0;
    }
    dp->mem_malloc += malloc_size;

    $DEBUG_PRINTK("RID: [%d] MEM_MALLOC: %d\n", *req_id, dp->mem_malloc);
    if (centroids_defined()) {
        long long delta = normalize_datapoint(malloc_size, MALLOC_OFFSET);
        update_outlier_score(ctx, *req_id, delta, ts, dp->cputime);
    }
    return 0;
};

int probe_tcp_sendmsg(struct pt_regs *ctx, struct sock *sk, struct msghdr *hdr, size_t size) {
    u32 pid = bpf_get_current_pid_tgid();
    int *req_id_p = tid_to_rid.lookup(&pid);

    if (!req_id_p) {
        return 0;
    }
    int req_id = *req_id_p;

    u64 ts = bpf_ktime_get_ns();

    struct datapoint *dp = lookup_or_init_dp(req_id, ts);
    if (!dp) {
        return 0;
    }
    dp->tcp_sent += size;

    $DEBUG_PRINTK("RID: [%d] MEM_MALLOC: %d\n", req_id, dp->tcp_sent);
    if (centroids_defined()) {
        long long delta = normalize_datapoint(size, TCP_SENT_OFFSET);
        update_outlier_score(ctx, req_id, delta, ts, dp->cputime);
    }
    return 0;
}

int probe_tcp_cleanup_rbuf(struct pt_regs *ctx, struct sock *sk, int copied) {
    //The read buffer might have been empty (see net/ipv4/tcp.c)
    if (copied <= 0) {
        return -1;
    }
    u32 pid = bpf_get_current_pid_tgid();
    int *req_id = tid_to_rid.lookup(&pid);
    if (!req_id) {
        return 0;
    }

    u64 ts = bpf_ktime_get_ns();
    u64 idle_time = 0;

    struct datapoint *dp = lookup_or_init_dp(*req_id, ts);
    if (!dp) {
        return 0;
    }
    dp->tcp_rcvd += copied;
    if (dp->last_tcp_rcv_ts != 0) { // If not our first rcv()
        idle_time = ts - dp->last_tcp_rcv_ts;
        dp->tcp_idle_time += idle_time;
    }
    dp->last_tcp_rcv_ts = ts;
    if (dp->saddr == 0) {
        dp->saddr = sk->__sk_common.skc_daddr;
    }

    $DEBUG_PRINTK("RID [%d] SADDR: %d\n", *req_id, dp->saddr);
    $DEBUG_PRINTK("RID [%d] TCP_RCV: %d\n", *req_id, dp->tcp_rcvd);
    $DEBUG_PRINTK("RID [%d] TCP_IDLE_TIME: %lld\n", *req_id, dp->tcp_idle_time);
    if (centroids_defined()) {
        if (idle_time) {
            //FIXME: There is an overflow problem that should disappear when we move
            //to bitshift rather than 10^ exponentiation for FPA.
            if (idle_time > 1000000000) {
                bpf_trace_printk("idle time was greater than 1s: %s\n", idle_time);
                long long delta = 1000000000000000;
                update_outlier_score(ctx, *req_id, delta, ts, dp->cputime);
            } else {
                long long delta = normalize_datapoint(idle_time, IDLE_TIME_OFFSET);
                update_outlier_score(ctx, *req_id, delta, ts, dp->cputime);
            }
        }
        long long delta = normalize_datapoint(copied, TCP_RCVD_OFFSET);
        update_outlier_score(ctx, *req_id, delta, ts, dp->cputime);
    }
    return 0;
}

void new_assoc_2(struct pt_regs *ctx) {
    u64 ts = bpf_ktime_get_ns();

    unsigned long assoc;
    bpf_probe_read(&assoc, sizeof(assoc), (void*)&PT_REGS_PARM2(ctx));
    if (assoc == 0) {
        return;
    }
    //u64 ts = bpf_ktime_get_ns();

    int idx = 0;
    int *prev_rid = max_rid.lookup(&idx);
    if (prev_rid == NULL) {
        return;
    }
    (*prev_rid) += 1;
    int next_rid = *prev_rid;

    lookup_or_init_dp(next_rid, ts);
    assoc_to_rid.update(&assoc, &next_rid);

    $DEBUG_PRINTK("=======================================================\n");
    $DEBUG_PRINTK("Associated [%lu] to req [%d].\n", assoc, next_rid);
    $DEBUG_PRINTK("=======================================================\n");
    //struct datapoint dp = {.first_ts = ts, .last_tcp_rcv_ts = ts};
    //datapoints.insert(&next_rid, &dp);
}

void start_assoc_1(struct pt_regs *ctx) {
    u64 ts = bpf_ktime_get_ns();
    u32 pid = bpf_get_current_pid_tgid();
    int *req_id_p = tid_to_rid.lookup(&pid);
    if (!req_id_p) {
        $DEBUG_PRINTK("=======================================================\n");
        $DEBUG_PRINTK("No association for pid [%d].\n", pid);
        $DEBUG_PRINTK("=======================================================\n");
        return;
    }

    unsigned long assoc;
    bpf_probe_read(&assoc, sizeof(assoc), (void*)&PT_REGS_PARM1(ctx));
    if (assoc == 0) {
        return;
    }

    int req_id = *req_id_p;
    lookup_or_init_dp(req_id, ts);
    assoc_to_rid.update(&assoc, &req_id);

    $DEBUG_PRINTK("=======================================================\n");
    $DEBUG_PRINTK("Associated [%lu] to req [%d]..\n", assoc, req_id);
    $DEBUG_PRINTK("=======================================================\n");
}

void start_assoc_1_and_unmap(struct pt_regs *ctx) {

    u32 pid = bpf_get_current_pid_tgid();
    int *req_id_p = tid_to_rid.lookup(&pid);
    if (!req_id_p) {
        $DEBUG_PRINTK("=======================================================\n");
        $DEBUG_PRINTK("No association for pid [%d].\n", pid);
        $DEBUG_PRINTK("=======================================================\n");
        return;
    }

    unsigned long assoc;
    bpf_probe_read(&assoc, sizeof(assoc), (void*)&PT_REGS_PARM1(ctx));
    if (assoc == 0) {
        return;
    }
    u64 ts = bpf_ktime_get_ns();

    int req_id = *req_id_p;
    lookup_or_init_dp(req_id, ts);
    assoc_to_rid.update(&assoc, &req_id);

    $DEBUG_PRINTK("=======================================================\n");
    $DEBUG_PRINTK("Associated [%lu] to req [%d]..\n", assoc, req_id);
    $DEBUG_PRINTK("=======================================================\n");

    update_array(ctx, pid, ts, req_id);
    tid_to_rid.delete(&pid);

    $DEBUG_PRINTK("=======================================================\n");
    $DEBUG_PRINTK("Unmapped tid [%d] from req [%d] assoc [%lu]\n", pid, req_id);
    $DEBUG_PRINTK("=======================================================\n");
}

void start_assoc_2(struct pt_regs *ctx) {
    u32 pid = bpf_get_current_pid_tgid();
    int *req_id_p = tid_to_rid.lookup(&pid);
    if (!req_id_p) {
        return;
    }

    u64 ts = bpf_ktime_get_ns();

    unsigned long assoc;
    bpf_probe_read(&assoc, sizeof(assoc), (void*)&PT_REGS_PARM2(ctx));
    if (assoc == 0) {
        return;
    }

    int req_id = *req_id_p;
    lookup_or_init_dp(req_id, ts);
    assoc_to_rid.update(&assoc, &req_id);

    $DEBUG_PRINTK("=======================================================\n");
    $DEBUG_PRINTK("Associated [%lu] to req [%d]...\n", assoc, req_id);
    $DEBUG_PRINTK("=======================================================\n");
}

void map_tid_to_rid_3(struct pt_regs *ctx) {
    unsigned long assoc;
    bpf_probe_read(&assoc, sizeof(assoc), (void*)&PT_REGS_PARM3(ctx));
    if (assoc == 0) {
        return;
    }
    int *req_id_p = assoc_to_rid.lookup(&assoc);
    if (req_id_p == NULL) {
        $DEBUG_PRINTK("=======================================================\n");
        $DEBUG_PRINTK("No mapping for assoc %lu\n", assoc);
        $DEBUG_PRINTK("=======================================================\n");
        return;
    }

    u32 pid = bpf_get_current_pid_tgid();

    if (tid_to_rid.lookup(&pid)) {
        $DEBUG_PRINTK("=======================================================\n");
        $DEBUG_PRINTK("Existing ownership by tid %d \n", pid);
        $DEBUG_PRINTK("=======================================================\n");
        return;
    }


    int req_id = *req_id_p;
    tid_to_rid.insert(&pid, &req_id);
    u64 ts = bpf_ktime_get_ns();
    start.update(&pid, &ts);
    $DEBUG_PRINTK("=======================================================\n");
    $DEBUG_PRINTK("Mapped tid [%d] to req [%d] assoc [%lu]\n", pid, req_id, assoc);
    $DEBUG_PRINTK("=======================================================\n");
}

void map_tid_to_rid_1(struct pt_regs *ctx) {
    unsigned long assoc;
    bpf_probe_read(&assoc, sizeof(assoc), (void*)&PT_REGS_PARM1(ctx));
    if (assoc == 0) {
        return;
    }
    int *req_id_p = assoc_to_rid.lookup(&assoc);
    if (req_id_p == NULL) {
        $DEBUG_PRINTK("=======================================================\n");
        $DEBUG_PRINTK("No mapping for assoc %lu\n", assoc);
        $DEBUG_PRINTK("=======================================================\n");
        return;
    }

    u32 pid = bpf_get_current_pid_tgid();

    if (tid_to_rid.lookup(&pid)) {
        $DEBUG_PRINTK("=======================================================\n");
        $DEBUG_PRINTK("Existing ownership by tid %d \n", pid);
        $DEBUG_PRINTK("=======================================================\n");
        return;
    }


    int req_id = *req_id_p;
    tid_to_rid.insert(&pid, &req_id);
    u64 ts = bpf_ktime_get_ns();
    start.update(&pid, &ts);
    $DEBUG_PRINTK("=======================================================\n");
    $DEBUG_PRINTK("Mapped tid [%d] to req [%d] assoc [%lu]\n", pid, req_id, assoc);
    $DEBUG_PRINTK("=======================================================\n");
}

/** Apache and Nodejs user probes */
void ap_map_conn_to_rid(struct pt_regs *ctx) {
    unsigned long conn;
    bpf_probe_read(&conn, sizeof(conn), (void*)&PT_REGS_RC(ctx));
    if (conn == 0) {
        return;
    }
    //u64 ts = bpf_ktime_get_ns();

    int idx = 0;
    int *prev_rid = max_rid.lookup(&idx);
    if (prev_rid == NULL) {
        return;
    }
    (*prev_rid) += 1;
    int next_rid = *prev_rid;

    assoc_to_rid.update(&conn, &next_rid);
    $DEBUG_PRINTK("=======================================================\n");
    $DEBUG_PRINTK("Mapped conn [%lu] to req [%d]\n", conn, next_rid);
    $DEBUG_PRINTK("=======================================================\n");

    //struct datapoint dp = {.first_ts = ts, .last_tcp_rcv_ts = ts};
    //datapoints.insert(&next_rid, &dp);
}

void ap_map_tid_to_rid(struct pt_regs *ctx) {
    unsigned long conn;
    bpf_probe_read(&conn, sizeof(conn), (void*)&PT_REGS_PARM1(ctx));
    if (conn == 0) {
        $DEBUG_PRINTK("=======================================================\n");
        $DEBUG_PRINTK("conn was 0? [%lu]\n", conn);
        $DEBUG_PRINTK("=======================================================\n");
        return;
    }

    int *req_id_p = assoc_to_rid.lookup(&conn);
    if (req_id_p == NULL) {
        $DEBUG_PRINTK("=======================================================\n");
        $DEBUG_PRINTK("no rid mapped to conn [%lu]\n", conn);
        $DEBUG_PRINTK("=======================================================\n");
        return;
    }
    u32 pid = bpf_get_current_pid_tgid();
    int req_id = *req_id_p;
    tid_to_rid.insert(&pid, &req_id);
    u64 ts = bpf_ktime_get_ns();
    start.update(&pid, &ts);
    $DEBUG_PRINTK("=======================================================\n");
    $DEBUG_PRINTK("Mapped tid [%d] to req [%d]\n", pid, req_id);
    $DEBUG_PRINTK("=======================================================\n");
}

void ap_unmap_tid_to_rid(struct pt_regs *ctx) {
    u64 ts = bpf_ktime_get_ns();
    u32 pid = bpf_get_current_pid_tgid();
    int *req_id = tid_to_rid.lookup(&pid);
    if (!req_id) {
        return;
    }
    update_array(ctx, pid, ts, *req_id);
    tid_to_rid.delete(&pid);

    /*
    int req_id_cp = *req_id;
    struct datapoint *stored_dp = datapoints.lookup(&req_id_cp);
    if (stored_dp) {
        stored_dp->latest_ts_update = ts;
    }*/

    $DEBUG_PRINTK("=======================================================\n");
    $DEBUG_PRINTK("Unmapped tid [%d] from req [%d]\n", pid, *req_id);
    $DEBUG_PRINTK("=======================================================\n");
}

void map_tid_to_rid(struct pt_regs *ctx) {
    int req_id;
    bpf_probe_read(&req_id, sizeof(req_id), (void *)&PT_REGS_PARM3(ctx));
    if (req_id == 0) {
        return;
    }
    bpf_trace_printk("mapping req %d\n", req_id);
    u32 pid = bpf_get_current_pid_tgid();
    tid_to_rid.insert(&pid, &req_id);
    u64 ts = bpf_ktime_get_ns();
    start.update(&pid, &ts);
    $DEBUG_PRINTK("=======================================================\n");
    $DEBUG_PRINTK("Mapped tid [%d] to req [%d]\n", pid, req_id);
    $DEBUG_PRINTK("=======================================================\n");
}

void unmap_tid_to_rid(struct pt_regs *ctx) {
    u64 ts = bpf_ktime_get_ns();
    u32 pid = bpf_get_current_pid_tgid();
    int *req_id = tid_to_rid.lookup(&pid);
    if (!req_id) {
        return;
    }
    update_array(ctx, pid, ts, *req_id);
    tid_to_rid.delete(&pid);

    /*
    int req_id_cp = *req_id;
    struct datapoint *stored_dp = datapoints.lookup(&req_id_cp);
    if (stored_dp) {
        stored_dp->latest_ts_update = ts;
    }*/

    $DEBUG_PRINTK("=======================================================\n");
    $DEBUG_PRINTK("Unmapped tid [%d] from req [%d]\n", pid, *req_id);
    $DEBUG_PRINTK("=======================================================\n");
}
