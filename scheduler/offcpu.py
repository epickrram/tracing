#!/usr/bin/python
from bcc import BPF
import datetime
import sys
import time


if len(sys.argv) < 2:
    print("Usage: %s <cpu-number>" % (sys.argv[0]))
    sys.exit(1)

prog="""
#include <linux/types.h>
#include <linux/sched.h>
#include <uapi/linux/ptrace.h>

struct proc_name_t {
    char comm[TASK_COMM_LEN];
};

BPF_TABLE("hash", pid_t, u64, last_time_on_cpu, 1024);
BPF_TABLE("hash", pid_t, u64, max_offcpu, 1024);
BPF_TABLE("hash", pid_t, struct proc_name_t, proc_name, 1024);

int trace_finish_task_switch(struct pt_regs *ctx, struct task_struct *prev) {
    // bail early if this is not the CPU we're interested in
    u32 target_cpu = %d;
    if(target_cpu != bpf_get_smp_processor_id())
    {
        return 0;
    }

    // get information about previous/next processes
    struct proc_name_t pname = {};
    pid_t next_pid = bpf_get_current_pid_tgid();
    pid_t prev_pid = prev->pid;
    bpf_get_current_comm(&pname.comm, sizeof(pname.comm));

    // store mapping of pid -> command for display
    proc_name.update(&next_pid, &pname);

    // lookup current values for incoming process
    u64 *last_time;
    u64 *current_max_offcpu;
    u64 current_time = bpf_ktime_get_ns();
    last_time = last_time_on_cpu.lookup(&next_pid);
    current_max_offcpu = max_offcpu.lookup(&next_pid);

    // update max offcpu time
    if(last_time != NULL) {
        u64 delta_nanos = current_time - *last_time;
        if(current_max_offcpu == NULL) {
            max_offcpu.update(&next_pid, &delta_nanos);
        }
        else {
            if(delta_nanos > *current_max_offcpu) {
                max_offcpu.update(&next_pid, &delta_nanos);
            }
        }
    }

    // store outgoing process' time
    last_time_on_cpu.update(&prev_pid, &current_time);
    return 0;
};
"""

b = BPF(text=prog % (int(sys.argv[1])))
b.attach_kprobe(event="finish_task_switch", fn_name="trace_finish_task_switch")

while 1:
    time.sleep(1)
    for k,v in b["max_offcpu"].iteritems():
        if v != 0:
            proc_name = b["proc_name"][k].comm
            print("%s max offcpu for %s is %dus" % (datetime.datetime.now(), proc_name, v.value/1000))
    b["max_offcpu"].clear()

