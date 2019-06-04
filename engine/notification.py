import ctypes as ct

class NoteLoad(ct.Union):
    _fields_ =[("load_i", ct.c_int64),
              ("load_d", ct.c_double)];

class Notify(ct.Structure):
    _fields_ =[("type", ct.c_int),
                ("msg_size", ct.c_size_t),
                ("msg", ct.c_char * 32),
                ("load", NoteLoad)];

def print_notification(cpu, data, size):
    event = ct.cast(data, ct.POINTER(Notify)).contents

    if event.type == 0:
        print("Str Notification: ", event.msg)
    elif event.type == 1:
        print("Int Notification: ", event.msg, event.load.load_i)
    elif event.type == 2:
        print("Dou Notification: ", event.msg, event.load.load_d)
    else:
        print("??? Notification: ", event.msg)

def open_notify_buffer(bpf):
    bpf['notification_evt'].open_perf_buffer(print_notification)

def poll_notification(bpf):
    bpf.perf_buffer_poll()
