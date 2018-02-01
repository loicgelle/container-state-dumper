#undef TRACEPOINT_PROVIDER
#define TRACEPOINT_PROVIDER cgroup_ust

#undef TRACEPOINT_INCLUDE
#define TRACEPOINT_INCLUDE "./cgroup-tp.h"

#if !defined(_TP_H) || defined(TRACEPOINT_HEADER_MULTI_READ)
#define _TP_H

#include <lttng/tracepoint.h>

TRACEPOINT_EVENT(
    cgroup_ust,
    cgroup_subsys_root,

    /* Input arguments */
    TP_ARGS(
        char*, ss_root,
        char*, ss_name
    ),

    /* Output event fields */
    TP_FIELDS(
        ctf_string(root, ss_root)
        ctf_string(subsys_name, ss_name)
    )
)

TRACEPOINT_EVENT(
    cgroup_ust,
    cgroup_attached_pids,

    /* Input arguments */
    TP_ARGS(
        char*, path,
        uint64_t*, pids_arr,
        uint, pids_len
    ),

    /* Output event fields */
    TP_FIELDS(
        ctf_string(cgrp_path, path)
        ctf_sequence(uint64_t, pids, pids_arr, uint, pids_len)
    )
)

TRACEPOINT_EVENT(
    cgroup_ust,
    cgroup_file_int_value,

    /* Input arguments */
    TP_ARGS(
        char*, path,
        char*, f_name,
        int64_t, value
    ),

    /* Output event fields */
    TP_FIELDS(
        ctf_string(cgrp_path, path)
        ctf_string(filename, f_name)
        ctf_integer(int64_t, val, value)
    )
)

TRACEPOINT_EVENT(
    cgroup_ust,
    cgroup_file_uint_value,

    /* Input arguments */
    TP_ARGS(
        char*, path,
        char*, f_name,
        uint64_t, value
    ),

    /* Output event fields */
    TP_FIELDS(
        ctf_string(cgrp_path, path)
        ctf_string(filename, f_name)
        ctf_integer(uint64_t, val, value)
    )
)

TRACEPOINT_EVENT(
    cgroup_ust,
    cgroup_file_string_value,

    /* Input arguments */
    TP_ARGS(
        char*, path,
        char*, f_name,
        char*, value
    ),

    /* Output event fields */
    TP_FIELDS(
        ctf_string(cgrp_path, path)
        ctf_string(filename, f_name)
        ctf_string(val, value)
    )
)

TRACEPOINT_EVENT(
    cgroup_ust,
    cgroup_file_string_pair_value,

    /* Input arguments */
    TP_ARGS(
        char*, path,
        char*, f_name,
        char*, value1,
        char*, value2
    ),

    /* Output event fields */
    TP_FIELDS(
        ctf_string(cgrp_path, path)
        ctf_string(filename, f_name)
        ctf_string(val1, value1)
        ctf_string(val2, value2)
    )
)

TRACEPOINT_EVENT(
    cgroup_ust,
    cgroup_file_blkio_value,

    /* Input arguments */
    TP_ARGS(
        char*, path,
        char*, f_name,
        int64_t, maj,
        int64_t, min,
        uint64_t, value
    ),

    /* Output event fields */
    TP_FIELDS(
        ctf_string(cgrp_path, path)
        ctf_string(filename, f_name)
        ctf_integer(int64_t, major, maj)
        ctf_integer(int64_t, minor, min)
        ctf_integer(uint64_t, val, value)
    )
)

TRACEPOINT_EVENT(
    cgroup_ust,
    cgroup_file_devices_value,

    /* Input arguments */
    TP_ARGS(
        char*, path,
        char*, f_name,
        char*, device_type,
        char*, maj,
        char*, min,
        char*, acc
    ),

    /* Output event fields */
    TP_FIELDS(
        ctf_string(cgrp_path, path)
        ctf_string(filename, f_name)
        ctf_string(dev_type, device_type)
        ctf_string(major, maj)
        ctf_string(minor, min)
        ctf_string(access, acc)
    )
)

TRACEPOINT_EVENT(
    cgroup_ust,
    cgroup_file_empty,

    /* Input arguments */
    TP_ARGS(
        char*, path,
        char*, f_name
    ),

    /* Output event fields */
    TP_FIELDS(
        ctf_string(cgrp_path, path)
        ctf_string(filename, f_name)
    )
)


// The integer denotes:
// 0: initial cgroup path
// 1: added cgroup path
// -1: removed cgroup path
TRACEPOINT_EVENT(
    cgroup_ust,
    cgroup_path_status,

    /* Input arguments */
    TP_ARGS(
        char*, path,
        int, st
    ),

    /* Output event fields */
    TP_FIELDS(
        ctf_string(cgrp_path, path)
        ctf_integer(int, status, st)
    )
)

#endif /* _TP_H */

#include <lttng/tracepoint-event.h>