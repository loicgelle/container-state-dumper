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
    cgroup_file_string_pair_values,

    /* Input arguments */
    TP_ARGS(
        char*, path,
        char*, f_name,
        char*, raw_content
    ),

    /* Output event fields */
    TP_FIELDS(
        ctf_string(cgrp_path, path)
        ctf_string(filename, f_name)
        ctf_string(content, raw_content)
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