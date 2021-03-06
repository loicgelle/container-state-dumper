# Container state dumper

This helper tool can be used to watch and trace the changes to control groups and namespaces on a Linux machine. It creates user-space tracepoints for LTTng-ust (http://lttng.org/docs).

## Prerequisites

- Go (https://golang.org/doc/install)
- LTTng-ust (http://lttng.org/docs)
- Working C toolchain for compiling (e.g. gcc)

## Installation

1. Get the code from github: `git clone https://github.com/loicgelle/container-state-dumper && cd container-state-dumper`

2. Compile the tracepoint provider and the tool: `make`

3. There is no step 3.

## Usage

1. First, you need to launch the tool: `./container-state-dumper`. It will wait for you to press enter when the tracing has started.

2. In another terminal window, create a new tracing session with LTTng: `lttng create demo-session`

3. Enable the events from the tool: `lttng enable-event --userspace 'cgroup_ust:*'`

4. Start tracing: `lttng start`

5. Back to the original terminal window, press Enter to start the state dump and launch the watcher.

6. You can stop the tracing any time with `lttng stop` and analyze the output trace with babeltrace.

## Development

### Warning

- Watching the changes in the cgroup filesystem is performed using the mechanism inotify. The memory consumption could be noticeable on systems with tens of thousands of control groups.
- Latency in the trace information and overhead on the machine could be expected, although no evaluation has been performed yet.

### Working

- Control groups: support for every configuration file from the following cgroup subsystems: `blkio`, `cpu`, `cpuset`, `freezer`, `hugetlb`, `memory`, `net_cls`, `net_prio`, `pids`.

### Todo

- Control groups: core files are not included yet in the statedump. Also, stats files are not supported (and could potentially never be).

- Namespaces: everything.
