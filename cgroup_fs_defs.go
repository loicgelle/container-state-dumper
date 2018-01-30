package main

// #cgo LDFLAGS: -ldl -L. cgroup-tpp.a -llttng-ust
/*
#define TRACEPOINT_DEFINE
#include "cgroup-tp.h"

void traceSubsysRoot(char* ss_root, char* ss_name) {
	tracepoint(cgroup_ust, cgroup_subsys_root, ss_root, ss_name);
}

void traceDumpPathId(char* path, int d_id) {
	tracepoint(cgroup_ust, cgroup_path_dump_id, path, d_id);
}

void traceAttachedPid(int d_id, int pid) {
	tracepoint(cgroup_ust, cgroup_attached_pid, d_id, pid);
}

void traceIntValue(int d_id, char* file_name, int64_t val) {
	tracepoint(cgroup_ust, cgroup_file_int_value, d_id, file_name, val);
}

void traceUintValue(int d_id, char* file_name, uint64_t val) {
	tracepoint(cgroup_ust, cgroup_file_uint_value, d_id, file_name, val);
}

void traceStringValue(int d_id, char* file_name, char* val) {
	tracepoint(cgroup_ust, cgroup_file_string_value, d_id, file_name, val);
}

void traceStringPairValue(int d_id, char* file_name, char* val1, char* val2) {
	tracepoint(cgroup_ust, cgroup_file_string_pair_value, d_id, file_name, val1, val2);
}

void traceBlkioValue(int d_id, char* file_name, int64_t maj, int64_t min, uint64_t val) {
	tracepoint(cgroup_ust, cgroup_file_blkio_value, d_id, file_name, maj, min, val);
}

void traceDevicesValue(int d_id, char* file_name, char* dev_type, char* maj, char* min, char* access) {
	tracepoint(cgroup_ust, cgroup_file_devices_value, d_id, file_name, dev_type, maj, min, access);
}
*/
import "C"

import (
	"path/filepath"
	"io/ioutil"
	"strings"
	"strconv"
	"errors"
	"fmt"
	"regexp"
)

type CgroupFileHandler func(int, string, string) error

// Associates cgroup core/subsys filenames to handlers that will
// read the file and trigger a trace event
var cgroup_fs_defs = map[string]CgroupFileHandler {

	// "blkio" subsys files
	"blkio.weight": cgroupFileUintHandler,
    "blkio.leaf_weight": cgroupFileUintHandler,
    "blkio.weight_device": cgroupFileBlkioHandler,
    "blkio.leaf_weight_device": cgroupFileBlkioHandler,
    "blkio.throttle.read_bps_device": cgroupFileBlkioHandler,
    "blkio.throttle.write_bps_device": cgroupFileBlkioHandler,
    "blkio.throttle.read_iops_device": cgroupFileBlkioHandler,
    "blkio.throttle.write_iops_device": cgroupFileBlkioHandler,
	// TODO: stat files

	// "cpu" subsys files
    "cpu.shares": cgroupFileUintHandler,
    "cpu.cfs_period_us": cgroupFileUintHandler,
    "cpu.cfs_quota_us": cgroupFileIntHandler,
    "cpu.rt_period_us": cgroupFileUintHandler,
	"cpu.rt_runtime_us": cgroupFileIntHandler,
	// TODO: stat files

	// "cpuset" subsys files
	"cpuset.cpus": cgroupFileStringHandler,
	"cpuset.mems": cgroupFileStringHandler,
	// TODO: stat files

	// "cpuacct" subsys files
	// TODO: stat files

	// "freezer" subsys files
	"freezer.state": cgroupFileStringHandler,
	"freezer.self_freezing": cgroupFileUintHandler,
	"freezer.parent_freezing": cgroupFileUintHandler,

	// "hugetlb" subsys files
	"hugetlb.limit_in_bytes": cgroupFileUintHandler,
	// TODO: stat files

	// "memory" subsys files
	"memory.limit_in_bytes": cgroupFileIntHandler,
	"memory.memsw.limit_in_bytes": cgroupFileIntHandler,
	"memory.soft_limit_in_bytes": cgroupFileIntHandler,
	"memory.use_hierarchy": cgroupFileUintHandler,
	"memory.swappiness": cgroupFileUintHandler,
	"memory.move_charge_at_immigrate": cgroupFileUintHandler,
	"memory.oom_control": cgroupFileStringPairsHandler,
	"memory.kmem.limit_in_bytes": cgroupFileIntHandler,
	"memory.kmem.tcp.limit_in_bytes": cgroupFileIntHandler,
	// TODO: stat files

	// "net_cls" subsys files
	"net_cls.classid": cgroupFileUintHandler,

	// "net_prio" subsys files
	"net_prio.ifpriomap": cgroupFileStringPairsHandler,
	
	// "pids" subsys files
	"pids.max": cgroupFileStringHandler,
	// TODO: stat files

}

// If filename is not matched exactly, we can use regex matching to
// recover the filename
var cgroup_fs_lookaside_defs = map[*regexp.Regexp]string {
	regexp.MustCompile(`hugetlb\.[^\.]*\.limit_in_bytes`): "hugetlb.limit_in_bytes",
}

// File handlers and helper functions

// Source: github.com/opencontainers/runc/libcontainer/cgroups/fs/utils.go
func getStringFromFile(path string, filename string) (string, error) {
	contents, err := ioutil.ReadFile(filepath.Join(path, filename))
	if err != nil {
		return "", err
	}

	return strings.TrimSpace(string(contents)), nil
}

func getStringLinesFromFile(path string, filename string) ([]string, error) {
	contents, err := ioutil.ReadFile(filepath.Join(path, filename))
	if err != nil {
		return nil, err
	}

	lines := strings.Split(string(contents), "\n")
	if len(lines) > 0 {
		return lines, nil
	} else {
		return []string{strings.TrimSpace(string(contents))}, nil
	}
}


func cgroupFileUintHandler(d_id int, path string, filename string) error {
	strval, err := getStringFromFile(path, filename)
	if err != nil {
		return err
	}

	// Source: github.com/opencontainers/runc/libcontainer/cgroups/fs/utils.go
	// Saturates negative values at zero and returns a uint64.
	// Due to kernel bugs, some of the memory cgroup stats can be negative.
	value, err := strconv.ParseUint(strval, 10, 64)
	if err != nil {
		intValue, intErr := strconv.ParseInt(strval, 10, 64)
		// 1. Handle negative values greater than MinInt64 (and)
		// 2. Handle negative values lesser than MinInt64
		if intErr == nil && intValue < 0 {
			value = 0
		} else if intErr != nil && intErr.(*strconv.NumError).Err == strconv.ErrRange && intValue < 0 {
			value = 0
		} else {
			return err
		}
	}

	C.traceUintValue(C.int(d_id), C.CString(filename), C.uint64_t(value))
	return nil
}

func cgroupFileIntHandler(d_id int, path string, filename string) error {
	strval, err := getStringFromFile(path, filename)
	if err != nil {
		return err
	}

	value, err := strconv.ParseInt(strval, 10, 64)
	if err != nil {
		return err
	}

	C.traceIntValue(C.int(d_id), C.CString(filename), C.int64_t(value))
	return nil
}

func cgroupFileStringHandler(d_id int, path string, filename string) error {
	strval, err := getStringFromFile(path, filename)
	if err != nil {
		return err
	}

	C.traceStringValue(C.int(d_id), C.CString(filename), C.CString(strval))
	return nil
}

func cgroupFileBlkioHandler(d_id int, path string, filename string) error {
	lines, err := getStringLinesFromFile(path, filename)
	if err != nil {
		return err
	}

	for _, line := range lines {
		var dev_type, major, minor, access string
		_, err := fmt.Sscanf(line, "%s %s:%s %s", &dev_type, &major, &minor, &access)
		if err != nil {	
			return err
		}
		fmt.Printf("%s %s:%s %s\n", dev_type, major, minor, access)
		//C.traceBlkioValue(C.int(d_id), C.CString(filename), C.int64_t(major), C.int64_t(minor), C.uint64_t(val))
	}

	return nil
}

func cgroupFileDevicesHandler(d_id int, path string, filename string) error {
	lines, err := getStringLinesFromFile(path, filename)
	if err != nil {
		return err
	}

	for _, line := range lines {
		re := regexp.MustCompile(`(a|c|b)+?\s([0-9]|\*)+\:([0-9]|\*)+\s([r|w|m]+)`)
		matches := re.FindStringSubmatch(line)
		if len(matches) > 4 {
			var dev_type, major, minor, access string
			dev_type = matches[1]
			major = matches[2]
			minor = matches[3]
			access = matches[4]
			C.traceDevicesValue(C.int(d_id), C.CString(filename), C.CString(dev_type), C.CString(major), C.CString(minor), C.CString(access))
		} else {
			return errors.New("Error while parsing devices cgroup file")
		}
		
	}

	return nil
}

func cgroupFileStringPairsHandler(d_id int, path string, filename string) error {
	lines, err := getStringLinesFromFile(path, filename)
	if err != nil {
		return err
	}

	for _, line := range lines {
		re := regexp.MustCompile(`(\w+)\s(\w+)`)
		matches := re.FindStringSubmatch(line)
		if len(matches) > 2 {
			val1 := matches[1]
			val2 := matches[2]
			C.traceStringPairValue(C.int(d_id), C.CString(filename), C.CString(val1), C.CString(val2))
		} else {
			return errors.New("Error while parsing pair of strings in cgroup file")
		}
		
	}

	return nil
}

// Simple trace functions

func cgroupSubsysRootHandler(mountpoint string, subsys string) {
	C.traceSubsysRoot(C.CString(mountpoint), C.CString(subsys))
}

func cgroupPathIdHandler(path string, id int) {	
	C.traceDumpPathId(C.CString(path), C.int(id))
}

func cgroupAttachedPidHandler(currId int, pid int) {	
	C.traceAttachedPid(C.int(currId), C.int(pid))
}