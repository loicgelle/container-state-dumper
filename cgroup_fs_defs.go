package main

// #cgo LDFLAGS: -ldl -L. cgroup-tpp.a -llttng-ust
/*
#define TRACEPOINT_DEFINE
#include "cgroup-tp.h"

void traceSubsysRoot(char* ss_root, char* ss_name) {
	tracepoint(cgroup_ust, cgroup_subsys_root, ss_root, ss_name);
}

void traceAttachedPid(char* path, uint64_t* pids, uint pids_len) {
	tracepoint(cgroup_ust, cgroup_attached_pids, path, pids, pids_len);
}

void traceIntValue(char* path, char* file_name, int64_t val) {
	tracepoint(cgroup_ust, cgroup_file_int_value, path, file_name, val);
}

void traceUintValue(char* path, char* file_name, uint64_t val) {
	tracepoint(cgroup_ust, cgroup_file_uint_value, path, file_name, val);
}

void traceStringValue(char* path, char* file_name, char* val) {
	tracepoint(cgroup_ust, cgroup_file_string_value, path, file_name, val);
}

void traceStringPairValue(char* path, char* file_name, char* val1, char* val2) {
	tracepoint(cgroup_ust, cgroup_file_string_pair_value, path, file_name, val1, val2);
}

void traceBlkioValue(char* path, char* file_name, int64_t maj, int64_t min, uint64_t val) {
	tracepoint(cgroup_ust, cgroup_file_blkio_value, path, file_name, maj, min, val);
}

void traceDevicesValue(char* path, char* file_name, char* dev_type, char* maj, char* min, char* access) {
	tracepoint(cgroup_ust, cgroup_file_devices_value, path, file_name, dev_type, maj, min, access);
}

void traceEmptyFile(char* path, char* file_name) {
	tracepoint(cgroup_ust, cgroup_file_empty, path, file_name);
}

void tracePath(char* path, int status) {
	tracepoint(cgroup_ust, cgroup_path_status, path, status);
}
*/
import "C"

import (
	"github.com/opencontainers/runc/libcontainer/cgroups"

	"path/filepath"
	"io/ioutil"
	"strings"
	"strconv"
	"errors"
	"fmt"
	"regexp"
	"crypto/md5"
)

type CgroupFileHandler func(string, string) error

// Associates cgroup core/subsys filenames to handlers that will
// read the file and trigger a trace event
var cgroup_fs_defs = map[string]CgroupFileHandler {

	// core cgroup files
	"cgroup.procs": cgroupFileProcsHandler,

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

	// "devices" subsys files
	"devices.deny": cgroupFileDevicesHandler,
	"devices.allow": cgroupFileDevicesHandler,

}

// If filename is not matched exactly, we can use regex matching to
// recover the filename
var cgroup_fs_lookaside_defs = map[*regexp.Regexp]string {
	regexp.MustCompile(`hugetlb\.[^\.]*\.limit_in_bytes`): "hugetlb.limit_in_bytes",
}

// Keep track of information about the last file processed to avoid redundant dump
var lastFileHash [16]byte

// File handlers and helper functions

// Source: github.com/opencontainers/runc/libcontainer/cgroups/fs/utils.go
func getStringFromFile(path string, filename string) (string, error) {
	contents, err := ioutil.ReadFile(filepath.Join(path, filename))
	if err != nil {
		return "", err
	}

	hash := md5.Sum([]byte(string(contents)+path+filename))
	if hash == lastFileHash {
		return "", errors.New("File processing cancelled to avoid duplication")
	}
	lastFileHash = hash
	
	return strings.TrimSpace(string(contents)), nil
}

func getStringLinesFromFile(path string, filename string) ([]string, error) {
	contents, err := ioutil.ReadFile(filepath.Join(path, filename))
	if err != nil {
		return nil, err
	}

	hash := md5.Sum([]byte(string(contents)+path+filename))
	if hash == lastFileHash {
		return []string{}, errors.New("File processing cancelled to avoid duplication")
	}
	lastFileHash = hash

	lines := strings.Split(string(contents), "\n")
	if len(lines) > 0 {
		return lines, nil
	} else {
		return []string{}, nil
	}
}


func cgroupFileUintHandler(path string, filename string) error {
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

	C.traceUintValue(C.CString(path), C.CString(filename), C.uint64_t(value))
	return nil
}

func cgroupFileIntHandler(path string, filename string) error {
	strval, err := getStringFromFile(path, filename)
	if err != nil {
		return err
	}

	value, err := strconv.ParseInt(strval, 10, 64)
	if err != nil {
		return err
	}

	C.traceIntValue(C.CString(path), C.CString(filename), C.int64_t(value))
	return nil
}

func cgroupFileStringHandler(path string, filename string) error {
	strval, err := getStringFromFile(path, filename)
	if err != nil {
		return err
	}

	C.traceStringValue(C.CString(path), C.CString(filename), C.CString(strval))
	return nil
}

func cgroupFileBlkioHandler(path string, filename string) error {
	lines, err := getStringLinesFromFile(path, filename)

	if err != nil {
		return err
	}

	if len(lines) == 0 || lines[0] == "" {
		C.traceEmptyFile(C.CString(path), C.CString(filename))
		return nil
	}

	for _, line := range lines {
		var major, minor int64
		var val uint64
		_, err := fmt.Sscanf(line, "%d:%d %d", &major, &minor, &val)
		if err != nil {	
			return err
		}
		C.traceBlkioValue(C.CString(path), C.CString(filename), C.int64_t(major), C.int64_t(minor), C.uint64_t(val))
	}

	return nil
}

func cgroupFileDevicesHandler(path string, _ string) error {
	// We need to read "devices.list" instead of the given write-only file
	read_filename := "devices_list"

	lines, err := getStringLinesFromFile(path, read_filename)

	if err != nil {
		return err
	}

	if len(lines) == 0 || lines[0] == "" {
		C.traceEmptyFile(C.CString(path), C.CString(read_filename))
		return nil
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
			C.traceDevicesValue(C.CString(path), C.CString(read_filename), C.CString(dev_type), C.CString(major), C.CString(minor), C.CString(access))
		} else {
			return errors.New("Error while parsing devices cgroup file")
		}
		
	}

	return nil
}

func cgroupFileStringPairsHandler(path string, filename string) error {
	lines, err := getStringLinesFromFile(path, filename)
	if err != nil {
		return err
	}

	if len(lines) == 0 {
		C.traceEmptyFile(C.CString(path), C.CString(filename))
		return nil
	}

	for _, line := range lines {
		re := regexp.MustCompile(`(\w+)\s(\w+)`)
		matches := re.FindStringSubmatch(line)
		if len(matches) > 2 {
			val1 := matches[1]
			val2 := matches[2]
			C.traceStringPairValue(C.CString(path), C.CString(filename), C.CString(val1), C.CString(val2))
		} else {
			return errors.New("Error while parsing pair of strings in cgroup file")
		}
		
	}

	return nil
}

func cgroupFileProcsHandler(path string, filename string) error {
	pids, err := cgroups.GetPids(path)

	if err != nil {
		return err
	}

	hash := md5.Sum([]byte(string(len(pids))+path+filename))
	if hash == lastFileHash {
		return errors.New("File processing cancelled to avoid duplication")
	}
	lastFileHash = hash

	if len(pids) == 0 {
		C.traceEmptyFile(C.CString(path), C.CString(filename))
		return nil
	}

	if len(pids) > 0 {
		pids_64 := make([]uint64, len(pids))
		for i, pid := range pids {
			pids_64[i] = uint64(pid)
		}
		C.traceAttachedPid(C.CString(path), (*C.uint64_t)(&pids_64[0]), C.uint(len(pids)))
	}
	return nil
}

// Simple trace functions

func cgroupSubsysRootHandler(mountpoint string, subsys string) {
	C.traceSubsysRoot(C.CString(mountpoint), C.CString(subsys))
}

func cgroupPathHandler(path string, status int) {
	C.tracePath(C.CString(path), C.int(status))
}