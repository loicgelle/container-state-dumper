package main

import (
	"fmt"
	"os"
	"bufio"
	"path/filepath"
	"io/ioutil"
	"github.com/opencontainers/runc/libcontainer/cgroups"
)

var cgroupUniqId int = 0

/* Control group statedump functions */

func cgroupDumpHandler(path string, f os.FileInfo, err error) error {
	if (f.IsDir()) {
		currId := cgroupUniqId
		cgroupUniqId++

		/* TP: dump path id */
		cgroupPathIdHandler(path, currId)
		
		pids, err := cgroups.GetPids(path)
		if err == nil {
			for _, pid := range pids {
				/* TP: dump cgroup attached pid */				
				cgroupAttachedPidHandler(currId, pid)
			}
		}

		/* Handle files in path */
		files, err := ioutil.ReadDir(path)
		if err != nil {
			return err
		}
	
		for _, f := range files {
			filename := f.Name()
			fileHandler := cgroup_fs_defs[filename]
			if fileHandler != nil {
				fileHandler(currId, path, filename)
			} else {
				// If filename not exactly matched, try to use regex matching
				for pattern, match := range cgroup_fs_lookaside_defs {
					if pattern.MatchString(filename) {
						fileHandler := cgroup_fs_defs[match]
						if fileHandler != nil {
							fileHandler(currId, path, filename)
						}
					}
				}
			}
		}
	}
	return nil
}

func makeCgroupsStatedump() {
	mounts, err := cgroups.GetCgroupMounts(false)

	/* Iterate through hierarchies */
	if err == nil {
		for _, m := range mounts {
			for _, ss := range m.Subsystems {
				/* TP: subsys root */
				cgroupSubsysRootHandler(m.Mountpoint, ss)
			}
			
			// Print cgroup subdirs
			err = filepath.Walk(m.Mountpoint, cgroupDumpHandler)
			if err != nil {
				fmt.Println("Error while iterating through cgroups.")
			}
		}
	} else {
		fmt.Println("Error while retrieving cgroup mountpoints.")
	}
}

/* Main function */

func main() {
	fmt.Println("Ready for the statedump.")
	fmt.Print("Press 'Enter' to continue...")
	bufio.NewReader(os.Stdin).ReadBytes('\n') 

	makeCgroupsStatedump()
}