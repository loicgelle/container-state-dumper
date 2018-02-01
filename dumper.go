package main

import (
	"fmt"
	"os"
	"bufio"
	"path"
	"path/filepath"
	"io/ioutil"
	"github.com/opencontainers/runc/libcontainer/cgroups"
	"github.com/tywkeene/go-fsevents"
)

// Control group statedump functions

func cgroupFileHandler(path string, filename string) {
	fileHandler := cgroup_fs_defs[filename]
	if fileHandler != nil {
		fileHandler(path, filename)
	} else {
		// If filename not exactly matched, try to use regex matching
		for pattern, match := range cgroup_fs_lookaside_defs {
			if pattern.MatchString(filename) {
				fileHandler := cgroup_fs_defs[match]
				if fileHandler != nil {
					fileHandler(path, filename)
				}
			}
		}
	}
}

func cgroupDumpHandler(path string, f os.FileInfo, err error) error {
	if (f.IsDir()) {
		cgroupPathHandler(path, 0)
		/* Handle files in path */
		files, err := ioutil.ReadDir(path)
		if err != nil {
			return err
		}
	
		for _, f := range files {
			cgroupFileHandler(path, f.Name())
		}
	}
	return nil
}

// Returns the subsys roots to watch
func makeCgroupsStatedump() []string {
	mounts, err := cgroups.GetCgroupMounts(false)
	subsysRoots := make([]string, 0, 20)

	// Iterate through hierarchies
	if err == nil {
		for _, m := range mounts {
			for _, ss := range m.Subsystems {
				// TP: subsys root
				cgroupSubsysRootHandler(m.Mountpoint, ss)
				subsysRoots = append(subsysRoots, m.Mountpoint)
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

	return subsysRoots
}

func handleCgroupEvents(watcher *fsevents.Watcher) {
	watcher.StartAll()
	go watcher.Watch()

	for {
		select {
		case event := <-watcher.Events:
			// In case file is modified
			if event.IsFileChanged() {
				filepath, filename := path.Split(event.Path)
				cgroupFileHandler(filepath, filename)
			}

			// In case new cgroup is created
			if event.IsDirCreated() {
				// Add directory to watcher
				dirpath := path.Clean(event.Path)
				watcher.AddDescriptor(dirpath, 0)
				descriptor := watcher.GetDescriptorByPath(dirpath)
				descriptor.Start(watcher.FileDescriptor)

				cgroupPathHandler(dirpath, 1)
			}
			
			// In case cgroup is removed
			if event.IsDirRemoved() {
				dirpath := path.Clean(event.Path)
				watcher.RemoveDescriptor(path.Clean(dirpath))

				cgroupPathHandler(dirpath, -1)
			}
			
			break
		case err := <-watcher.Errors:
			fmt.Println(err)
			break
		}
	}
}

func startCgroupWatching(subsysRoots []string) {
	options := &fsevents.WatcherOptions{
		Recursive:       true,
		UseWatcherFlags: true,
	}
	inotifyFlags := fsevents.Delete | fsevents.Create | fsevents.IsDir | fsevents.Modified | fsevents.MovedTo |
		fsevents.Modified
	
	var w *fsevents.Watcher
	var err error
	for i, watchDir := range subsysRoots {
		if i == 0 {
			w, err = fsevents.NewWatcher(watchDir, inotifyFlags, options)
                	if err != nil {
                        	panic(err)
                	}
			continue
		}
		w.RecursiveAdd(watchDir, 0)
	}
	handleCgroupEvents(w)
}


// Main function 
func main() {
	fmt.Println("Ready for the statedump.")
	fmt.Print("Press 'Enter' to continue...")
	bufio.NewReader(os.Stdin).ReadBytes('\n') 

	subsysRoots := makeCgroupsStatedump()
	startCgroupWatching(subsysRoots)
}
