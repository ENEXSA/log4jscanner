// Copyright 2021 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// The log4jscanner tool scans a set of directories for log4j vulnerable JARs.
package main

import (
	"errors"
	"flag"
	"fmt"
	"github.com/briandowns/spinner"
	"github.com/fatih/color"
	"io/fs"
	"log"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"time"
	"unsafe"

	"github.com/google/log4jscanner/jar"
)

func usage() {
	fmt.Fprint(os.Stderr, `Usage: log4jscanner [flag] [directories]

A log4j vulnerability scanner. The scanner walks the provided directories
attempting to find vulnerable JARs. Paths of vulnerable JARs are printed
to stdout.

Flags:

    -s, --skip     Glob pattern to skip when scanning (e.g. '/var/run/*'). May
                   be provided multiple times.
    -f, --force    Don't skip network and userland filesystems. (smb,nfs,afs,fuse)
    -w, --rewrite  Rewrite vulnerable JARs as they are detected.
    -v, --verbose  Print verbose logs to stderr.

`)
}

var skipDirs = map[string]bool{
	".hg":          true,
	".git":         true,
	"node_modules": true,
	".idea":        true,

	// TODO(ericchiang): expand
}

var (
	errUnknownDriveType = errors.New("unknown drive type")
	errNoRootDir        = errors.New("invalid root drive path")

	driveTypeErrors = [...]error{
		0: errUnknownDriveType,
		1: errNoRootDir,
	}
	kernel32          = syscall.NewLazyDLL("kernel32.dll")
	getDriveTypeWProc = kernel32.NewProc("GetDriveTypeW")
	getLastError      = kernel32.NewProc("GetLastError")
)

const (
	driveUnknown = iota
	driveNoRootDir

	driveRemovable
	driveFixed
	driveRemote
	driveCDROM
	driveRamdisk
)

func getdrives() ([]string, error) {
	var drive = [4]uint16{
		1: ':',
		2: '\\',
	}
	var drives []string

	getLogicalDrivesHandle := kernel32.NewProc("GetLogicalDrives")

	if ret, _, _ := getLogicalDrivesHandle.Call(0, 0, 0, 0); ret == 0 {
		errorVal, _, _ := getLastError.Call()
		return nil, fmt.Errorf("GetLogicalDrives failed with return code %d", errorVal)
	} else {
		driveLetters := bitsToDrives(uint32(ret))
		for _, driveLetter := range driveLetters {
			//fmt.Printf("Process drive letter '%s'\n", driveLetter)
			drive[0] = uint16(driveLetter[0])
			dt, err := getDriveType(drive[:])

			if err != nil {
				if err == errNoRootDir {
					continue
				}
				return nil, fmt.Errorf("error getting type of: %s: %s",
					syscall.UTF16ToString(drive[:]), err)
			}
			if dt != driveFixed {
				continue
			}
			drives = append(drives, syscall.UTF16ToString(drive[:]))
		}
	}
	return drives, nil
}

func getDriveType(rootPathName []uint16) (int, error) {
	rc, _, _ := getDriveTypeWProc.Call(
		uintptr(unsafe.Pointer(&rootPathName[0])),
	)

	dt := int(rc)

	if dt == driveUnknown || dt == driveNoRootDir {
		return -1, driveTypeErrors[dt]
	}

	return dt, nil
}

func bitsToDrives(bitMap uint32) (drives []string) {
	availableDrives := []string{"A", "B", "C", "D", "E", "F", "G", "H", "I", "J", "K", "L", "M", "N", "O", "P", "Q", "R", "S", "T", "U", "V", "W", "X", "Y", "Z"}

	for i := range availableDrives {
		if bitMap&1 == 1 {
			drives = append(drives, availableDrives[i])
		}
		bitMap >>= 1
	}

	return
}

func removeDuplicateStr(strSlice []string) []string {
	allKeys := make(map[string]bool)
	list := []string{}
	for _, item := range strSlice {
		if _, value := allKeys[item]; !value {
			allKeys[item] = true
			list = append(list, item)
		}
	}
	return list
}

func main() {
	var (
		rewrite    bool
		w          bool
		verbose    bool
		v          bool
		force      bool
		f          bool
		toSkip     []string
		foundFiles []string
	)
	appendSkip := func(dir string) error {
		toSkip = append(toSkip, dir)
		return nil
	}

	foundVulnerableFile := false
	fmt.Println()
	headColor := color.New(color.FgGreen).Add(color.Underline)
	headColor.Println("  *** ENEXSA Log4J Patcher ***  ")

	flag.BoolVar(&rewrite, "rewrite", false, "")
	flag.BoolVar(&w, "w", false, "")
	flag.BoolVar(&verbose, "verbose", false, "")
	flag.BoolVar(&v, "v", false, "")
	flag.BoolVar(&force, "force", false, "")
	flag.BoolVar(&f, "f", false, "")
	flag.Func("s", "", appendSkip)
	flag.Func("skip", "", appendSkip)
	flag.Usage = usage
	flag.Parse()
	dirs := flag.Args()
	if len(dirs) == 0 {
		drives, err := getdrives()
		if err != nil {
			color.Red(err.Error())
			os.Exit(1)
		}
		dirs = drives
	}
	if f {
		force = f
	}
	if v {
		verbose = v
	}
	if w {
		rewrite = w
	}
	log.SetFlags(log.LstdFlags | log.Lshortfile)
	logf := func(format string, v ...interface{}) {
		if verbose {
			log.Printf(format, v...)
		}
	}
	fmt.Println("Searching for Log4J vulnerability at:")
	for _, dir := range dirs {
		fmt.Printf(" -> %s\n", dir)
	}
	fmt.Println()
	seen := 0
	s := spinner.New(spinner.CharSets[14], 100*time.Millisecond) // Build our new spinner
	s.Color("white", "bold")
	s.Suffix = " Searching..."
	s.Start()
	walker := jar.Walker{
		Rewrite: rewrite,
		SkipDir: func(path string, d fs.DirEntry) bool {
			seen++
			if seen%5000 == 0 {
				logf("Scanned %d files", seen)
			}
			if !d.IsDir() {
				return false
			}
			for _, pattern := range toSkip {
				if ok, err := filepath.Match(pattern, path); err == nil && ok {
					return true
				}
			}
			if skipDirs[filepath.Base(path)] {
				return true
			}
			ignore, err := ignoreDir(path, force)
			if err != nil {
				log.Printf("Error scanning %s: %v", path, err)
			}
			return ignore
		},
		HandleError: func(path string, err error) {
			color.Yellow("Error: scanning %s: %v", path, err)
		},
		HandleReport: func(path string, r *jar.Report) {
			if !rewrite {
				foundVulnerableFile = true
				foundFiles = append(foundFiles, path)
			}
		},
		HandleRewrite: func(path string, r *jar.Report) {
			if rewrite {
				fmt.Println(path)
			}
		},
	}

	for _, dir := range dirs {
		logf("Scanning %s", dir)
		if err := walker.Walk(dir); err != nil {
			log.Printf("Error: walking %s: %v", dir, err)
		}
	}

	s.Stop()
	if foundVulnerableFile {
		var char string
		fmt.Println()
		fmt.Println("-------------------------------------")

		color.Yellow("Found files with vulnerability: ")
		var searchDirs []string
		for _, dir := range foundFiles {
			fmt.Println(dir)
			searchDirs = append(searchDirs, filepath.Dir(dir))
		}
		fmt.Println("-------------------------------------")

		searchDirs = removeDuplicateStr(searchDirs)
		//for _, dir := range searchDirs {
		//	fmt.Println(dir)
		//}

		fmt.Print("Do you want to fix found files? [y/n]")
		fmt.Scanln(&char)
		char = strings.Replace(char, "\r\n", "", -1)
		if strings.Compare("y", char) == 0 {
			fmt.Println()
			color.Green("Fixing found files...")
			s.Suffix = " Fixing..."
			s.Start()
			rewrite = true
			walker.Rewrite = true

			for _, dir := range dirs {
				logf("Scanning %s", dir)
				if err := walker.Walk(dir); err != nil {
					log.Printf("Error: walking %s: %v", dir, err)
				}
			}
			s.Stop()
			color.Green("Finished")
		} else {
			color.Yellow("Fixing cancelled!")
		}
	} else {
		color.Green("No vulnerable files found.")
	}
}
