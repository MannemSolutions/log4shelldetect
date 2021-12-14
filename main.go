package main

import (
	"archive/zip"
	"bytes"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"math"
	"os"
	"path"
	"path/filepath"
	"strings"
	"sync"
)

var printMutex = new(sync.Mutex)

type status int

func (s status) String() (ret string) {

	switch s {
	case StatusOK:
		return "OK"
	case StatusPatched:
		return "PATCHED"
	case StatusVulnerable:
		return "VULNRBL"
	case StatusMaybe:
		return "MAYBE"
	case StatusUnknown:
		return "UNKNOWN"
	}
	return "?"
}

const (
	StatusOK       status = iota
	StatusPatched
	StatusUnknown
	StatusMaybe
	StatusVulnerable
)

type jar struct {
	name       string
	desc       []string
	vulnerable bool
	maybe      bool
	patched    bool
}

func (j *jar) check() {
	if isDir, err := IsDirectory(j.name); err != nil {
		j.desc = append(j.desc, err.Error())
		j.setStatus(StatusUnknown)
	} else if isDir {
		err := filepath.Walk(j.name,
			func(osPathname string, info os.FileInfo, err error) error {
				if strings.HasSuffix(osPathname, "log4j/core/lookup/JndiLookup.class") {
					j.setStatus(StatusVulnerable)
				} else if strings.HasSuffix(osPathname, "lookup/JndiLookup.class") {
					j.setStatus(StatusMaybe)
				} else if strings.HasSuffix(osPathname, "log4j/core/appender/mom/JmsAppender$Builder.class") {
					err := func() error {
						if size, err := FileSize(osPathname); err != nil {
							return errors.New("cannot get size of jmsAppender")
						} else if size > int64(math.Pow(2, 20)) {
							return errors.New("jmsAppender is too big")
						}
						if data, err := os.ReadFile(osPathname); err != nil {
							return err
						} else if bytes.Contains(data, []byte("allowedLdapHosts")) {
							j.setStatus(StatusPatched)
						}
						return nil
					}()
					if err != nil {
						log.Printf("error reading %q: %v", osPathname, err)
					}
				} else if osPathname == j.name {
				} else if path.Ext(osPathname) == ".jar" {
					subJar := jar{name: osPathname}
					subJar.check()
					j.setStatus(subJar.getStatus())
				}
				return nil
			})
		if err != nil {
			panic(err)
		}
	} else {
		j.checkFile(j.name, nil, 0, 0)
	}
	j.printState()
}

func (j *jar) checkFile(pathToFile string, rd io.ReaderAt, size int64, depth int) {
	if depth > 100 {
		j.desc = append(j.desc, "reached recursion limit of 100 (why do you have so many jars in jars???)")
		j.setStatus(StatusUnknown)
	}

	if pathToFile == "" {
		pathToFile = j.name
	}

	err := func() error {
		if rd == nil {
			f, err := os.Open(pathToFile)
			if err != nil {
				j.desc = append(j.desc, err.Error())
				return err
			}
			defer f.Close()

			stat, err := f.Stat()
			if err != nil {
				j.desc = append(j.desc, err.Error())
				return err
			}

			size = stat.Size()
			rd = f
		}

		zipRd, err := zip.NewReader(rd, size)
		if err != nil {
			j.desc = append(j.desc, err.Error())
			return err
		}

		for _, file := range zipRd.File {
			if strings.HasSuffix(file.Name, "log4j/core/lookup/JndiLookup.class") {
				j.setStatus(StatusVulnerable)
			}

			if strings.HasSuffix(file.Name, "lookup/JndiLookup.class") {
				j.setStatus(StatusMaybe)
			}

			if strings.HasSuffix(file.Name, "log4j/core/appender/mom/JmsAppender$Builder.class") {
				err := func() error {
					if file.UncompressedSize64 > 1024*1024 {
						return errors.New("jmsAppender is too big")
					}

					subRd, err := file.Open()
					if err != nil {
						return err
					}
					defer subRd.Close()

					data, err := io.ReadAll(subRd)
					if err != nil {
						return err
					}

					if bytes.Contains(data, []byte("allowedLdapHosts")) {
						j.setStatus(StatusPatched)
					}

					return nil
				}()
				if err != nil {
					log.Printf("error reading %q: %v", file.Name, err)
				}
			}

			if path.Ext(file.Name) == ".jar" {
				if file.UncompressedSize64 > 500*1024*1024 {
					j.setStatus(StatusUnknown)
					j.desc = append(j.desc, fmt.Sprintf("embedded jar file %q is too large (> 500 MB)", file.Name))
				} else {
					err := func() error {
						subRd, err := file.Open()
						if err != nil {
							return err
						}

						defer subRd.Close()

						buf := bytes.NewBuffer(make([]byte, 0, file.UncompressedSize64))
						_, err = buf.ReadFrom(subRd)
						if err != nil {
							return err
						}

						j.checkFile(pathToFile, bytes.NewReader(buf.Bytes()), int64(buf.Len()), depth+1)
						return nil
					}()
					if err != nil {
						j.setStatus(StatusUnknown)
						j.desc = append(j.desc, fmt.Sprintf("error while checking embedded jar file %q: %v", file.Name, err))
					}
				}
			}
		}


		return nil
	}()
	if err != nil {
		j.setStatus(StatusUnknown)
		j.desc = append(j.desc, err.Error())
	}
}

func (j *jar) setStatus(newState status) {
	switch newState {
	case StatusVulnerable:
		j.vulnerable = true
	case StatusMaybe:
		j.maybe = true
	case StatusPatched:
		j.patched = true
	}
}

func (j *jar) getStatus() status {

	if ! j.vulnerable {
		if j.maybe {
			return StatusMaybe
		} else {
			return StatusOK
		}
	} else if j.patched {
		return StatusPatched
	} else {
		return StatusVulnerable
	}
}

func (j jar) printState() {
	printMutex.Lock()
	defer printMutex.Unlock()

	if *mode == "list" {
		if j.vulnerable || j.maybe {
			fmt.Println(j.name)
		}

		return
	}

	jState := j.getStatus()
	if jState == StatusOK && ! *logOk {
			return
	}

	var desc string
	if len(j.desc) > 0 {
		desc = fmt.Sprintf(": %s", strings.Join(j.desc, ", "))
	}
	fmt.Printf("%-8.8s %s %s\n", jState.String(), j.name, desc)
}

var mode = flag.String("mode", "report", "the output mode, either \"report\" (every jar pretty printed) or \"list\" (list of potentially vulnerable files)")
var logOk = flag.Bool("ok", false, "also report OK lines")

func IsDirectory(path string) (bool, error) {
	fileInfo, err := os.Stat(path)
	if err != nil{
		return false, err
	}
	return fileInfo.IsDir(), err
}
func FileSize(path string) (int64, error) {
	fileInfo, err := os.Stat(path)
	if err != nil{
		return -1, err
	}
	return fileInfo.Size(), err
}

func main() {
	flag.Parse()

	if flag.Arg(0) == "" {
		fmt.Println("Usage: log4shelldetect [options] <path>")
		fmt.Println("Scans a file or folder recursively for jar files that may be")
		fmt.Println("vulnerable to Log4Shell (CVE-2021-44228) by inspecting")
		fmt.Println("the class paths inside the Jar")
		fmt.Println("")
		fmt.Println("Options:")
		flag.PrintDefaults()
		os.Exit(1)
	}

	target := flag.Arg(0)

	if isDir, err := IsDirectory(target); err != nil && ! isDir {
		j := jar{name: target}
		j.checkFile(target, nil, 0, 0)
		j.printState()
		return
	}

	pool := make(chan struct{}, 8)

	err := filepath.Walk(target,
		func(osPathname string, info os.FileInfo, err error) error {
			if filepath.Ext(osPathname) == ".jar" {
				j := jar{name: osPathname}
				pool <- struct{}{}
				go func() {
					j.check()
					<-pool
				}()
			}
			return nil
		})
	if err != nil {
		panic(err)
	}

	for i := 0; i < cap(pool); i++ {
		pool <- struct{}{}
	}
}

