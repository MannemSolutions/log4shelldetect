package main

import (
	"archive/zip"
	"bytes"
	"crypto/sha256"
	"errors"
	"flag"
	"fmt"
    "github.com/hashicorp/go-version"
	"io"
	"math"
	"os"
	"path"
	"path/filepath"
	"strings"
	"sync"
)

var printMutex = new(sync.Mutex)

type jar struct {
	name      string
	version   *version.Version
	hash      string
	unknown   bool
}

func (j *jar) check() {
	var sVersion string
	if isDir, err := IsDirectory(j.name); err != nil {
		j.unknown = true
		if *debug {
			fmt.Println(err.Error())
		}
	} else if isDir {
		err := filepath.Walk(j.name,
			func(osPathname string, info os.FileInfo, err error) error {
				if strings.HasSuffix(osPathname, "log4j/core/lookup/JndiLookup.class") {
					if size, err := FileSize(osPathname); err != nil {
						return errors.New("cannot get size of JndiLookup.class")
					} else if size > int64(math.Pow(2, 20)) {
						return errors.New("JndiLookup.class is too big")
					}
					if data, err := os.ReadFile(osPathname); err != nil {
						return err
					} else {
						j.hash = fmt.Sprintf("%x", sha256.Sum256(data))
					}
				}
				if strings.HasSuffix(osPathname, "META-INF/maven/org.apache.logging.log4j/log4j-core/pom.properties") {
					if size, err := FileSize(osPathname); err != nil {
						return errors.New("cannot get size of pom.properties")
					} else if size > int64(math.Pow(2, 20)) {
						return errors.New("pom.properties is too big")
					}
					if data, err := os.ReadFile(osPathname); err != nil {
						return err
					} else {
						sVersion = ""
						lines := string(data)
						for _, line := range strings.Split(lines, "\n") {
							if strings.HasPrefix(line, "version=") {
								sVersion = strings.Replace(line, "version=", "", 1)
							}
						}
						if sVersion == "" {
							return fmt.Errorf("could not find version in pom.properties %s\n", j.name)
						} else if jVersion, err := version.NewVersion(sVersion); err != nil {
							return fmt.Errorf("invalid version in pom.properties %s for %s\n", sVersion, j.name)
						} else {
							j.setVersion(jVersion)
						}
					}
				} else if osPathname == j.name {
					// Skipping this jar because it is me
				} else if path.Ext(osPathname) == ".jar" || path.Ext(osPathname) == ".war" {
					subJar := jar{name: osPathname}
					subJar.check()
					j.setVersion(subJar.version)
				}
				return nil
			})
		if err != nil {
			j.unknown = true
			if *debug {
				fmt.Printf("error parsing %s: %s\n", j.name, err.Error())
			}
		}
	} else {
		j.checkFile(j.name, nil, 0, 0)
	}
}

func (j *jar) checkFile(pathToFile string, rd io.ReaderAt, size int64, depth int) {
	var sVersion string
	if depth > 100 {
		j.unknown = true
		if *debug {
			fmt.Printf("reached recursion limit of 100 (why do you have so many jars in jars???)")
		}
	}

	if pathToFile == "" {
		pathToFile = j.name
	}

	err := func() error {
		if rd == nil {
			// #nosec G304
			f, err := os.Open(pathToFile)
			if err != nil {
				return err
			}

			stat, err := f.Stat()
			if err != nil {
				return err
			}

			size = stat.Size()
			rd = f
		}

		zipRd, err := zip.NewReader(rd, size)
		if err != nil {
			return err
		}

		for _, file := range zipRd.File {
			if strings.HasSuffix(file.Name, "log4j/core/lookup/JndiLookup.class") {
				if file.UncompressedSize64 > uint64(math.Pow(2, 20)) {
					return errors.New("JndiLookup.class is too big")
				}
				subRd, err := file.Open()
				if err != nil {
					return err
				}

				if data, err := io.ReadAll(subRd); err != nil {
					return err
				} else {
					j.hash = fmt.Sprintf("%x", sha256.Sum256(data))
				}
				_ = subRd.Close()
			} else if strings.HasSuffix(file.Name, "META-INF/maven/org.apache.logging.log4j/log4j-core/pom.properties") {
				if file.UncompressedSize64 > uint64(math.Pow(2, 20)) {
					return errors.New("pom.properties is too big")
				}
				subRd, err := file.Open()
				if err != nil {
					return err
				}

				if data, err := io.ReadAll(subRd); err != nil {
					return err
				} else {
					lines := string(data)
					for _, line := range strings.Split(lines, "\n") {
						if strings.HasPrefix(line, "version=") {
							sVersion = strings.Replace(line, "version=", "", 1)
						}
					}
					if sVersion == "" {
						return fmt.Errorf("could not find version in pom.properties %s\n", j.name)
					} else if jVersion, err := version.NewVersion(sVersion) ;err != nil {
						return fmt.Errorf("invalid version in pom.properties %s for %s\n", sVersion, j.name)
					} else {
						j.setVersion(jVersion)
					}
				}
			} else if path.Ext(file.Name) == ".jar" || path.Ext(file.Name) == ".war"  {
				if file.UncompressedSize64 > 500*1024*1024 {
					return fmt.Errorf("embedded jar file %q is too large (> 500 MB)", file.Name)
				} else {
					err := func() error {
						subRd, err := file.Open()
						if err != nil {
							return err
						}

						buf := bytes.NewBuffer(make([]byte, 0, file.UncompressedSize64))
						_, err = buf.ReadFrom(subRd)
						_ = subRd.Close()
						if err != nil {
							return err
						}

						j.checkFile(pathToFile, bytes.NewReader(buf.Bytes()), int64(buf.Len()), depth+1)
						return nil
					}()
					if err != nil {
						return fmt.Errorf("error while checking embedded jar file %q: %v", file.Name, err)
					}
				}
			}
		}
		return nil
	}()
	if err != nil {
		j.unknown = true
		if *debug {
			fmt.Println(err.Error())
		}
	}
}

func (j *jar) setVersion(newVersion *version.Version) bool {
	if newVersion == nil {
		return false
	}
	if j.version == nil {
		j.version = newVersion
		return true
	}
	if j.version.GreaterThan(newVersion) {
		j.version = newVersion
		return true
	}
	return false
}

func (j jar) getState() string {
	if j.unknown {
		return "UNKNOWN"
	} else if j.version == nil {
		return "NOLOG4J"
	} else if j.hash == "" {
		return "PATCHED"
	} else {
		return "LOG4J"
	}
}
func (j jar) printState() {
	var cols []string
	printMutex.Lock()
	defer printMutex.Unlock()

	jState := j.getState()
	if jState == "NOLOG4J" && ! *logOk {
		return
	}
	if *logHash {
		hash := "UNKNOWN"
		if j.hash != "" {
			hash = j.hash
		}
		cols = append(cols, fmt.Sprintf("%-64.64s", hash))
	}
	if *logVersion {
		if j.version == nil {
			cols = append(cols, "NOLOG4J   ")
		 } else {
			cols = append(cols, fmt.Sprintf("%-10.10s", j.version.String()))
		}
	}
	cols = append(cols, fmt.Sprintf("%-7.7s", jState))
	cols = append(cols, j.name)
	fmt.Println(strings.Join(cols, " "))
}

var logOk = flag.Bool("ok", false, "also report jar files without log4j")
var debug = flag.Bool("debug", false, "print debug messages")
var logHash = flag.Bool("hash", false, "print sha-256 hash of JndiLookup.class")
var logVersion = flag.Bool("l4jversion", false, "print version of log4j")

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
			if filepath.Ext(osPathname) == ".jar" || filepath.Ext(osPathname) == ".war" {
				j := jar{name: osPathname}
				pool <- struct{}{}
				go func() {
					j.check()
					j.printState()
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

