package jar

import (
	"archive/zip"
	"bytes"
	"crypto/sha256"
	"errors"
	"fmt"
	"github.com/hashicorp/go-version"
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
var filesMutex = new(sync.Mutex)
var jarsMutex = new(sync.Mutex)

type Jar struct {
	name       string
	version    *version.Version
	hash       string
	fileErrors FileErrors
	debug      bool
	poms       Paths
	classes    Paths
	excludes   Paths
}

type Jars map[string]*Jar

var jars = make(Jars)
var files = make(map[string]bool)

func NewJar(name string, debug bool, myClasses Paths, myPoms Paths, myExcludes Paths) *Jar {
	if evaluedName, err := filepath.EvalSymlinks(name); err == nil {
		// If there is an error, we have a broken symlink.
		// In that case we just create a jar for original name and leave to rest of the code
		// to handle the issue and report properly.
		// But this one seems fine, so let's use the actual file path for this jar.
		name = evaluedName
	}
	jarsMutex.Lock()
	defer jarsMutex.Unlock()
	if _, exists := jars[name]; exists {
		// This is already scanned. Let's skip this.
		return nil
	} else {
		j := &Jar{
			name:     name,
			debug:    debug,
			poms:     myPoms,
			classes:  myClasses,
			excludes: myExcludes,
		}
		jars[name] = j
		return j
	}
}

func (j Jar) CheckFile(path string) ([]byte, error) {
	// follow symlinks, and make sure we don't double scan
	if evaluatedPath, err := filepath.EvalSymlinks(path); err == nil {
		path = evaluatedPath
	}
	filesMutex.Lock()
	if _, exists := files[path]; exists {
		return nil, nil
	}
	files[path] = true
	filesMutex.Unlock()
	if j.excludes.Matches(path) {
		// Exclude if this file is on the excludes list
		return nil, nil
	}
	if j.poms.Matches(path) || j.classes.Matches(path) {
		if size, err := FileSize(path); err != nil {
			return nil, fmt.Errorf("cannot get size of %s", path)
		} else if size > int64(math.Pow(2, 20)) {
			return nil, fmt.Errorf("%s is too big", path)
		}
		if data, err := os.ReadFile(path); err != nil {
			return nil, err
		} else {
			return data, nil
		}
	}
	return nil, nil
}

func (j Jar) CheckFileInZip(file *zip.File) ([]byte, error) {
	if j.poms.Matches(file.Name) || j.classes.Matches(file.Name) {
		if file.UncompressedSize64 > uint64(math.Pow(2, 20)) {
			return nil, errors.New("JndiLookup.class is too big")
		}
		subRd, err := file.Open()
		if err != nil {
			return nil, err
		}

		if data, err := io.ReadAll(subRd); err != nil {
			return nil, err
		} else if err = subRd.Close(); err != nil {
			return nil, err
		} else {
			return data, nil
		}
	}
	return nil, nil
}

func (j *Jar) Excluded() bool {
	return j.excludes.Matches(j.name)
}

func (j *Jar) CheckPath() {
	var sVersion string
	if j.Excluded() {
		return
	}
	if isDir, err := IsDirectory(j.name); err != nil {
		j.fileErrors = append(j.fileErrors, FileError{FileErrorNoFile})
	} else if isDir {
		err := filepath.Walk(j.name,
			func(osPath string, info os.FileInfo, err error) error {
				if data, err := j.CheckFile(osPath); err != nil {
					return err
				} else if data != nil {
					if j.classes.Matches(osPath) {
						//log.Printf("class: %s", osPath)
						j.hash = fmt.Sprintf("%x", sha256.Sum256(data))
						if j.debug {
							log.Printf("%s:%s has hash %s", j.name, osPath, j.hash)
						}
					} else if j.poms.Matches(osPath) {
						//log.Printf("pom: %s", osPath)
						sVersion = versionFromPom(data)
						if sVersion == "" {
							return fmt.Errorf("could not find version in %s\n", osPath)
						} else if j.version, err = version.NewVersion(sVersion); err != nil {
							return fmt.Errorf("invalid version %s in %s\n", sVersion, osPath)
						} else {
							if j.debug {
								log.Printf("%s:%s reads version %s", j.name, osPath, j.version)
							}
						}
					}
				} else if osPath == j.name {
					// Skipping this jar because it is me
				} else if path.Ext(osPath) == ".jar" || path.Ext(osPath) == ".war" {
					if subJar := NewJar(osPath, j.debug, j.classes, j.poms, j.excludes); subJar != nil {
						subJar.CheckPath()
						j.setVersion(subJar.version)
					}
				}
				return nil
			})
		if err != nil {
			if fEID, ok := err.(FileError); ok {
				j.fileErrors = append(j.fileErrors, fEID)
			} else {
				j.fileErrors = append(j.fileErrors, FileError{FileErrorUnknown})
				if j.debug {
					fmt.Println(err.Error())
				}
			}
		}
	} else {
		j.CheckZip(j.name, nil, 0, 0)
	}
}

func (j *Jar) CheckZip(pathToFile string, rd io.ReaderAt, size int64, depth int) {
	var sVersion string
	if depth > 100 {
		j.fileErrors = append(j.fileErrors, FileError{FileErrorUnknown})
		if j.debug {
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
				return FileError{FileErrorNoFile}
			}

			stat, err := f.Stat()
			if err != nil {
				return err
			}

			size = stat.Size()
			if size == 0 {
				return FileError{FileErrorEmpty}
			}
			rd = f
		}

		zipRd, err := zip.NewReader(rd, size)
		if err != nil {
			return FileError{FileErrorNoZip}
		}

		for _, file := range zipRd.File {
			if data, err := j.CheckFileInZip(file); err != nil {
				return err
			} else if data != nil {
				if j.classes.Matches(file.Name) {
					//log.Printf("class: %s", file.Name)
					j.hash = fmt.Sprintf("%x", sha256.Sum256(data))
					if j.debug {
						log.Printf("%s:%s has hash %s", j.name, file.Name, j.hash)
					}
				} else if j.poms.Matches(file.Name) {
					//log.Printf("pom: %s", file.Name)
					sVersion = versionFromPom(data)
					if sVersion == "" {
						return fmt.Errorf("could not find version in %s in %s\n", file.Name, j.name)
					} else if j.version, err = version.NewVersion(sVersion); err != nil {
						return fmt.Errorf("invalid version %s in %s in %s\n", sVersion, file.Name, j.name)
					} else {
						if j.debug {
							log.Printf("%s:%s reads version %s", j.name, file.Name, j.version)
						}
					}
				}
			} else if path.Ext(file.Name) == ".jar" || path.Ext(file.Name) == ".war" {
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

						j.CheckZip(pathToFile, bytes.NewReader(buf.Bytes()), int64(buf.Len()), depth+1)
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
		if fEID, ok := err.(FileError); ok {
			j.fileErrors = append(j.fileErrors, fEID)
		} else {
			j.fileErrors = append(j.fileErrors, FileError{FileErrorUnknown})
			if j.debug {
				fmt.Println(err.Error())
			}
		}
	}
}

func (j *Jar) setVersion(newVersion *version.Version) bool {
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

func (j Jar) getState() string {
	if j.fileErrors.MaxID() > FileErrorNone {
		return j.fileErrors.MaxID().String()
	} else if j.version != nil {
		if j.hash != "" {
			return "DETECTED"
		} else {
			return "WORKAROUND"
		}
	} else if j.hash == "" {
		return "UNDETECTED"
	} else {
		return "DETECTED"
	}
}

func (j Jar) PrintState(logOk bool, logHash bool, logVersion bool) {
	if j.Excluded() {
		return
	}
	var cols []string
	printMutex.Lock()
	defer printMutex.Unlock()

	jState := j.getState()
	if jState == "UNDETECTED" && !logOk {
		return
	}
	if logHash {
		hash := "UNKNOWN"
		if j.hash != "" {
			hash = j.hash
		}
		cols = append(cols, fmt.Sprintf("%-64.64s", hash))
	}
	if logVersion {
		if j.version == nil {
			cols = append(cols, "VERSION_UNKNOWN")
		} else {
			cols = append(cols, fmt.Sprintf("%-15.15s", j.version.String()))
		}
	}
	cols = append(cols, fmt.Sprintf("%-10.10s", jState))
	cols = append(cols, j.name)
	fmt.Println(strings.Join(cols, " "))
}
