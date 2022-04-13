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

type Jars map[string]*Jar
type Jar struct {
	name       string
	fileErrors FileErrors
	debug      bool
	scanTypes  *ScanTypes
	excludes   Paths
	hash       string
}

var jars = make(Jars)
var files = make(map[string]bool)

func NewJar(name string, debug bool, scanTypes *ScanTypes, myExcludes Paths) *Jar {
	if evaluatedName, err := filepath.EvalSymlinks(name); err == nil {
		// If there is an error, we have a broken symlink.
		// In that case we just create a jar for original name and leave to rest of the code
		// to handle the issue and report properly.
		// But this one seems fine, so let's use the actual file path for this jar.
		name = evaluatedName
	}
	jarsMutex.Lock()
	defer jarsMutex.Unlock()
	if _, exists := jars[name]; exists {
		// This is already scanned. Let's skip this.
		return nil
	} else {
		j := &Jar{
			name:      name,
			debug:     debug,
			scanTypes: scanTypes,
			excludes:  myExcludes,
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
		filesMutex.Unlock()
		return nil, nil
	}
	files[path] = true
	filesMutex.Unlock()
	if j.excludes.Matches(path) {
		// Exclude if this file is on the excludes list
		return nil, nil
	}
	if j.scanTypes.Matches(path) {
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
	if j.scanTypes.Matches(file.Name) {
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

func (j Jar) Excluded() bool {
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
					for stName, st := range j.scanTypes.scanTypes {
						if st.classes.Matches(osPath) {
							//log.Printf("class: %s", osPath)
							hash := fmt.Sprintf("%x", sha256.Sum256(data))
							st.AddHash(hash)
							if j.debug {
								log.Printf("%s:%s has hash %s", j.name, osPath, hash)
							}
							if sVersion, exists := st.version_hashes[hash]; exists {
								if myVersion, err := version.NewVersion(sVersion); err != nil {
									return fmt.Errorf("invalid version %s in hash %s\n", sVersion, hash)
								} else {
									st.AddVersion(*myVersion)
									if j.debug {
										log.Printf("%s hash %s reads version %s", j.name, hash, myVersion)
									}
								}
							}
						} else if st.poms.Matches(osPath) {
							//log.Printf("pom: %s", osPath)
							sVersion = versionFromPom(data)
							if sVersion == "" {
								return fmt.Errorf("could not find version in %s\n", osPath)
							} else if myVersion, err := version.NewVersion(sVersion); err != nil {
								return fmt.Errorf("invalid version %s in %s\n", sVersion, osPath)
							} else {
								st.AddVersion(*myVersion)
								if j.debug {
									log.Printf("%s:%s reads version %s", j.name, osPath, myVersion)
								}
							}
						}
						j.scanTypes.scanTypes[stName] = st
					}
				} else if osPath == j.name {
					// Skipping this jar because it is me
				} else if path.Ext(osPath) == ".jar" || path.Ext(osPath) == ".war" {
					if subJar := NewJar(osPath, j.debug, j.scanTypes, j.excludes); subJar != nil {
						subJar.CheckPath()
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
				for stName, st := range j.scanTypes.scanTypes {
					if st.classes.Matches(file.Name) {
						//log.Printf("class: %s", file.Name)
						hash := fmt.Sprintf("%x", sha256.Sum256(data))
						st.AddHash(hash)
						if j.debug {
							log.Printf("%s:%s has hash %s", j.name, file.Name, hash)
						}
						if sVersion, exists := st.version_hashes[hash]; exists {
							if myVersion, err := version.NewVersion(sVersion); err != nil {
								return fmt.Errorf("invalid version %s in hash %s\n", sVersion, hash)
							} else {
								st.AddVersion(*myVersion)
								if j.debug {
									log.Printf("%s hash %s reads version %s", j.name, hash, myVersion)
								}
							}
						}
					} else if st.poms.Matches(file.Name) {
						//log.Printf("pom: %s", file.Name)
						sVersion = versionFromPom(data)
						if sVersion == "" {
							return fmt.Errorf("could not find version in %s in %s\n", file.Name, j.name)
						} else if myVersion, err := version.NewVersion(sVersion); err != nil {
							return fmt.Errorf("invalid version %s in %s in %s\n", sVersion, file.Name, j.name)
						} else {
							st.AddVersion(*myVersion)
							if j.debug {
								log.Printf("%s:%s reads version %s", j.name, file.Name, myVersion)
							}
						}
					}
					j.scanTypes.scanTypes[stName] = st
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

func (j *Jar) Hash() string {
	if j.hash != "" {
		return j.hash
	}
	if isDir, err := IsDirectory(j.name); err != nil {
		// Only an issue for broken symlinks
		//log.Printf("Could not read hash of %s, IsDirectory issue", j.name)
		return ""
	} else if isDir {
		j.hash = fmt.Sprintf("%x", HashDir(j.name))
	} else {
		j.hash = fmt.Sprintf("%x", HashFile(j.name))
	}
	return j.hash
}

func (j Jar) PrintStates(logOk bool, logJarHash bool, logLibHash bool, logVersion bool) {
	if j.Excluded() {
		return
	}
	var cols []string
	var jState string
	printMutex.Lock()
	defer printMutex.Unlock()

	for name, st := range j.scanTypes.scanTypes {
		cols = []string{fmt.Sprintf("%-20.20s", name)}

		if j.fileErrors.MaxID() > FileErrorNone {
			jState = j.fileErrors.MaxID().String()
		} else {
			jState = st.getState()
		}
		if jState == "UNDETECTED" && !logOk {
			continue
		}
		if logJarHash {
			cols = append(cols, fmt.Sprintf("%-64.64s", j.Hash()))
		}
		if logLibHash {
			libHash := "UNKNOWN"
			if len(st.hashes) > 0 {
				// multiple hashes. Just use last...
				libHash = st.hashes[len(st.hashes)-1]
			}
			cols = append(cols, fmt.Sprintf("%-64.64s", libHash))
		}
		if logVersion {
			if lowestVersion := st.LowestVersion(); lowestVersion == nil {
				cols = append(cols, "VERSION_UNKNOWN")
			} else {
				cols = append(cols, fmt.Sprintf("%-15.15s", lowestVersion.String()))
			}
		}
		cols = append(cols, fmt.Sprintf("%-10.10s", jState))
		cols = append(cols, j.name)
		fmt.Println(strings.Join(cols, " | "))
	}
}
