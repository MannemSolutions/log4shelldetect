package jar

import (
	"archive/zip"
	"bytes"
	"crypto/sha256"
	"errors"
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

type Jar struct {
	name       string
	version    *version.Version
	hash       string
	fileErrors FileErrors
	debug      bool
}

func NewJar(name string, debug bool) (j *Jar) {
	return &Jar{
		name:  name,
		debug: debug,
	}
}

func (j *Jar) Check() {
	var sVersion string
	if isDir, err := IsDirectory(j.name); err != nil {
		j.fileErrors = append(j.fileErrors, FileError{FileErrorNoFile})
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
					subJar := Jar{name: osPathname}
					subJar.Check()
					j.setVersion(subJar.version)
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
		j.CheckFile(j.name, nil, 0, 0)
	}
}

func (j *Jar) CheckFile(pathToFile string, rd io.ReaderAt, size int64, depth int) {
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
					} else if jVersion, err := version.NewVersion(sVersion); err != nil {
						return fmt.Errorf("invalid version in pom.properties %s for %s\n", sVersion, j.name)
					} else {
						j.setVersion(jVersion)
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

						j.CheckFile(pathToFile, bytes.NewReader(buf.Bytes()), int64(buf.Len()), depth+1)
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
	} else if j.version == nil {
		return "NOLOG4J"
	} else if j.hash == "" {
		return "WORKAROUND"
	} else {
		return "LOG4J"
	}
}
func (j Jar) PrintState(logOk bool, logHash bool, logVersion bool) {
	var cols []string
	printMutex.Lock()
	defer printMutex.Unlock()

	jState := j.getState()
	if jState == "NOLOG4J" && !logOk {
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
			cols = append(cols, "NOLOG4J   ")
		} else {
			cols = append(cols, fmt.Sprintf("%-10.10s", j.version.String()))
		}
	}
	cols = append(cols, fmt.Sprintf("%-10.10s", jState))
	cols = append(cols, j.name)
	fmt.Println(strings.Join(cols, " "))
}
