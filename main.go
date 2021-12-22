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
	"log"
	"math"
	"os"
	"path"
	"path/filepath"
	"strings"
	"sync"
)

var (
	jndiLookupClassVersionHash = map[string]string{
		"39a495034d37c7934b64a9aa686ea06b61df21aa222044cc50a47d6903ba1ca8": "2.0-beta9",
		"a03e538ed25eff6c4fe48aabc5514e5ee687542f29f2206256840e74ed59bcd2": "2.0-rc2",
		"fd6c63c11f7a6b52eff04be1de3477c9ddbbc925022f7216320e6db93f1b7d29": "2.0",
		"964fa0bf8c045097247fa0c973e0c167df08720409fd9e44546e0ceda3925f3e": "2.0.1",
		"9626798cce6abd0f2ffef89f1a3d0092a60d34a837a02bbe571dbe00236a2c8c": "2.0.2",
		"a768e5383990b512f9d4f97217eda94031c2fa4aea122585f5a475ab99dc7307": "2.1",
		"0ad99a95ff637fc966fc4ce5fe1f9e78d3b24b113282f9990b95a6fde3383d9c": "2.3.1",
		"a534961bbfce93966496f86c9314f46939fd082bb89986b48b7430c3bea903f7": "2.4",
		"e8ffed196e04f81b015f847d4ec61f22f6731c11b5a21b1cfc45ccbc58b8ea45": "2.6",
		"cee2305065bb61d434cdb45cfdaa46e7da148e5c6a7678d56f3e3dc8d7073eae": "2.7",
		"66c89e2d5ae674641138858b571e65824df6873abb1677f7b2ef5c0dd4dbc442": "2.8",
		"d4ec57440cd6db6eaf6bcb6b197f1cbaf5a3e26253d59578d51db307357cbf15": "2.8.2",
		"0f038a1e0aa0aff76d66d1440c88a2b35a3d023ad8b2e3bac8e25a3208499f7e": "2.10.0",
		"5c104d16ff9831b456e4d7eaf66bcf531f086767782d08eece3fb37e40467279": "2.12.0",
		"edb797a8633f629b7c2187ccafd259a16a0b7b4cce4d42e646f8472358b8962a": "2.12.3",
		"febbc7867784d0f06934fec59df55ee45f6b24c55b17fff71cc4fca80bf22ebb": "2.12.2",
		"2b32bfc0556ea59307b9b2fde75b6dfbb5bf4f1d008d1402bc9a2357d8a8c61f": "2.13.0",
		"84057480ba7da6fb6d9ea50c53a00848315833c1f34bf8f4a47f11a14499ae3f": "2.14.0",
		"e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855": "2.16.0b",
		"ddad241274b834182525eeddc35c3198247507bd2df59645b58b94cd18fada7c": "2.17.0",
	}
)

var printMutex = new(sync.Mutex)


type jar struct {
	name    string
	version *version.Version
	unknown bool
}

func (j *jar) check() {
	if isDir, err := IsDirectory(j.name); err != nil {
		j.unknown = true
		if *debug {
			fmt.Println(err.Error())
		}
	} else if isDir {
		err := filepath.Walk(j.name,
			func(osPathname string, info os.FileInfo, err error) error {
				if strings.HasSuffix(osPathname, "log4j/core/lookup/JndiLookup.class") {
					err := func() error {
						if size, err := FileSize(osPathname); err != nil {
							return errors.New("cannot get size of JndiLookup.class")
						} else if size > int64(math.Pow(2, 20)) {
							return errors.New("JndiLookup.class is too big")
						}
						if data, err := os.ReadFile(osPathname); err != nil {
							return err
						} else {
							hash := fmt.Sprintf("%x", sha256.Sum256(data))
							if sVersion, ok := jndiLookupClassVersionHash[hash]; ! ok {
								j.unknown = true
								if *debug {
									fmt.Printf("unknown version (hash %s) of JndiLookup.class for file %s\n", hash, j.name)
								}
							} else if jVersion, err := version.NewVersion(sVersion)	;err != nil {
								j.unknown = true
								if *debug {
									fmt.Printf("error converting version %s: %e\n", sVersion, err)
								}
							} else {
								j.setVersion(jVersion)
							}
						}
						return nil
					}()
					if err != nil {
						j.unknown = true
						if *debug {
							log.Printf("error reading %q: %v", osPathname, err)
						}
					}
				} else if osPathname == j.name {
				} else if path.Ext(osPathname) == ".jar" || path.Ext(osPathname) == ".war" {
					subJar := jar{name: osPathname}
					subJar.check()
					j.setVersion(subJar.version)
				}
				return nil
			})
		if err != nil {
			panic(err)
		}
	} else {
		j.checkFile(j.name, nil, 0, 0)
	}
}

func (j *jar) checkFile(pathToFile string, rd io.ReaderAt, size int64, depth int) {
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
				j.unknown = true
				if *debug {
					fmt.Println(err.Error())
				}
				return err
			}

			stat, err := f.Stat()
			if err != nil {
				j.unknown = true
				if *debug {
					fmt.Println(err.Error())
				}
				return err
			}

			size = stat.Size()
			rd = f
		}

		zipRd, err := zip.NewReader(rd, size)
		if err != nil {
			j.unknown = true
			if *debug {
				fmt.Println(err.Error())
			}
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
					hash := fmt.Sprintf("%x", sha256.Sum256(data))
					if sVersion, ok := jndiLookupClassVersionHash[hash]; ! ok {
						_ = subRd.Close()
						j.unknown = true
						if *debug {
							fmt.Printf("unknown version (hash %s) of JndiLookup.class for file %s\n", hash, j.name)
						}
					} else if jVersion, err := version.NewVersion(sVersion)	;err != nil {
						_ = subRd.Close()
						j.unknown = true
						if *debug {
							fmt.Printf("error converting version %s: %e\n", sVersion, err)
						}
					} else {
						j.setVersion(jVersion)
					}
				}
				_ = subRd.Close()
				return nil
			} else if path.Ext(file.Name) == ".jar" || path.Ext(file.Name) == ".war"  {
				if file.UncompressedSize64 > 500*1024*1024 {
					j.unknown = true
					if *debug {
						fmt.Printf("embedded jar file %q is too large (> 500 MB)", file.Name)
					}
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
						j.unknown = true
						if *debug {
							fmt.Printf("error while checking embedded jar file %q: %v", file.Name, err)
						}
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

func (j *jar) setVersion(newVersion *version.Version) {
	if newVersion == nil {
		return
	}
	if j.version == nil {
		j.version = newVersion
	}
	if j.version.GreaterThan(newVersion) {
		j.version = newVersion
	}
}

func (j jar) getState() string {

	if j.unknown {
		return "UNKNOWN"
	} else if j.version == nil {
			return "OK"
	} else {
		return j.version.String() + "+"
	}
}
func (j jar) printState() {
	printMutex.Lock()
	defer printMutex.Unlock()

	jState := j.getState()
	if jState == "OK" && ! *logOk {
		return
	}

	fmt.Printf("%-10.10s %s\n", jState, j.name)
}

var logOk = flag.Bool("ok", false, "also report OK lines")
var debug = flag.Bool("debug", false, "print debug messages")

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

