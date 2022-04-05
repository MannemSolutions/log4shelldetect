package main

import (
	"flag"
	"fmt"
	"github.com/mannemsolutions/log4shelldetect/pkg/jar"
	"log"
	"os"
	"path/filepath"
)

var logOk = flag.Bool("ok", false, "also report jar files without the specified modules")
var debug = flag.Bool("debug", false, "print debug messages")
var logHash = flag.Bool("hash", false, "print sha-256 hash of detected .class file")
var logVersion = flag.Bool("modversion", false, "print version of module")

type arrayPaths []string

func (i *arrayPaths) String() string {
	return "module classes / pom files to scan for. Can be supplied multiple times. Supply at least once."
}

func (i *arrayPaths) Set(value string) error {
	*i = append(*i, value)
	return nil
}

var myPoms arrayPaths
var myClasses arrayPaths
var myExcludes arrayPaths

func main() {
	flag.Var(&myPoms, "pom", "Module pom files to scan for.")
	flag.Var(&myClasses, "class", "Module class files to scan for.")
	flag.Var(&myExcludes, "exclude", "Exclude files when paths match.")
	flag.Parse()

	if flag.Arg(0) == "" || len(myPoms)+len(myClasses) < 1 {
		fmt.Println("Usage: log4shelldetect [options] <path>")
		fmt.Println("Scans a file or folder recursively for jar files that may be")
		fmt.Println("vulnerable to Log4Shell (CVE-2021-44228) or other vulnerabilities")
		fmt.Println(" by inspecting the class paths inside the Jar")
		fmt.Println("")
		fmt.Println("Options:")
		flag.PrintDefaults()
		os.Exit(1)
	}
	if classes, err := jar.GetPaths(myClasses); err != nil {
		log.Fatalln(err)
	} else if poms, err := jar.GetPaths(myPoms); err != nil {
		log.Fatalln(err)
	} else if excludes, err := jar.GetPaths(myExcludes); err != nil {
		log.Fatalln(err)
	} else {
		for _, target := range flag.Args() {
			if isDir, err := jar.IsDirectory(target); err != nil && !isDir {
				if j := jar.NewJar(target, *debug, classes, poms, excludes); j != nil {
					j.CheckZip(target, nil, 0, 0)
					j.PrintState(*logOk, *logHash, *logVersion)
				}
				return
			}

			pool := make(chan struct{}, 8)

			err := filepath.Walk(target,
				func(osPathname string, info os.FileInfo, err error) error {
					if filepath.Ext(osPathname) == ".jar" || filepath.Ext(osPathname) == ".war" {
						if j := jar.NewJar(osPathname, *debug, classes, poms, excludes); j!= nil {
							pool <- struct{}{}
							go func() {
								j.CheckPath()
								j.PrintState(*logOk, *logHash, *logVersion)
								<-pool
							}()
						}
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
	}
}
