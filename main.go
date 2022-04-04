package main

import (
	"flag"
	"fmt"
	"github.com/mannemsolutions/log4shelldetect/pkg/jar"
	"os"
	"path/filepath"
)

var logOk = flag.Bool("ok", false, "also report jar files without the specified modules")
var debug = flag.Bool("debug", false, "print debug messages")
var logHash = flag.Bool("hash", false, "print sha-256 hash of detected .class file")
var logVersion = flag.Bool("modversion", false, "print version of module")

type arrayFlags []string

func (i *arrayFlags) String() string {
	return "module classes / pom files to scan for. Can be supplied multiple times. Supply at least once."
}

func (i *arrayFlags) Set(value string) error {
	*i = append(*i, value)
	return nil
}

var myFlags arrayFlags

func main() {
	flag.Var(&myFlags, "mod", "List of module files to scan for.")
	flag.Parse()

	if flag.Arg(0) == "" || len(myFlags) < 1 {
		fmt.Println("Usage: log4shelldetect [options] <path>")
		fmt.Println("Scans a file or folder recursively for jar files that may be")
		fmt.Println("vulnerable to Log4Shell (CVE-2021-44228) or other vulnerabilities")
		fmt.Println(" by inspecting the class paths inside the Jar")
		fmt.Println("")
		fmt.Println("Options:")
		flag.PrintDefaults()
		os.Exit(1)
	}

	for _, target := range flag.Args() {
		if isDir, err := jar.IsDirectory(target); err != nil && !isDir {
			j := jar.NewJar(target, *debug)
			for _, path := range myFlags {
				j.AddPath(path)
			}
			j.CheckZip(target, nil, 0, 0)
			j.PrintState(*logOk, *logHash, *logVersion)
			return
		}

		pool := make(chan struct{}, 8)

		err := filepath.Walk(target,
			func(osPathname string, info os.FileInfo, err error) error {
				if filepath.Ext(osPathname) == ".jar" || filepath.Ext(osPathname) == ".war" {
					j := jar.NewJar(osPathname, *debug)
					for _, path := range myFlags {
						j.AddPath(path)
					}
					pool <- struct{}{}
					go func() {
						j.CheckPath()
						j.PrintState(*logOk, *logHash, *logVersion)
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
}
