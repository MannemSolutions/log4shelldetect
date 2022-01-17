package main

import (
	"flag"
	"fmt"
	"github.com/mannemsolutions/log4shelldetect/pkg/jar"
	"os"
	"path/filepath"
)

var logOk = flag.Bool("ok", false, "also report jar files without log4j")
var debug = flag.Bool("debug", false, "print debug messages")
var logHash = flag.Bool("hash", false, "print sha-256 hash of JndiLookup.class")
var logVersion = flag.Bool("l4jversion", false, "print version of log4j")

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

	if isDir, err := jar.IsDirectory(target); err != nil && !isDir {
		j := jar.NewJar(target, *debug)
		j.CheckFile(target, nil, 0, 0)
		j.PrintState(*logOk, *logHash, *logVersion)
		return
	}

	pool := make(chan struct{}, 8)

	err := filepath.Walk(target,
		func(osPathname string, info os.FileInfo, err error) error {
			if filepath.Ext(osPathname) == ".jar" || filepath.Ext(osPathname) == ".war" {
				j := jar.NewJar(osPathname, *debug)
				pool <- struct{}{}
				go func() {
					j.Check()
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
