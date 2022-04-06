package main

import (
	"github.com/mannemsolutions/log4shelldetect/internal"
	"github.com/mannemsolutions/log4shelldetect/pkg/jar"
	"log"
	"os"
	"path/filepath"
)

func main() {
	if config, err := internal.NewConfig(); err != nil {
		log.Fatalln(err)
	} else if excludes, err := jar.NewPaths(config.Excludes); err != nil {
		log.Fatalln(err)
	} else if st, err := config.ScanTypes.ToScanTypes(); err != nil {
		log.Fatalln(err)
	} else {
		for _, target := range config.ScanPaths {
			if absTarget, err := filepath.Abs(target); err == nil {
				target = absTarget
			}
			if isDir, err := jar.IsDirectory(target); err != nil && !isDir {
				st = st.Clone()
				if j := jar.NewJar(target, config.PrintOption.Debug, st, excludes); j != nil {
					j.CheckZip(target, nil, 0, 0)
					j.PrintStates(config.PrintOption.Ok, config.PrintOption.Hash, config.PrintOption.LibVersion)
				}
				return
			}

			pool := make(chan struct{}, 8)

			err := filepath.Walk(target,
				func(osPathname string, info os.FileInfo, err error) error {
					if filepath.Ext(osPathname) == ".jar" || filepath.Ext(osPathname) == ".war" {
						st = st.Clone()
						if j := jar.NewJar(osPathname, config.PrintOption.Debug, st, excludes); j!= nil {
							pool <- struct{}{}
							go func() {
								j.CheckPath()
								j.PrintStates(config.PrintOption.Ok, config.PrintOption.Hash, config.PrintOption.LibVersion)
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
