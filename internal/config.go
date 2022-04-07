package internal

import (
	"flag"
	"fmt"
	"github.com/mannemsolutions/log4shelldetect/pkg/jar"
	"gopkg.in/yaml.v2"
	"io/ioutil"
	"os"
	"path/filepath"
)

/*
 * This module reads the config file and returns a config object with all entries from the config yaml file.
 */

const (
	envConfName     = "JARSCANNER_CONFIG"
	defaultConfFile = "/etc/jarscanner/config.yaml"
)

type ScanTypesConfig map[string]ScanTypeConfig
type ScanTypeConfig struct {
	Classes []string `yaml:"classes"`
	Poms    []string `yaml:"poms"`
}

func (stc ScanTypesConfig) ToScanTypes() (*jar.ScanTypes, error) {
	sts := jar.NewScanTypes()
	for name, st := range stc {
		if err := sts.Add(name, st.Classes, st.Poms); err != nil {
			return nil, err
		}
	}
	return sts, nil
}

type ExcludesConfig  []string
type ScanPathsConfig []string

type PrintOptionsConfig struct {
	LibHash    bool `yaml:"lib_hash"`
	JarHash    bool `yaml:"jar_hash"`
	LibVersion bool `yaml:"lib_version"`
	Ok         bool `yaml:"ok"`
	Debug      bool `yaml:"debug"`
}

type ScannerConfig struct {
	ScanTypes   ScanTypesConfig    `yaml:"scan_types"`
	Excludes    ExcludesConfig     `yaml:"excludes"`
	PrintOption PrintOptionsConfig `yaml:"print_options"`
	ScanPaths   ScanPathsConfig    `yaml:"scan_paths"`
}

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

func NewConfig() (config ScannerConfig, err error) {
	var (
		debug      bool
		version    bool
		logOk      bool
		libHash    bool
		jarHash    bool
		logVersion bool
		configFile string
	 	myScanType string
	)

	flag.Var(&myPoms, "pom", "Module pom files to scan for.")
	flag.StringVar(&myScanType, "type", "default", "Module pom files to scan for.")
	flag.Var(&myClasses, "class", "Module class files to scan for.")
	flag.Var(&myExcludes, "exclude", "Exclude files when paths match.")
	flag.BoolVar(&debug, "debug", false, "Add debugging output")
	flag.BoolVar(&version, "version", false, "Show version information")
	flag.BoolVar(&logOk, "ok", false, "also report jar files without the specified modules")
	flag.BoolVar(&libHash, "libhash", false, "print sha-256 hash of one of the detected .class file")
	flag.BoolVar(&jarHash, "jarhash", false, "print sha-256 hash of the jar file or dir")
	flag.BoolVar(&logVersion, "libversion", false, "print version of library if detected")
	flag.StringVar(&configFile, "config", os.Getenv(envConfName), "Path to configfile")
	flag.Parse()

	if version {
		//nolint
		fmt.Println(appVersion)
		os.Exit(0)
	}

	if configFile == "" {
		configFile = defaultConfFile
	}

	configFile, err = filepath.EvalSymlinks(configFile)
	if err != nil {
		return config, err
	}

	// This only parsed as yaml, nothing else
	// #nosec
	yamlConfig, err := ioutil.ReadFile(configFile)
	if err != nil {
		return config, err
	}

	err = yaml.Unmarshal(yamlConfig, &config)

	if debug {
		config.PrintOption.Debug = true
	}
	if logVersion {
		config.PrintOption.LibVersion = true
	}
	if logOk {
		config.PrintOption.Ok = true
	}
	if libHash {
		config.PrintOption.LibHash = true
	}
	if jarHash {
		config.PrintOption.JarHash = true
	}
	config.Excludes = append(config.Excludes, myExcludes...)
	if len(myClasses) + len(myPoms) > 0 {
		config.ScanTypes[myScanType] = ScanTypeConfig{
			Classes: myClasses,
			Poms: myPoms,
		}
	}
	config.ScanPaths = append(config.ScanPaths, flag.Args()...)

	if len(config.ScanPaths) == 0 || len(config.ScanTypes) == 0 {
		fmt.Println("Usage: jarscanner [options] <path>")
		fmt.Println("Scans a file or folder recursively for jar files that follow a certain pattern")
		fmt.Println("This helps to find jars with vulnerabilities like Log4Shell (CVE-2021-44228)")
		fmt.Println("")
		fmt.Println("Options:")
		flag.PrintDefaults()
		os.Exit(1)
	}

	return config, err
}