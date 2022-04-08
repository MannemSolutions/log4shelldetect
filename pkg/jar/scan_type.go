package jar

import (
	"github.com/hashicorp/go-version"
)

type ScanType struct {
	poms           Paths
	classes        Paths
	version_hashes map[string]string
	versions       []version.Version
	hashes         []string
}

func (st *ScanType) AddHash(hash string) {
	st.hashes = append(st.hashes, hash)
}

func (st *ScanType) AddVersion(version version.Version) {
	st.versions = append(st.versions, version)
}

func (st ScanType) Clone() ScanType {
	return ScanType{
		poms: st.poms,
		classes: st.classes,
		version_hashes: st.version_hashes,
	}
}

func (st ScanType) LowestVersion() *version.Version {
	if len(st.versions) == 0 {
		return nil
	}
	minVersion := &st.versions[0]
	for _, stVersion := range st.versions {
		if stVersion.LessThan(minVersion) {
			minVersion = &stVersion
		}
	}
	return minVersion
}

func (st ScanType) getState() string {
	if len(st.versions) > 0 {
		if len(st.hashes) > 0 {
			return "DETECTED"
		} else {
			return "WORKAROUND"
		}
	} else if len(st.hashes) == 0 {
		return "UNDETECTED"
	} else {
		return "DETECTED"
	}
}

type ScanTypes struct {
	scanTypes map[string]ScanType
}

func NewScanTypes() *ScanTypes {
	return &ScanTypes{
		scanTypes: make(map[string]ScanType),
	}
}

func (sts ScanTypes) Len () int {
	return len(sts.scanTypes)
}

func (sts *ScanTypes) Add (name string, classes []string, poms []string, versionHashes map[string]string) error {
	if myClasses, err := NewPaths(classes); err != nil {
		return err
	} else if myPoms, err := NewPaths(poms); err != nil {
		return err
	} else {
		st := ScanType{
			classes:        myClasses,
			poms:           myPoms,
			version_hashes: versionHashes,
		}
		sts.scanTypes[name] = st
		return nil
	}
}

func (sts ScanTypes) Matches (path string) bool {
	for _, st := range sts.scanTypes {
		if st.classes.Matches(path) {
			return true
		} else if st.poms.Matches(path) {
			return true
		}
	}
	return false
}

func (sts ScanTypes) Clone() *ScanTypes {
	newSts := NewScanTypes()
	for name, st := range sts.scanTypes {
		newSts.scanTypes[name] = st.Clone()
	}
	return newSts
}

