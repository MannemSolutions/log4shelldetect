package jar

import "regexp"
import "strings"

type Paths struct {
	paths map[string]*regexp.Regexp
}

func GetPaths() Paths {
	return Paths{
		paths: make(map[string]*regexp.Regexp),
	}
}

func (ps *Paths) Add(p string) error {
	if pathRe, err := regexp.Compile(p); err != nil {
		return err
	} else {
		ps.paths[p] = pathRe
	}
	return nil
}

func (ps *Paths) Contains(p string) bool {
	for path := range ps.paths {
		if strings.Contains(p, path) {
			return true
		}
	}
	return false
}

func (ps *Paths) Matches(p string) bool {
	for _, pathRe := range ps.paths {
		if pathRe.MatchString(p) {
			return true
		}
	}
	return false
}
