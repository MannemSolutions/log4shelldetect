package jar

import "regexp"
import "strings"

type Paths struct {
	paths map[string]*regexp.Regexp
}

func NewPaths(paths []string) (p Paths, err error) {
	p.paths = make(map[string]*regexp.Regexp)
	for _, path := range paths {
		if pathRe, err := regexp.Compile(path); err != nil {
			return p, err
		} else {
			p.paths[path] = pathRe
		}
	}
	return p, nil
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
