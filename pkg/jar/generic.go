package jar

import (
	"os"
	"strings"
)

func IsDirectory(path string) (bool, error) {
	fileInfo, err := os.Stat(path)
	if err != nil {
		return false, err
	}
	return fileInfo.IsDir(), err
}
func FileSize(path string) (int64, error) {
	fileInfo, err := os.Stat(path)
	if err != nil {
		return -1, err
	}
	return fileInfo.Size(), err
}

func versionFromPom(data []byte) string {
	lines := string(data)
	for _, line := range strings.Split(lines, "\n") {
		if strings.HasPrefix(line, "version=") {
			return strings.Replace(line, "version=", "", 1)
		}
	}
	return ""
}