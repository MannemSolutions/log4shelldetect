package jar

import (
	"crypto/sha256"
	"io"
	"log"
	"os"
	"path/filepath"
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

func HashFile(path string) []byte {

	f, err := os.Open(path)
	if err != nil {
		log.Printf("Could not read hash of %s, os.Open issue: %v", path, err)
		return nil
	}
	defer f.Close()

	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		log.Printf("Could not read hash of %s, io.Copy issue: %v", path, err)
		return nil
	}

	return h.Sum(nil)
}
func HashDir(path string) []byte {
	hash := sha256.New()
	err := filepath.Walk(path,
		func(osPath string, info os.FileInfo, err error) error {
			if err != nil {
				log.Printf("HashDir->Walk ran into an issue failure accessing a path %q: %v", osPath, err)
				return err
			}
			if info.IsDir() {
				return filepath.SkipDir
			}
			hash.Sum(HashFile(osPath))
			return nil
		})
	if err != nil {
		return nil
	}
	return hash.Sum(nil)
}