package jar

type FileErrorID int

type FileError struct {
	ID FileErrorID
}

func (m FileError) Error() string {
	return m.ID.String()
}

type FileErrors []FileError

const (
	FileErrorNone FileErrorID = iota
	FileErrorEmpty
	FileErrorNoZip
	FileErrorNoFile
	FileErrorUnknown
)

var (
	fromFileError = map[FileErrorID]string{
		FileErrorUnknown: "UNKNOWN",
		FileErrorEmpty:   "EMPTY",
		FileErrorNoZip:   "NOZIP",
		FileErrorNoFile:  "NOFILE",
		FileErrorNone:    "NONE",
	}
)

func NewFileError(fEID FileErrorID) (fe FileError) {
	return FileError{fEID}
}

func (fEID FileErrorID) String() string {
	if s, exists := fromFileError[fEID]; exists {
		return s
	}
	return FileErrorUnknown.String()
}

func (fes FileErrors) MaxID() (maxID FileErrorID) {
	maxID = FileErrorNone
	for _, fe := range fes {
		if fe.ID > maxID {
			maxID = fe.ID
		}
	}
	return maxID
}
