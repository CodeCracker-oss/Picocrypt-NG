package main

import (
	"archive/zip"
	"bytes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/subtle"
	"errors"
	"fmt"
	"hash"
	"image/color"
	"io"
	"math"
	"math/big"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/Picocrypt/infectious"
	"github.com/Picocrypt/serpent"
	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/blake2b"
	"golang.org/x/crypto/chacha20"
	"golang.org/x/crypto/hkdf"
	"golang.org/x/crypto/sha3"
)

type WorkOptions struct {
	mode            string
	paranoid        bool
	reedSolomon     bool
	deniability     bool
	recursively     bool
	recombine       bool
	compress        bool
	split           bool
	splitSize       string
	splitSelected   int32
	delete          bool
	autoUnzip       bool
	sameLevel       bool
	keep            bool
	kept            bool
	password        string
	confirmPassword string
	keyfile         bool
	keyfiles        []string
	keyfileOrdered  bool
	comments        string
	inputFile       string
	inputFileOld    string
	outputFile      string
	onlyFiles       []string
	onlyFolders     []string
	allFiles        []string
	passgenLength   int32
	passgenUpper    bool
	passgenLower    bool
	passgenNums     bool
	passgenSymbols  bool
	passgenCopy     bool
}

type ColorOptions = color.RGBA

var (
	WHITE       = ColorOptions{0xff, 0xff, 0xff, 0xff}
	RED         = ColorOptions{0xff, 0x00, 0x00, 0xff}
	GREEN       = ColorOptions{0x00, 0xff, 0x00, 0xff}
	YELLOW      = ColorOptions{0xff, 0xff, 0x00, 0xff}
	TRANSPARENT = ColorOptions{0x00, 0x00, 0x00, 0x00}
)

type workStatus struct {
	popup             string
	main              string
	mainColor         ColorOptions
	working           bool
	progress          float32
	progressInfo      string
	speed             float64
	eta               string
	canCancel         bool
	passwordHide      bool
	showKeyfile       bool
	keyfileLabel      string
	showProgress      bool
	startLabel        string
	ready             string
	inputLabel        string
	showGenPassPopup  bool
	passwordStrength  int
	commentsLabel     string
	scanning          bool
	showOverwrite     bool
	commentsDisabled  bool
	requiredFreeSpace int64
}

// global state/status
var status workStatus
var state WorkOptions

// constants
var version = "v2.00"

const KiB = 1 << 10
const MiB = 1 << 20
const GiB = 1 << 30
const TiB = 1 << 40

const maxPasswordLen = 256
const maxCommentLen = 256
const maxSplitLen = 6

var splitUnits = []string{"KiB", "MiB", "GiB", "TiB"}

// Reed-Solomon encoders
var rs1, rsErr1 = infectious.NewFEC(1, 3)
var rs5, rsErr2 = infectious.NewFEC(5, 15)
var rs16, rsErr3 = infectious.NewFEC(16, 48)
var rs24, rsErr4 = infectious.NewFEC(24, 72)
var rs32, rsErr5 = infectious.NewFEC(32, 96)
var rs64, rsErr6 = infectious.NewFEC(64, 192)
var rs128, rsErr7 = infectious.NewFEC(128, 136)
var fastDecode bool

// Compression variables and passthrough
var compressDone int64
var compressTotal int64
var compressStart time.Time

type compressorProgress struct {
	io.Reader
}

func (p *compressorProgress) Read(data []byte) (int, error) {
	if !status.working {
		return 0, io.EOF
	}
	read, err := p.Reader.Read(data)
	compressDone += int64(read)
	status.progress, status.speed, status.eta = statify(compressDone, compressTotal, compressStart)
	if state.compress {
		status.popup = fmt.Sprintf("Compressing at %.2f MiB/s (ETA: %s)", status.speed, status.eta)
	} else {
		status.popup = fmt.Sprintf("Combining at %.2f MiB/s (ETA: %s)", status.speed, status.eta)
	}
	return read, err
}

type encryptedZipWriter struct {
	_w      io.Writer
	_cipher *chacha20.Cipher
}

func (ezw *encryptedZipWriter) Write(data []byte) (n int, err error) {
	dst := make([]byte, len(data))
	ezw._cipher.XORKeyStream(dst, data)
	return ezw._w.Write(dst)
}

type encryptedZipReader struct {
	_r      io.Reader
	_cipher *chacha20.Cipher
}

func (ezr *encryptedZipReader) Read(data []byte) (n int, err error) {
	src := make([]byte, len(data))
	n, err = ezr._r.Read(src)
	if err == nil && n > 0 {
		dst := make([]byte, n)
		ezr._cipher.XORKeyStream(dst, src[:n])
		if copy(data, dst) != n {
			panic(errors.New("built-in copy() function failed"))
		}
	}
	return n, err
}

func onClickStartButton() {
	// Start button should be disabled if these conditions are true; don't do anything if so
	if (len(state.keyfiles) == 0 && state.password == "") || (state.mode == "encrypt" && state.password != state.confirmPassword) {
		return
	}

	if state.keyfile && state.keyfiles == nil {
		status.main = "Please select your keyfiles"
		status.mainColor = RED
		return
	}
	tmp, err := strconv.Atoi(state.splitSize)
	if state.split && (state.splitSize == "" || err != nil || tmp <= 0) {
		status.main = "Invalid chunk size"
		status.mainColor = RED
		return
	}

	// Check if output file already exists
	_, err = os.Stat(state.outputFile)

	// Check if any split chunks already exist
	if state.split {
		names, err2 := filepath.Glob(state.outputFile + ".*")
		if err2 != nil {
			panic(err2)
		}
		if len(names) > 0 {
			err = nil
		} else {
			err = os.ErrNotExist
		}
	}

	// If files already exist, show the overwrite modal
	if err == nil && !state.recursively {
		status.showOverwrite = true
	} else { // Nothing to worry about, start working
		status.showProgress = true
		fastDecode = true
		status.canCancel = true
		if !state.recursively {
			go func() {
				work()
				status.working = false
				status.showProgress = false

			}()
		} else {
			// Store variables as they will be cleared
			oldPassword := state.password
			oldKeyfile := state.keyfile
			oldKeyfiles := state.keyfiles
			oldKeyfileOrdered := state.keyfileOrdered
			oldKeyfileLabel := status.keyfileLabel
			oldComments := state.comments
			oldParanoid := state.paranoid
			oldReedsolo := state.reedSolomon
			oldDeniability := state.deniability
			oldSplit := state.split
			oldSplitSize := state.splitSize
			oldSplitSelected := state.splitSelected
			oldDelete := state.delete
			files := state.allFiles
			go func() {
				for _, file := range files {
					// Simulate dropping the file
					onDrop([]string{file})

					// Restore variables and options
					state.password = oldPassword
					state.confirmPassword = oldPassword
					state.keyfile = oldKeyfile
					state.keyfiles = oldKeyfiles
					state.keyfileOrdered = oldKeyfileOrdered
					status.keyfileLabel = oldKeyfileLabel
					state.comments = oldComments
					state.paranoid = oldParanoid
					state.reedSolomon = oldReedsolo
					if state.mode != "decrypt" {
						state.deniability = oldDeniability
					}
					state.split = oldSplit
					state.splitSize = oldSplitSize
					state.splitSelected = oldSplitSelected
					state.delete = oldDelete

					work()
					if !status.working {
						resetUI()
						cancel(nil, nil)
						status.showProgress = false
						return
					}
				}
				status.working = false
				status.showProgress = false
			}()
		}
	}
}

func onDrop(names []string) {
	if status.showKeyfile {
		state.keyfiles = append(state.keyfiles, names...)

		// Make sure keyfiles are accessible, remove duplicates
		var tmp []string
		for _, i := range state.keyfiles {
			duplicate := false
			for _, j := range tmp {
				if i == j {
					duplicate = true
				}
			}
			stat, statErr := os.Stat(i)
			fin, err := os.Open(i)
			if err == nil {
				fin.Close()
			} else {
				status.showKeyfile = false
				resetUI()
				accessDenied("Keyfile read")
				return
			}
			if !duplicate && statErr == nil && !stat.IsDir() {
				tmp = append(tmp, i)
			}
		}
		state.keyfiles = tmp

		// Update the keyfile status
		if len(state.keyfiles) == 0 {
			status.keyfileLabel = "None selected"
		} else if len(state.keyfiles) == 1 {
			status.keyfileLabel = "Using 1 keyfile"
		} else {
			status.keyfileLabel = fmt.Sprintf("Using %d keyfiles", len(state.keyfiles))
		}
		return
	}

	status.scanning = true
	files, folders := 0, 0
	compressDone, compressTotal = 0, 0
	resetUI()

	// One item dropped
	if len(names) == 1 {
		stat, err := os.Stat(names[0])
		if err != nil {
			status.main = "Failed to stat dropped item"
			status.mainColor = RED
			return
		}

		// A folder was dropped
		if stat.IsDir() {
			folders++
			state.mode = "encrypt"
			status.inputLabel = "1 folder"
			status.startLabel = "Zip and Encrypt"
			state.onlyFolders = append(state.onlyFolders, names[0])
			state.inputFile = filepath.Join(filepath.Dir(names[0]), "encrypted-"+strconv.Itoa(int(time.Now().Unix()))) + ".zip"
			state.outputFile = state.inputFile + ".pcv"
		} else { // A file was dropped
			files++
			status.requiredFreeSpace = stat.Size()

			// Is the file a part of a split volume?
			nums := []string{"0", "1", "2", "3", "4", "5", "6", "7", "8", "9"}
			endsNum := false
			for _, i := range nums {
				if strings.HasSuffix(names[0], i) {
					endsNum = true
				}
			}
			isSplit := strings.Contains(names[0], ".pcv.") && endsNum

			// Decide if encrypting or decrypting
			if strings.HasSuffix(names[0], ".pcv") || isSplit {
				state.mode = "decrypt"
				status.inputLabel = "Volume for decryption"
				status.startLabel = "Decrypt"
				status.commentsLabel = "Comments (read-only):"
				status.commentsDisabled = true

				// Get the correct input and output filenames
				if isSplit {
					ind := strings.Index(names[0], ".pcv")
					names[0] = names[0][:ind+4]
					state.inputFile = names[0]
					state.outputFile = names[0][:ind]
					state.recombine = true

					// Find out the number of splitted chunks
					totalFiles := 0
					for {
						stat, err := os.Stat(fmt.Sprintf("%s.%d", state.inputFile, totalFiles))
						if err != nil {
							break
						}
						totalFiles++
						compressTotal += stat.Size()
					}
					status.requiredFreeSpace = compressTotal
				} else {
					state.outputFile = names[0][:len(names[0])-4]
				}

				// Open the input file in read-only mode
				var fin *os.File
				var err error
				if isSplit {
					fin, err = os.Open(names[0] + ".0")
				} else {
					fin, err = os.Open(names[0])
				}
				if err != nil {
					resetUI()
					accessDenied("Read")
					return
				}

				// Check if version can be read from header
				tmp := make([]byte, 15)
				if n, err := fin.Read(tmp); err != nil || n != 15 {
					fin.Close()
					status.main = "Failed to read 15 bytes from file"
					status.mainColor = RED
					return
				}
				tmp, err = rsDecode(rs5, tmp)
				if valid, _ := regexp.Match(`^v\d\.\d{2}`, tmp); err != nil || !valid {
					// Volume has plausible deniability
					state.deniability = true
					status.main = "Can't read header, assuming volume is deniable"
					fin.Close()
				} else {
					// Read comments from file and check for corruption
					tmp = make([]byte, 15)
					if n, err := fin.Read(tmp); err != nil || n != 15 {
						fin.Close()
						status.main = "Failed to read 15 bytes from file"
						status.mainColor = RED
						return
					}
					tmp, err = rsDecode(rs5, tmp)
					if err == nil {
						commentsLength, err := strconv.Atoi(string(tmp))
						if err != nil {
							state.comments = "Comment length is corrupted"
						} else {
							tmp = make([]byte, commentsLength*3)
							if n, err := fin.Read(tmp); err != nil || n != commentsLength*3 {
								fin.Close()
								status.main = "Failed to read comments from file"
								status.mainColor = RED
								return
							}
							state.comments = ""
							for i := 0; i < commentsLength*3; i += 3 {
								t, err := rsDecode(rs1, tmp[i:i+3])
								if err != nil {
									state.comments = "Comments are corrupted"
									break
								}
								state.comments += string(t)
							}
						}
					} else {
						state.comments = "Comments are corrupted"

					}

					// Read flags from file and check for corruption
					flags := make([]byte, 15)
					if n, err := fin.Read(flags); err != nil || n != 15 {
						fin.Close()
						status.main = "Failed to read 15 bytes from file"
						status.mainColor = RED
						return
					}
					if err := fin.Close(); err != nil {
						panic(err)
					}
					flags, err = rsDecode(rs5, flags)
					if err != nil {
						status.main = "The volume header is damaged"
						status.mainColor = RED
						return
					}

					// Update UI and variables according to flags
					if flags[1] == 1 {
						state.keyfile = true
						status.keyfileLabel = "Keyfiles required"
					} else {
						status.keyfileLabel = "Not applicable"
					}
					if flags[2] == 1 {
						state.keyfileOrdered = true
					}
				}
			} else { // One file was dropped for encryption
				state.mode = "encrypt"
				status.inputLabel = "1 file"
				status.startLabel = "Encrypt"
				state.inputFile = names[0]
				state.outputFile = names[0] + ".pcv"
			}

			// Add the file
			state.onlyFiles = append(state.onlyFiles, names[0])
			state.inputFile = names[0]
			if !isSplit {
				compressTotal += stat.Size()
			}
		}
	} else { // There are multiple dropped items
		state.mode = "encrypt"
		status.startLabel = "Zip and Encrypt"

		// Go through each dropped item and add to corresponding slices
		for _, name := range names {
			stat, err := os.Stat(name)
			if err != nil {
				resetUI()
				status.main = "Failed to stat dropped items"
				status.mainColor = RED
				return
			}
			if stat.IsDir() {
				folders++
				state.onlyFolders = append(state.onlyFolders, name)
			} else {
				files++
				state.onlyFiles = append(state.onlyFiles, name)
				state.allFiles = append(state.allFiles, name)

				compressTotal += stat.Size()
				status.requiredFreeSpace += stat.Size()
				status.inputLabel = fmt.Sprintf("scanning files... (%s)", sizeify(compressTotal))
			}
		}

		// Update UI with the number of files and folders selected
		if folders == 0 {
			status.inputLabel = fmt.Sprintf("%d files", files)
		} else if files == 0 {
			status.inputLabel = fmt.Sprintf("%d folders", folders)
		} else {
			if files == 1 && folders > 1 {
				status.inputLabel = fmt.Sprintf("1 file and %d folders", folders)
			} else if folders == 1 && files > 1 {
				status.inputLabel = fmt.Sprintf("%d files and 1 folder", files)
			} else if folders == 1 && files == 1 {
				status.inputLabel = "1 file and 1 folder"
			} else {
				status.inputLabel = fmt.Sprintf("%d files and %d folders", files, folders)
			}
		}
		// Set the input and output paths
		state.inputFile = filepath.Join(filepath.Dir(names[0]), "encrypted-"+strconv.Itoa(int(time.Now().Unix()))) + ".zip"
		state.outputFile = state.inputFile + ".pcv"
	}

	// Recursively add all files in 'onlyFolders' to 'allFiles'
	go func() {
		oldInputLabel := status.inputLabel
		for _, name := range state.onlyFolders {
			if filepath.Walk(name, func(path string, _ os.FileInfo, err error) error {
				if err != nil {
					resetUI()
					status.main = "Failed to walk through dropped items"
					status.mainColor = RED
					return err
				}
				stat, err := os.Stat(path)
				if err != nil {
					resetUI()
					status.main = "Failed to walk through dropped items"
					status.mainColor = RED
					return err
				}
				// If 'path' is a valid file path, add to 'allFiles'
				if !stat.IsDir() {
					state.allFiles = append(state.allFiles, path)
					compressTotal += stat.Size()
					status.requiredFreeSpace += stat.Size()
					status.inputLabel = fmt.Sprintf("scanning files... (%s)", sizeify(compressTotal))
				}
				return nil
			}) != nil {
				resetUI()
				status.main = "Failed to walk through dropped items"
				status.mainColor = RED
				return
			}
		}
		status.inputLabel = fmt.Sprintf("%s (%s)", oldInputLabel, sizeify(compressTotal))
		status.scanning = false
	}()
}

func work() {
	status.popup = "Starting..."
	status.main = "working..."
	status.mainColor = WHITE
	status.working = true

	padded := false

	// Cryptography values
	var salt []byte                    // Argon2 salt, 16 bytes
	var hkdfSalt []byte                // HKDF-SHA3 salt, 32 bytes
	var serpentIV []byte               // Serpent IV, 16 bytes
	var nonce []byte                   // 24-byte XChaCha20 nonce
	var keyHash []byte                 // HMAC-SHA3-512 of header
	var keyHashRef []byte              // Same as 'keyHash', but used for comparison
	var keyfileKey []byte              // The SHA3-256 hashes of keyfiles
	var keyfileHash = make([]byte, 32) // The SHA3-256 of 'keyfileKey'
	var keyfileHashRef []byte          // Same as 'keyfileHash', but used for comparison
	var authTag []byte                 // 64-byte authentication tag (BLAKE2b or HMAC-SHA3)

	// Header fields decoded (used for MAC verification)
	var headerVersion []byte
	var headerComments []byte
	var headerCommentsLen int
	var headerFlags []byte

	var tempZipCipherW *chacha20.Cipher
	var tempZipCipherR *chacha20.Cipher
	var tempZipInUse bool = false
	// Whether keyfiles should be applied for this operation (based on header for decrypt)
	var useKeyfiles bool
	func() { // enclose to keep out of parent scope
		key, nonce := make([]byte, 32), make([]byte, 12)
		if n, err := rand.Read(key); err != nil || n != 32 {
			panic(errors.New("fatal crypto/rand error"))
		}
		if n, err := rand.Read(nonce); err != nil || n != 12 {
			panic(errors.New("fatal crypto/rand error"))
		}
		if bytes.Equal(key, make([]byte, 32)) || bytes.Equal(nonce, make([]byte, 12)) {
			panic(errors.New("fatal crypto/rand error")) // this should never happen but be safe
		}
		var errW error
		var errR error
		tempZipCipherW, errW = chacha20.NewUnauthenticatedCipher(key, nonce)
		tempZipCipherR, errR = chacha20.NewUnauthenticatedCipher(key, nonce)
		if errW != nil || errR != nil {
			panic(errors.New("fatal chacha20 init error"))
		}
	}()

	// Combine/compress all files into a .zip file if needed
	if len(state.allFiles) > 1 || len(state.onlyFolders) > 0 {
		// Consider case where compressing only one file
		files := state.allFiles
		if len(state.allFiles) == 0 {
			files = state.onlyFiles
		}

		// Get the root directory of the selected files
		var rootDir string
		if len(state.onlyFolders) > 0 {
			rootDir = filepath.Dir(state.onlyFolders[0])
		} else {
			rootDir = filepath.Dir(state.onlyFiles[0])
		}

		// Open a temporary .zip for writing
		state.inputFile = strings.TrimSuffix(state.outputFile, ".pcv") + ".tmp"
		file, err := os.Create(state.inputFile)
		if err != nil { // Make sure file is writable
			accessDenied("Write")
			return
		}

		// Add each file to the .zip
		tempZip := encryptedZipWriter{
			_w:      file,
			_cipher: tempZipCipherW,
		}
		tempZipInUse = true
		writer := zip.NewWriter(&tempZip)
		compressStart = time.Now()
		for i, path := range files {
			status.progressInfo = fmt.Sprintf("%d/%d", i+1, len(files))

			// Create file info header (size, last modified, etc.)
			stat, err := os.Stat(path)
			if err != nil {
				writer.Close()
				file.Close()
				os.Remove(state.inputFile)
				resetUI()
				status.main = "Failed to stat input files"
				status.mainColor = RED
				return
			}
			header, err := zip.FileInfoHeader(stat)
			if err != nil {
				writer.Close()
				file.Close()
				os.Remove(state.inputFile)
				resetUI()
				status.main = "Failed to create zip.FileInfoHeader"
				status.mainColor = RED
				return
			}
			header.Name = strings.TrimPrefix(path, rootDir)
			header.Name = filepath.ToSlash(header.Name)
			header.Name = strings.TrimPrefix(header.Name, "/")

			if state.compress {
				header.Method = zip.Deflate
			} else {
				header.Method = zip.Store
			}

			// Open the file for reading
			entry, err := writer.CreateHeader(header)
			if err != nil {
				writer.Close()
				file.Close()
				os.Remove(state.inputFile)
				resetUI()
				status.main = "Failed to writer.CreateHeader"
				status.mainColor = RED
				return
			}
			fin, err := os.Open(path)
			if err != nil {
				writer.Close()
				file.Close()
				os.Remove(state.inputFile)
				resetUI()
				accessDenied("Read")
				return
			}

			// Use a passthrough to catch compression progress
			passthrough := &compressorProgress{Reader: fin}
			buf := make([]byte, MiB)
			_, err = io.CopyBuffer(entry, passthrough, buf)
			fin.Close()

			if err != nil {
				writer.Close()
				insufficientSpace(nil, file)
				os.Remove(state.inputFile)
				return
			}

			if !status.working {
				writer.Close()
				cancel(nil, file)
				os.Remove(state.inputFile)
				return
			}
		}
		if err := writer.Close(); err != nil {
			panic(err)
		}
		if err := file.Close(); err != nil {
			panic(err)
		}
	}

	// Recombine a split file if necessary
	if state.recombine {
		totalFiles := 0
		totalBytes := int64(0)
		done := 0

		// Find out the number of splitted chunks
		for {
			stat, err := os.Stat(fmt.Sprintf("%s.%d", state.inputFile, totalFiles))
			if err != nil {
				break
			}
			totalFiles++
			totalBytes += stat.Size()
		}

		// Make sure not to overwrite anything
		_, err := os.Stat(state.outputFile + ".pcv")
		if err == nil { // File already exists
			status.main = "Please remove " + filepath.Base(state.outputFile+".pcv")
			status.mainColor = RED
			return
		}

		// Create a .pcv to combine chunks into
		fout, err := os.Create(state.outputFile + ".pcv")
		if err != nil { // Make sure file is writable
			accessDenied("Write")
			return
		}

		// Merge all chunks into one file
		startTime := time.Now()
		for i := range totalFiles {
			fin, err := os.Open(fmt.Sprintf("%s.%d", state.inputFile, i))
			if err != nil {
				fout.Close()
				os.Remove(state.outputFile + ".pcv")
				resetUI()
				accessDenied("Read")
				return
			}

			for {
				if !status.working {
					cancel(fin, fout)
					os.Remove(state.outputFile + ".pcv")
					return
				}

				// Copy from the chunk into the .pcv
				data := make([]byte, MiB)
				read, err := fin.Read(data)
				if err != nil {
					break
				}
				data = data[:read]
				var n int
				n, err = fout.Write(data)
				done += read

				if err != nil || n != len(data) {
					insufficientSpace(fin, fout)
					os.Remove(state.outputFile + ".pcv")
					return
				}

				// Update the stats
				status.progress, status.speed, status.eta = statify(int64(done), totalBytes, startTime)
				status.progressInfo = fmt.Sprintf("%d/%d", i+1, totalFiles)
				status.popup = fmt.Sprintf("Recombining at %.2f MiB/s (ETA: %s)", status.speed, status.eta)
			}
			if err := fin.Close(); err != nil {
				panic(err)
			}
		}
		if err := fout.Close(); err != nil {
			panic(err)
		}
		state.inputFileOld = state.inputFile
		state.inputFile = state.outputFile + ".pcv"
	}

	// Input volume has plausible deniability
	if state.mode == "decrypt" && state.deniability {
		status.popup = "Removing deniability protection..."
		status.progressInfo = ""
		status.progress = 0
		status.canCancel = false

		// Get size of volume for showing progress
		stat, err := os.Stat(state.inputFile)
		if err != nil {
			// we already read from inputFile successfully in onDrop
			// so it is very unlikely this err != nil, we can just panic
			panic(err)
		}
		total := stat.Size()

		// Rename input volume to free up the filename
		fin, err := os.Open(state.inputFile)
		if err != nil {
			panic(err)
		}
		for strings.HasSuffix(state.inputFile, ".tmp") {
			state.inputFile = strings.TrimSuffix(state.inputFile, ".tmp")
		}
		state.inputFile += ".tmp"
		fout, err := os.Create(state.inputFile)
		if err != nil {
			panic(err)
		}

		// Get the Argon2 salt and XChaCha20 nonce from input volume
		salt := make([]byte, 16)
		nonce := make([]byte, 24)
		if n, err := fin.Read(salt); err != nil || n != 16 {
			panic(errors.New("failed to read 16 bytes from file"))
		}
		if n, err := fin.Read(nonce); err != nil || n != 24 {
			panic(errors.New("failed to read 24 bytes from file"))
		}

		// Generate key and XChaCha20
		key := argon2.IDKey([]byte(state.password), salt, 4, 1<<20, 4, 32)
		chacha, err := chacha20.NewUnauthenticatedCipher(key, nonce)
		if err != nil {
			panic(err)
		}

		// Decrypt the entire volume
		done, counter := 0, 0
		for {
			src := make([]byte, MiB)
			size, err := fin.Read(src)
			if err != nil {
				break
			}
			src = src[:size]
			dst := make([]byte, len(src))
			chacha.XORKeyStream(dst, src)
			if n, err := fout.Write(dst); err != nil || n != len(dst) {
				fout.Close()
				os.Remove(fout.Name())
				panic(errors.New("failed to write dst"))
			}

			// Update stats
			done += size
			counter += MiB
			status.progress = float32(float64(done) / float64(total))

			// Change nonce after 60 GiB to prevent overflow
			if counter >= 60*GiB {
				tmp := sha3.New256()
				if n, err := tmp.Write(nonce); err != nil || n != len(nonce) {
					panic(errors.New("failed to write nonce to tmp during rekeying"))
				}
				nonce = tmp.Sum(nil)[:24]
				chacha, err = chacha20.NewUnauthenticatedCipher(key, nonce)
				if err != nil {
					panic(err)
				}
				counter = 0
			}
		}

		if err := fin.Close(); err != nil {
			panic(err)
		}
		if err := fout.Close(); err != nil {
			panic(err)
		}

		// Check if the version can be read from the volume
		fin, err = os.Open(state.inputFile)
		if err != nil {
			panic(err)
		}
		tmp := make([]byte, 15)
		if n, err := fin.Read(tmp); err != nil || n != 15 {
			panic(errors.New("failed to read 15 bytes from file"))
		}
		if err := fin.Close(); err != nil {
			panic(err)
		}
		tmp, err = rsDecode(rs5, tmp)
		if valid, _ := regexp.Match(`^v\d\.\d{2}`, tmp); err != nil || !valid {
			os.Remove(state.inputFile)
			state.inputFile = strings.TrimSuffix(state.inputFile, ".tmp")
			broken(nil, nil, "Password is incorrect or the file is not a volume", true)
			if state.recombine {
				state.inputFile = state.inputFileOld
			}
			return
		}
	}

	status.canCancel = false
	status.progress = 0
	status.progressInfo = ""

	// Subtract the header size from the total size if decrypting
	stat, err := os.Stat(state.inputFile)
	if err != nil {
		resetUI()
		accessDenied("Read")
		return
	}
	total := stat.Size()
	if state.mode == "decrypt" {
		total -= 789
	}

	// Open input file in read-only mode
	fin, err := os.Open(state.inputFile)
	if err != nil {
		resetUI()
		accessDenied("Read")
		return
	}

	// Setup output file
	var fout *os.File

	// If encrypting, generate values and write to file
	if state.mode == "encrypt" {
		status.popup = "Generating values..."

		// Stores any errors when writing to file
		errs := make([]error, 11)

		// Make sure not to overwrite anything
		_, err = os.Stat(state.outputFile)
		if state.split && err == nil { // File already exists
			fin.Close()
			if len(state.allFiles) > 1 || len(state.onlyFolders) > 0 || state.compress {
				os.Remove(state.inputFile)
			}
			status.main = "Please remove " + filepath.Base(state.outputFile)
			status.mainColor = RED
			return
		}

		// Create the output file
		fout, err = os.Create(state.outputFile + ".incomplete")
		if err != nil {
			fin.Close()
			if len(state.allFiles) > 1 || len(state.onlyFolders) > 0 || state.compress {
				os.Remove(state.inputFile)
			}
			accessDenied("Write")
			return
		}

		// Set up cryptographic values
		salt = make([]byte, 16)
		hkdfSalt = make([]byte, 32)
		serpentIV = make([]byte, 16)
		nonce = make([]byte, 24)

		// Write the program version to file
		_, errs[0] = fout.Write(rsEncode(rs5, []byte(version)))

		if len(state.comments) > 99999 {
			panic(errors.New("comments exceed maximum length"))
		}

		// Encode and write the comment length to file
		commentsLength := []byte(fmt.Sprintf("%05d", len(state.comments)))
		_, errs[1] = fout.Write(rsEncode(rs5, commentsLength))

		// Encode the comment and write to file
		for _, i := range []byte(state.comments) {
			_, err := fout.Write(rsEncode(rs1, []byte{i}))
			if err != nil {
				errs[2] = err
			}
		}

		// Configure flags and write to file
		flags := make([]byte, 5)
		if state.paranoid { // Paranoid mode selected
			flags[0] = 1
		}
		if len(state.keyfiles) > 0 { // Keyfiles are being used
			flags[1] = 1
		}
		if state.keyfileOrdered { // Order of keyfiles matter
			flags[2] = 1
		}
		if state.reedSolomon { // Full Reed-Solomon encoding is selected
			flags[3] = 1
		}
		if total%int64(MiB) >= int64(MiB)-128 { // Reed-Solomon internals
			flags[4] = 1
		}
		_, errs[3] = fout.Write(rsEncode(rs5, flags))

		// Fill values with Go's CSPRNG
		if n, err := rand.Read(salt); err != nil || n != 16 {
			panic(errors.New("failed to read 16 bytes from crypto/rand"))
		}
		if n, err := rand.Read(hkdfSalt); err != nil || n != 32 {
			panic(errors.New("failed to read 32 bytes from crypto/rand"))
		}
		if n, err := rand.Read(serpentIV); err != nil || n != 16 {
			panic(errors.New("failed to read 16 bytes from crypto/rand"))
		}
		if n, err := rand.Read(nonce); err != nil || n != 24 {
			panic(errors.New("failed to read 24 bytes from crypto/rand"))
		}
		if bytes.Equal(salt, make([]byte, 16)) {
			panic(errors.New("fatal crypto/rand error"))
		}
		if bytes.Equal(hkdfSalt, make([]byte, 32)) {
			panic(errors.New("fatal crypto/rand error"))
		}
		if bytes.Equal(serpentIV, make([]byte, 16)) {
			panic(errors.New("fatal crypto/rand error"))
		}
		if bytes.Equal(nonce, make([]byte, 24)) {
			panic(errors.New("fatal crypto/rand error"))
		}

		// Encode values with Reed-Solomon and write to file
		_, errs[4] = fout.Write(rsEncode(rs16, salt))
		_, errs[5] = fout.Write(rsEncode(rs32, hkdfSalt))
		_, errs[6] = fout.Write(rsEncode(rs16, serpentIV))
		_, errs[7] = fout.Write(rsEncode(rs24, nonce))

		// Write placeholders for future use
		_, errs[8] = fout.Write(make([]byte, 192))  // Hash of encryption key
		_, errs[9] = fout.Write(make([]byte, 96))   // Hash of keyfile key
		_, errs[10] = fout.Write(make([]byte, 192)) // BLAKE2b/HMAC-SHA3 tag

		for _, err := range errs {
			if err != nil {
				insufficientSpace(fin, fout)
				if len(state.allFiles) > 1 || len(state.onlyFolders) > 0 || state.compress {
					os.Remove(state.inputFile)
				}
				os.Remove(fout.Name())
				return
			}
		}
	} else { // Decrypting, read values from file and decode
		status.popup = "Reading values..."

		// Stores any Reed-Solomon decoding errors
		errs := make([]error, 10)

		versionEnc := make([]byte, 15)
		fin.Read(versionEnc)
		headerVersion, errs[0] = rsDecode(rs5, versionEnc)

		tmp := make([]byte, 15)
		fin.Read(tmp)
		tmp, errs[1] = rsDecode(rs5, tmp)

		if valid, err := regexp.Match(`^\d{5}$`, tmp); !valid || err != nil {
			broken(fin, nil, "Unable to read comments length", true)
			return
		}

		commentsLength, _ := strconv.Atoi(string(tmp))
		headerCommentsLen = commentsLength
		headerComments = make([]byte, 0, commentsLength)
		for i := 0; i < commentsLength; i++ {
			cEnc := make([]byte, 3)
			fin.Read(cEnc)
			cDec, err := rsDecode(rs1, cEnc)
			if err != nil {
				errs[1] = err
			}
			headerComments = append(headerComments, cDec...)
		}
		total -= int64(commentsLength) * 3

		flags := make([]byte, 15)
		fin.Read(flags)
		flags, errs[2] = rsDecode(rs5, flags)
		headerFlags = flags
		state.paranoid = flags[0] == 1
		state.reedSolomon = flags[3] == 1
		padded = flags[4] == 1
		if state.deniability {
			state.keyfile = flags[1] == 1
			state.keyfileOrdered = flags[2] == 1
		}
		// For decryption, only consider keyfiles if header requires them
		useKeyfiles = len(headerFlags) > 1 && headerFlags[1] == 1

		salt = make([]byte, 48)
		fin.Read(salt)
		salt, errs[3] = rsDecode(rs16, salt)

		hkdfSalt = make([]byte, 96)
		fin.Read(hkdfSalt)
		hkdfSalt, errs[4] = rsDecode(rs32, hkdfSalt)

		serpentIV = make([]byte, 48)
		fin.Read(serpentIV)
		serpentIV, errs[5] = rsDecode(rs16, serpentIV)

		nonce = make([]byte, 72)
		fin.Read(nonce)
		nonce, errs[6] = rsDecode(rs24, nonce)

		keyHashRef = make([]byte, 192)
		fin.Read(keyHashRef)
		keyHashRef, errs[7] = rsDecode(rs64, keyHashRef)

		keyfileHashRef = make([]byte, 96)
		fin.Read(keyfileHashRef)
		keyfileHashRef, errs[8] = rsDecode(rs32, keyfileHashRef)

		authTag = make([]byte, 192)
		fin.Read(authTag)
		authTag, errs[9] = rsDecode(rs64, authTag)

		// If there was an issue during decoding, the header is corrupted
		for _, err := range errs {
			if err != nil {
				if state.keep { // If the user chooses to force decrypt
					state.kept = true
				} else {
					broken(fin, nil, "The volume header is damaged", true)
					return
				}
			}
		}
	}

	status.popup = "Deriving key..."

	// Derive encryption keys and subkeys
	var key []byte
	if state.paranoid {
		key = argon2.IDKey(
			[]byte(state.password),
			salt,
			8,     // 8 passes
			1<<20, // 1 GiB memory
			8,     // 8 threads
			32,    // 32-byte output key
		)
	} else {
		key = argon2.IDKey(
			[]byte(state.password),
			salt,
			4,
			1<<20,
			4,
			32,
		)
	}
	if bytes.Equal(key, make([]byte, 32)) {
		panic(errors.New("fatal crypto/argon2 error"))
	}

	// If keyfiles are being used. Decide whether to use keyfiles during this operation
	if state.mode == "encrypt" {
		useKeyfiles = len(state.keyfiles) > 0
	}

	if useKeyfiles {
		status.popup = "Reading keyfiles..."

		var keyfileTotal int64
		for _, path := range state.keyfiles {
			stat, err := os.Stat(path)
			if err != nil {
				panic(err) // we already checked os.Stat in onDrop
			}
			keyfileTotal += stat.Size()
		}

		if state.keyfileOrdered { // If order matters, hash progressively
			var tmp = sha3.New256()
			var keyfileDone int

			// For each keyfile...
			for _, path := range state.keyfiles {
				fin, err := os.Open(path)
				if err != nil {
					panic(err)
				}
				for { // Read in chunks of 1 MiB
					data := make([]byte, MiB)
					size, err := fin.Read(data)
					if err != nil {
						break
					}
					data = data[:size]
					if _, err := tmp.Write(data); err != nil { // Hash the data
						panic(err)
					}

					// Update progress
					keyfileDone += size
					status.progress = float32(keyfileDone) / float32(keyfileTotal)
				}
				if err := fin.Close(); err != nil {
					panic(err)
				}
			}
			keyfileKey = tmp.Sum(nil) // Get the SHA3-256

			// Store a hash of 'keyfileKey' for comparison
			tmp = sha3.New256()
			if _, err := tmp.Write(keyfileKey); err != nil {
				panic(err)
			}
			keyfileHash = tmp.Sum(nil)
		} else { // If order doesn't matter, hash individually and combine
			var keyfileDone int

			// For each keyfile...
			for _, path := range state.keyfiles {
				fin, err := os.Open(path)
				if err != nil {
					panic(err)
				}
				tmp := sha3.New256()
				for { // Read in chunks of 1 MiB
					data := make([]byte, MiB)
					size, err := fin.Read(data)
					if err != nil {
						break
					}
					data = data[:size]
					if _, err := tmp.Write(data); err != nil { // Hash the data
						panic(err)
					}

					// Update progress
					keyfileDone += size
					status.progress = float32(keyfileDone) / float32(keyfileTotal)
				}
				if err := fin.Close(); err != nil {
					panic(err)
				}

				sum := tmp.Sum(nil) // Get the SHA3-256

				// XOR keyfile hash with 'keyfileKey'
				if keyfileKey == nil {
					keyfileKey = sum
				} else {
					for i, j := range sum {
						keyfileKey[i] ^= j
					}
				}
			}

			// Store a hash of 'keyfileKey' for comparison
			tmp := sha3.New256()
			if _, err := tmp.Write(keyfileKey); err != nil {
				panic(err)
			}
			keyfileHash = tmp.Sum(nil)
		}
	}

	status.popup = "Calculating values..."

	// Single HKDF stream: derive header subkey first (v2), then payload subkeys and rekeying
	var unifiedKDF io.Reader
	// Track legacy v1 volumes to delay HKDF init until after keyfile XOR
	var isLegacyV1 bool

	// Compute or verify header auth (v2: HMAC over header; v1: SHA3-512(key))
	if state.mode == "encrypt" {
		// v2 format for new volumes
		unifiedKDF = hkdf.New(sha3.New256, key, hkdfSalt, nil)
		subkeyHeader := make([]byte, 64)
		if _, err := io.ReadFull(unifiedKDF, subkeyHeader); err != nil {
			panic(errors.New("fatal hkdf.Read error"))
		}
		macHeader := hmac.New(sha3.New512, subkeyHeader)

		// Reconstruct flags
		flagsHeader := make([]byte, 5)
		if state.paranoid {
			flagsHeader[0] = 1
		}
		if len(state.keyfiles) > 0 {
			flagsHeader[1] = 1
		}
		if state.keyfileOrdered {
			flagsHeader[2] = 1
		}
		if state.reedSolomon {
			flagsHeader[3] = 1
		}
		if total%int64(MiB) >= int64(MiB)-128 {
			flagsHeader[4] = 1
		}

		macHeader.Write([]byte(version))
		macHeader.Write([]byte(fmt.Sprintf("%05d", len(state.comments))))
		macHeader.Write([]byte(state.comments))
		macHeader.Write(flagsHeader)
		macHeader.Write(salt)
		macHeader.Write(hkdfSalt)
		macHeader.Write(serpentIV)
		macHeader.Write(nonce)
		macHeader.Write(keyfileHash)

		keyHash = macHeader.Sum(nil)
	} else {
		// Decrypt path: check which version produced the volume
		isLegacyV1 := bytes.HasPrefix(headerVersion, []byte("v1."))
		if isLegacyV1 {
			// v1 compatibility: header stores SHA3-512(key)
			tmp := sha3.New512()
			if _, err := tmp.Write(key); err != nil {
				panic(err)
			}
			keyHash = tmp.Sum(nil)

			keyCorrect := subtle.ConstantTimeCompare(keyHash, keyHashRef) == 1
			keyfileCorrect := subtle.ConstantTimeCompare(keyfileHash, keyfileHashRef) == 1
			incorrect := !keyCorrect
			// For legacy v1 volumes, require keyfiles strictly based on header flag
			// instead of UI state to avoid stale/mismatched UI variables.
			if useKeyfiles {
				incorrect = !keyCorrect || !keyfileCorrect
			}
			if incorrect {
				if state.keep {
					state.kept = true
				} else {
					if !keyCorrect {
						status.main = "The provided password is incorrect"
					} else {
						if state.keyfileOrdered {
							status.main = "Incorrect keyfiles or ordering"
						} else {
							status.main = "Incorrect keyfiles"
						}
						if state.deniability {
							fin.Close()
							os.Remove(state.inputFile)
							state.inputFile = strings.TrimSuffix(state.inputFile, ".tmp")
						}
					}
					broken(fin, nil, status.main, true)
					if state.recombine {
						state.inputFile = state.inputFileOld
					}
					return
				}
			}

			// Create output file only after validation succeeds
			fout, err = os.Create(state.outputFile + ".incomplete")
			if err != nil {
				fin.Close()
				if state.recombine {
					os.Remove(state.inputFile)
				}
				accessDenied("Write")
				return
			}
		} else {
			// v2 validation: HMAC-SHA3-256 over header using first 64 bytes of a single HKDF stream
			unifiedKDF = hkdf.New(sha3.New256, key, hkdfSalt, nil)
			subkeyHeader := make([]byte, 64)
			if _, err := io.ReadFull(unifiedKDF, subkeyHeader); err != nil {
				panic(errors.New("fatal hkdf.Read error"))
			}
			macHeader := hmac.New(sha3.New512, subkeyHeader)

			macHeader.Write(headerVersion)
			macHeader.Write([]byte(fmt.Sprintf("%05d", headerCommentsLen)))
			macHeader.Write(headerComments)
			macHeader.Write(headerFlags)
			macHeader.Write(salt)
			macHeader.Write(hkdfSalt)
			macHeader.Write(serpentIV)
			macHeader.Write(nonce)
			macHeader.Write(keyfileHash)

			keyHash = macHeader.Sum(nil)

			headerValid := subtle.ConstantTimeCompare(keyHash, keyHashRef) == 1
			keyfileCorrect := subtle.ConstantTimeCompare(keyfileHash, keyfileHashRef) == 1
			incorrect := !headerValid
			if useKeyfiles {
				incorrect = !headerValid || !keyfileCorrect
			}

			if incorrect {
				if state.keep {
					state.kept = true
				} else {
					if !headerValid {
						status.main = "The password is incorrect or header is tampered"
					} else {
						if state.keyfileOrdered {
							status.main = "Incorrect keyfiles or ordering"
						} else {
							status.main = "Incorrect keyfiles"
						}
						if state.deniability {
							fin.Close()
							os.Remove(state.inputFile)
							state.inputFile = strings.TrimSuffix(state.inputFile, ".tmp")
						}
					}
					broken(fin, nil, status.main, true)
					if state.recombine {
						state.inputFile = state.inputFileOld
					}
					return
				}
			}

			// Create the output file for decryption (after validation)
			fout, err = os.Create(state.outputFile + ".incomplete")
			if err != nil {
				fin.Close()
				if state.recombine {
					os.Remove(state.inputFile)
				}
				accessDenied("Write")
				return
			}
		}
	}

	if useKeyfiles && len(state.keyfiles) > 0 {
		// Prevent an even number of duplicate keyfiles
		if bytes.Equal(keyfileKey, make([]byte, 32)) {
			status.main = "Duplicate keyfiles detected"
			status.mainColor = RED
			fin.Close()
			if len(state.allFiles) > 1 || len(state.onlyFolders) > 0 || state.compress {
				os.Remove(state.inputFile)
			}
			fout.Close()
			os.Remove(fout.Name())
			return
		}

		// XOR the encryption key with the keyfile key
		tmp := key
		key = make([]byte, 32)
		for i := range key {
			key[i] = tmp[i] ^ keyfileKey[i]
		}
	}

	done, counter := 0, 0
	chacha, err := chacha20.NewUnauthenticatedCipher(key, nonce)
	if err != nil {
		panic(err)
	}

	// Use the single HKDF stream to derive payload MAC subkey and Serpent key
	var mac hash.Hash
	subkey := make([]byte, 32)
	// Initialize HKDF for legacy v1 only after keyfiles have been XORed into key
	if isLegacyV1 && unifiedKDF == nil {
		unifiedKDF = hkdf.New(sha3.New256, key, hkdfSalt, nil)
	}
	if _, err := io.ReadFull(unifiedKDF, subkey); err != nil {
		panic(errors.New("fatal hkdf.Read error"))
	}
	if state.paranoid {
		mac = hmac.New(sha3.New512, subkey) // HMAC-SHA3
	} else {
		mac, err = blake2b.New512(subkey) // Keyed BLAKE2b
		if err != nil {
			panic(err)
		}
	}

	// Generate another subkey for use as Serpent's key
	serpentKey := make([]byte, 32)
	if _, err := io.ReadFull(unifiedKDF, serpentKey); err != nil {
		panic(errors.New("fatal hkdf.Read error"))
	}
	s, err := serpent.NewCipher(serpentKey)
	if err != nil {
		panic(err)
	}
	serpent := cipher.NewCTR(s, serpentIV)

	// Start the main encryption process
	status.canCancel = true
	startTime := time.Now()
	tempZip := encryptedZipReader{
		_r:      fin,
		_cipher: tempZipCipherR,
	}
	for {
		if !status.working {
			cancel(fin, fout)
			if state.recombine || len(state.allFiles) > 1 || len(state.onlyFolders) > 0 || state.compress {
				os.Remove(state.inputFile)
			}
			os.Remove(fout.Name())
			return
		}

		// Read in data from the file
		var src []byte
		if state.mode == "decrypt" && state.reedSolomon {
			src = make([]byte, MiB/128*136)
		} else {
			src = make([]byte, MiB)
		}

		var size int
		if tempZipInUse {
			size, err = tempZip.Read(src)
		} else {
			size, err = fin.Read(src)
		}
		if err != nil {
			break
		}
		src = src[:size]
		dst := make([]byte, len(src))

		// Do the actual encryption
		if state.mode == "encrypt" {
			if state.paranoid {
				serpent.XORKeyStream(dst, src)
				copy(src, dst)
			}

			chacha.XORKeyStream(dst, src)
			if _, err := mac.Write(dst); err != nil {
				panic(err)
			}

			if state.reedSolomon {
				copy(src, dst)
				dst = nil
				// If a full MiB is available
				if len(src) == MiB {
					// Encode every chunk
					for i := 0; i < MiB; i += 128 {
						dst = append(dst, rsEncode(rs128, src[i:i+128])...)
					}
				} else {
					// Encode the full chunks
					chunks := math.Floor(float64(len(src)) / 128)
					for i := 0; float64(i) < chunks; i++ {
						dst = append(dst, rsEncode(rs128, src[i*128:(i+1)*128])...)
					}

					// Pad and encode the final partial chunk
					dst = append(dst, rsEncode(rs128, pad(src[int(chunks*128):]))...)
				}
			}
		} else { // Decryption
			if state.reedSolomon {
				copy(dst, src)
				src = nil
				// If a complete 1 MiB block is available
				if len(dst) == MiB/128*136 {
					// Decode every chunk
					for i := 0; i < MiB/128*136; i += 136 {
						tmp, err := rsDecode(rs128, dst[i:i+136])
						if err != nil {
							if state.keep {
								state.kept = true
							} else {
								broken(fin, fout, "The input file is irrecoverably damaged", false)
								return
							}
						}
						if i == MiB/128*136-136 && done+MiB/128*136 >= int(total) && padded {
							tmp = unpad(tmp)
						}
						src = append(src, tmp...)

						if !fastDecode && i%17408 == 0 {
							status.progress, status.speed, status.eta = statify(int64(done+i), total, startTime)
							status.progressInfo = fmt.Sprintf("%.2f%%", status.progress*100)
							status.popup = fmt.Sprintf("Repairing at %.2f MiB/s (ETA: %s)", status.speed, status.eta)
						}
					}
				} else {
					// Decode the full chunks
					chunks := len(dst)/136 - 1
					for i := range chunks {
						tmp, err := rsDecode(rs128, dst[i*136:(i+1)*136])
						if err != nil {
							if state.keep {
								state.kept = true
							} else {
								broken(fin, fout, "The input file is irrecoverably damaged", false)
								return
							}
						}
						src = append(src, tmp...)

						if !fastDecode && i%128 == 0 {
							status.progress, status.speed, status.eta = statify(int64(done+i*136), total, startTime)
							status.progressInfo = fmt.Sprintf("%.2f%%", status.progress*100)
							status.popup = fmt.Sprintf("Repairing at %.2f MiB/s (ETA: %s)", status.speed, status.eta)
						}
					}

					// Unpad and decode the final partial chunk
					tmp, err := rsDecode(rs128, dst[int(chunks)*136:])
					if err != nil {
						if state.keep {
							state.kept = true
						} else {
							broken(fin, fout, "The input file is irrecoverably damaged", false)
							return
						}
					}
					src = append(src, unpad(tmp)...)
				}
				dst = make([]byte, len(src))
			}

			if _, err := mac.Write(src); err != nil {
				panic(err)
			}
			chacha.XORKeyStream(dst, src)

			if state.paranoid {
				copy(src, dst)
				serpent.XORKeyStream(dst, src)
			}
		}

		// Write the data to output file
		_, err = fout.Write(dst)
		if err != nil {
			insufficientSpace(fin, fout)
			if state.recombine || len(state.allFiles) > 1 || len(state.onlyFolders) > 0 || state.compress {
				os.Remove(state.inputFile)
			}
			os.Remove(fout.Name())
			return
		}

		// Update stats
		if state.mode == "decrypt" && state.reedSolomon {
			done += MiB / 128 * 136
		} else {
			done += MiB
		}
		counter += MiB
		status.progress, status.speed, status.eta = statify(int64(done), total, startTime)
		status.progressInfo = fmt.Sprintf("%.2f%%", status.progress*100)
		if state.mode == "encrypt" {
			status.popup = fmt.Sprintf("Encrypting at %.2f MiB/s (ETA: %s)", status.speed, status.eta)
		} else {
			if fastDecode {
				status.popup = fmt.Sprintf("Decrypting at %.2f MiB/s (ETA: %s)", status.speed, status.eta)
			}
		}

		// Change nonce/IV after 60 GiB to prevent overflow
		if counter >= 60*GiB {
			// ChaCha20
			nonce = make([]byte, 24)
			if _, err := io.ReadFull(unifiedKDF, nonce); err != nil {
				panic(errors.New("fatal hkdf.Read error"))
			}
			chacha, err = chacha20.NewUnauthenticatedCipher(key, nonce)
			if err != nil {
				panic(err)
			}

			// Serpent
			serpentIV = make([]byte, 16)
			if _, err := io.ReadFull(unifiedKDF, serpentIV); err != nil {
				panic(errors.New("fatal hkdf.Read error"))
			}
			serpent = cipher.NewCTR(s, serpentIV)

			// Reset counter to 0
			counter = 0
		}
	}

	status.progress = 0
	status.progressInfo = ""

	if state.mode == "encrypt" {
		status.popup = "Writing values..."

		// Seek back to header and write important values
		if _, err := fout.Seek(int64(309+len(state.comments)*3), 0); err != nil {
			panic(err)
		}
		if _, err := fout.Write(rsEncode(rs64, keyHash)); err != nil {
			panic(err)
		}
		if _, err := fout.Write(rsEncode(rs32, keyfileHash)); err != nil {
			panic(err)
		}
		if _, err := fout.Write(rsEncode(rs64, mac.Sum(nil))); err != nil {
			panic(err)
		}
	} else {
		status.popup = "Comparing values..."

		// Validate the authenticity of decrypted data
		if subtle.ConstantTimeCompare(mac.Sum(nil), authTag) == 0 {
			// Decrypt again but this time rebuilding the input data
			if state.reedSolomon && fastDecode {
				fastDecode = false
				fin.Close()
				fout.Close()
				work()
				return
			}

			if state.keep {
				state.kept = true
			} else {
				broken(fin, fout, "The input file is damaged or modified", false)
				return
			}
		}
	}

	if err := fin.Close(); err != nil {
		panic(err)
	}
	if err := fout.Close(); err != nil {
		panic(err)
	}

	if err := os.Rename(state.outputFile+".incomplete", state.outputFile); err != nil {
		panic(err)
	}

	// Add plausible deniability
	if state.mode == "encrypt" && state.deniability {
		status.popup = "Adding plausible deniability..."
		status.canCancel = false

		// Get size of volume for showing progress
		stat, err := os.Stat(state.outputFile)
		if err != nil {
			panic(err)
		}
		total := stat.Size()

		// Rename the output volume to free up the filename
		os.Rename(state.outputFile, state.outputFile+".tmp")
		fin, err := os.Open(state.outputFile + ".tmp")
		if err != nil {
			panic(err)
		}
		fout, err := os.Create(state.outputFile + ".incomplete")
		if err != nil {
			panic(err)
		}

		// Use a random Argon2 salt and XChaCha20 nonce
		salt := make([]byte, 16)
		nonce := make([]byte, 24)
		if n, err := rand.Read(salt); err != nil || n != 16 {
			panic(errors.New("fatal crypto/rand error"))
		}
		if n, err := rand.Read(nonce); err != nil || n != 24 {
			panic(errors.New("fatal crypto/rand error"))
		}
		if bytes.Equal(salt, make([]byte, 16)) || bytes.Equal(nonce, make([]byte, 24)) {
			panic(errors.New("fatal crypto/rand error"))
		}
		if _, err := fout.Write(salt); err != nil {
			panic(err)
		}
		if _, err := fout.Write(nonce); err != nil {
			panic(err)
		}

		// Generate key and XChaCha20
		key := argon2.IDKey([]byte(state.password), salt, 4, 1<<20, 4, 32)
		if bytes.Equal(key, make([]byte, 32)) {
			panic(errors.New("fatal crypto/argon2 error"))
		}
		chacha, err := chacha20.NewUnauthenticatedCipher(key, nonce)
		if err != nil {
			panic(err)
		}

		// Encrypt the entire volume
		done, counter := 0, 0
		for {
			src := make([]byte, MiB)
			size, err := fin.Read(src)
			if err != nil {
				break
			}
			src = src[:size]
			dst := make([]byte, len(src))
			chacha.XORKeyStream(dst, src)
			if _, err := fout.Write(dst); err != nil {
				panic(err)
			}

			// Update stats
			done += size
			counter += MiB
			status.progress = float32(float64(done) / float64(total))

			// Change nonce after 60 GiB to prevent overflow
			if counter >= 60*GiB {
				tmp := sha3.New256()
				if _, err := tmp.Write(nonce); err != nil {
					panic(err)
				}
				nonce = tmp.Sum(nil)[:24]
				chacha, err = chacha20.NewUnauthenticatedCipher(key, nonce)
				if err != nil {
					panic(err)
				}
				counter = 0
			}
		}

		if err := fin.Close(); err != nil {
			panic(err)
		}
		if err := fout.Close(); err != nil {
			panic(err)
		}
		if err := os.Remove(fin.Name()); err != nil {
			panic(err)
		}
		if err := os.Rename(state.outputFile+".incomplete", state.outputFile); err != nil {
			panic(err)
		}
		status.canCancel = true

	}

	// Split the file into chunks
	if state.split {
		var splitted []string
		stat, err := os.Stat(state.outputFile)
		if err != nil {
			panic(err)
		}
		size := stat.Size()
		finishedFiles := 0
		finishedBytes := 0
		chunkSize, err := strconv.Atoi(state.splitSize)
		if err != nil {
			panic(err)
		}

		// Calculate chunk size
		if state.splitSelected == 0 {
			chunkSize *= KiB
		} else if state.splitSelected == 1 {
			chunkSize *= MiB
		} else if state.splitSelected == 2 {
			chunkSize *= GiB
		} else if state.splitSelected == 3 {
			chunkSize *= TiB
		} else {
			chunkSize = int(math.Ceil(float64(size) / float64(chunkSize)))
		}

		// Get the number of required chunks
		chunks := int(math.Ceil(float64(size) / float64(chunkSize)))
		status.progressInfo = fmt.Sprintf("%d/%d", finishedFiles+1, chunks)

		// Open the volume for reading
		fin, err := os.Open(state.outputFile)
		if err != nil {
			panic(err)
		}

		// Delete existing chunks to prevent mixed chunks
		names, err := filepath.Glob(state.outputFile + ".*")
		if err != nil {
			panic(err)
		}
		for _, i := range names {
			if err := os.Remove(i); err != nil {
				panic(err)
			}
		}

		// Start the splitting process
		startTime := time.Now()
		for i := range chunks {
			// Make the chunk
			fout, _ := os.Create(fmt.Sprintf("%s.%d.incomplete", state.outputFile, i))
			done := 0

			// Copy data into the chunk
			for {
				data := make([]byte, MiB)
				for done+len(data) > chunkSize {
					data = make([]byte, int(math.Ceil(float64(len(data))/2)))
				}

				read, err := fin.Read(data)
				if err != nil {
					break
				}
				if !status.working {
					cancel(fin, fout)
					if len(state.allFiles) > 1 || len(state.onlyFolders) > 0 || state.compress {
						os.Remove(state.inputFile)
					}
					os.Remove(state.outputFile)
					for _, j := range splitted { // Remove existing chunks
						os.Remove(j)
					}
					os.Remove(fmt.Sprintf("%s.%d", state.outputFile, i))
					return
				}

				data = data[:read]
				_, err = fout.Write(data)
				if err != nil {
					insufficientSpace(fin, fout)
					if len(state.allFiles) > 1 || len(state.onlyFolders) > 0 || state.compress {
						os.Remove(state.inputFile)
					}
					os.Remove(state.outputFile)
					for _, j := range splitted { // Remove existing chunks
						os.Remove(j)
					}
					os.Remove(fmt.Sprintf("%s.%d", state.outputFile, i))
					return
				}
				done += read
				if done >= chunkSize {
					break
				}

				// Update stats
				finishedBytes += read
				status.progress, status.speed, status.eta = statify(int64(finishedBytes), int64(size), startTime)
				status.popup = fmt.Sprintf("Splitting at %.2f MiB/s (ETA: %s)", status.speed, status.eta)
			}
			if err := fout.Close(); err != nil {
				panic(err)
			}

			// Update stats
			finishedFiles++
			if finishedFiles == chunks {
				finishedFiles--
			}
			splitted = append(splitted, fmt.Sprintf("%s.%d", state.outputFile, i))
			status.progressInfo = fmt.Sprintf("%d/%d", finishedFiles+1, chunks)
		}

		if err := fin.Close(); err != nil {
			panic(err)
		}
		if err := os.Remove(state.outputFile); err != nil {
			panic(err)
		}
		names, err = filepath.Glob(state.outputFile + ".*.incomplete")
		if err != nil {
			panic(err)
		}
		for _, i := range names {
			if err := os.Rename(i, strings.TrimSuffix(i, ".incomplete")); err != nil {
				panic(err)
			}
		}
	}

	status.canCancel = false
	status.progress = 0
	status.progressInfo = ""

	// Delete temporary files used during encryption and decryption
	if state.recombine || len(state.allFiles) > 1 || len(state.onlyFolders) > 0 || state.compress {
		if err := os.Remove(state.inputFile); err != nil {
			panic(err)
		}
		if state.deniability {
			os.Remove(strings.TrimSuffix(state.inputFile, ".tmp"))
		}
	}

	// Delete the input files if the user chooses
	if state.delete {
		status.popup = "Deleting files..."

		if state.mode == "decrypt" {
			if state.recombine { // Remove each chunk of volume
				i := 0
				for {
					_, err := os.Stat(fmt.Sprintf("%s.%d", state.inputFileOld, i))
					if err != nil {
						break
					}
					if err := os.Remove(fmt.Sprintf("%s.%d", state.inputFileOld, i)); err != nil {
						panic(err)
					}
					i++
				}
			} else {
				if err := os.Remove(state.inputFile); err != nil {
					panic(err)
				}
				if state.deniability {
					if err := os.Remove(strings.TrimSuffix(state.inputFile, ".tmp")); err != nil {
						panic(err)
					}
				}
			}
		} else {
			for _, i := range state.onlyFiles {
				if err := os.Remove(i); err != nil {
					panic(err)
				}
			}
			for _, i := range state.onlyFolders {
				if err := os.RemoveAll(i); err != nil {
					panic(err)
				}
			}
		}
	}
	if state.mode == "decrypt" && state.deniability {
		os.Remove(state.inputFile)
	}

	if state.mode == "decrypt" && !state.kept && state.autoUnzip {
		status.showProgress = true
		status.popup = "Unzipping..."

		if err := unpackArchive(state.outputFile); err != nil {
			status.main = "Auto unzipping failed!"
			status.mainColor = RED
			return
		}

		if err := os.Remove(state.outputFile); err != nil {
			panic(err)
		}
	}

	// All done, reset the UI
	oldKept := state.kept
	resetUI()
	state.kept = oldKept

	// If the user chose to keep a corrupted/modified file, let them know
	if state.kept {
		status.main = "The input file was modified. Please be careful"
		status.mainColor = YELLOW
	} else {
		status.main = "Completed"
		status.mainColor = GREEN
	}
}

// If the OS denies reading or writing to a file
func accessDenied(s string) {
	status.main = s + " access denied by operating system"
	status.mainColor = RED
}

// If there isn't enough disk space
func insufficientSpace(fin *os.File, fout *os.File) {
	fin.Close()
	fout.Close()
	status.main = "Insufficient disk space"
	status.mainColor = RED
}

// If corruption is detected during decryption
func broken(fin *os.File, fout *os.File, message string, keepOutput bool) {
	fin.Close()
	fout.Close()
	status.main = message
	status.mainColor = RED

	// Clean up files since decryption failed
	if state.recombine {
		os.Remove(state.inputFile)
	}
	if !keepOutput {
		os.Remove(state.outputFile)
	}
}

// Stop working if user hits "Cancel"
func cancel(fin *os.File, fout *os.File) {
	fin.Close()
	fout.Close()
	status.main = "Operation cancelled by user"
	status.mainColor = WHITE
}

// Reset the UI to a clean state with nothing selected or checked
func resetUI() {
	state.mode = ""

	state.inputFile = ""
	state.inputFileOld = ""
	state.outputFile = ""
	state.onlyFiles = nil
	state.onlyFolders = nil
	state.allFiles = nil
	status.inputLabel = "Drop files and folders into this window"

	state.password = ""
	state.confirmPassword = ""
	status.passwordHide = true

	state.passgenLength = 32
	state.passgenUpper = true
	state.passgenLower = true
	state.passgenNums = true
	state.passgenSymbols = true
	state.passgenCopy = true

	state.keyfile = false
	state.keyfiles = nil
	state.keyfileOrdered = false
	status.keyfileLabel = "None selected"

	state.comments = ""
	status.commentsLabel = "Comments:"
	status.commentsDisabled = false

	state.paranoid = false
	state.reedSolomon = false
	state.deniability = false
	state.recursively = false
	state.split = false
	state.splitSize = ""
	state.splitSelected = 1
	state.recombine = false
	state.compress = false
	state.delete = false
	state.autoUnzip = false
	state.sameLevel = false
	state.keep = false
	state.kept = false

	status.startLabel = "Start"
	status.main = "ready"
	status.mainColor = WHITE
	status.popup = ""
	status.requiredFreeSpace = 0

	status.progress = 0
	status.progressInfo = ""

}

// Reed-Solomon encoder
func rsEncode(rs *infectious.FEC, data []byte) []byte {
	res := make([]byte, rs.Total())
	rs.Encode(data, func(s infectious.Share) {
		res[s.Number] = s.Data[0]
	})
	return res
}

// Reed-Solomon decoder
func rsDecode(rs *infectious.FEC, data []byte) ([]byte, error) {
	// If fast decode, just return the first 128 bytes
	if rs.Total() == 136 && fastDecode {
		return data[:128], nil
	}

	tmp := make([]infectious.Share, rs.Total())
	for i := range rs.Total() {
		tmp[i].Number = i
		tmp[i].Data = append(tmp[i].Data, data[i])
	}
	res, err := rs.Decode(nil, tmp)

	// Force decode the data but return the error as well
	if err != nil {
		if rs.Total() == 136 {
			return data[:128], err
		}
		return data[:rs.Total()/3], err
	}

	// No issues, return the decoded data
	return res, nil
}

// PKCS#7 pad (for use with Reed-Solomon)
func pad(data []byte) []byte {
	padLen := 128 - len(data)%128
	padding := bytes.Repeat([]byte{byte(padLen)}, padLen)
	return append(data, padding...)
}

// PKCS#7 unpad
func unpad(data []byte) []byte {
	padLen := int(data[127])
	return data[:128-padLen]
}

// Generate a cryptographically secure password
func genPassword() string {
	chars := ""
	if state.passgenUpper {
		chars += "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
	}
	if state.passgenLower {
		chars += "abcdefghijklmnopqrstuvwxyz"
	}
	if state.passgenNums {
		chars += "1234567890"
	}
	if state.passgenSymbols {
		chars += "-=_+!@#$^&()?<>"
	}

	max := big.NewInt(int64(len(chars)))
	tmp := make([]byte, state.passgenLength)
	for i := range tmp {
		idx, err := rand.Int(rand.Reader, max)
		if err != nil {
			return ""
		}
		tmp[i] = chars[idx.Int64()]
	}
	result := string(tmp)
	return result
}

// Convert done, total, and starting time to progress, speed, and ETA
func statify(done int64, total int64, start time.Time) (float32, float64, string) {
	progress := float32(done) / float32(total)
	elapsed := float64(time.Since(start)) / float64(MiB) / 1000
	speed := float64(done) / elapsed / float64(MiB)
	eta := int(math.Floor(float64(total-done) / (speed * float64(MiB))))
	return float32(math.Min(float64(progress), 1)), speed, timeify(eta)
}

// Convert seconds to HH:MM:SS
func timeify(seconds int) string {
	hours := int(math.Floor(float64(seconds) / 3600))
	seconds %= 3600
	minutes := int(math.Floor(float64(seconds) / 60))
	seconds %= 60
	hours = int(math.Max(float64(hours), 0))
	minutes = int(math.Max(float64(minutes), 0))
	seconds = int(math.Max(float64(seconds), 0))
	return fmt.Sprintf("%02d:%02d:%02d", hours, minutes, seconds)
}

// Convert bytes to KiB, MiB, etc.
func sizeify(size int64) string {
	if size >= int64(TiB) {
		return fmt.Sprintf("%.2f TiB", float64(size)/float64(TiB))
	} else if size >= int64(GiB) {
		return fmt.Sprintf("%.2f GiB", float64(size)/float64(GiB))
	} else if size >= int64(MiB) {
		return fmt.Sprintf("%.2f MiB", float64(size)/float64(MiB))
	} else {
		return fmt.Sprintf("%.2f KiB", float64(size)/float64(KiB))
	}
}

func unpackArchive(zipPath string) error {
	reader, err := zip.OpenReader(zipPath)
	if err != nil {
		return err
	}
	defer reader.Close()

	var totalSize int64
	for _, f := range reader.File {
		totalSize += int64(f.UncompressedSize64)
	}

	var extractDir string
	if state.sameLevel {
		extractDir = filepath.Dir(zipPath)
	} else {
		extractDir = filepath.Join(filepath.Dir(zipPath), strings.TrimSuffix(filepath.Base(zipPath), ".zip"))
	}

	var done int64
	startTime := time.Now()

	for _, f := range reader.File {
		if strings.Contains(f.Name, "..") {
			return errors.New("potentially malicious zip item path")
		}
		outPath := filepath.Join(extractDir, f.Name)

		// Make directory if current entry is a folder
		if f.FileInfo().IsDir() {
			if err := os.MkdirAll(outPath, 0700); err != nil {
				return err
			}
		}
	}

	for i, f := range reader.File {
		if strings.Contains(f.Name, "..") {
			return errors.New("potentially malicious zip item path")
		}

		// Already handled above
		if f.FileInfo().IsDir() {
			continue
		}

		outPath := filepath.Join(extractDir, f.Name)

		// Otherwise create necessary parent directories
		if err := os.MkdirAll(filepath.Dir(outPath), 0700); err != nil {
			return err
		}

		// Open the file inside the archive
		fileInArchive, err := f.Open()
		if err != nil {
			return err
		}
		defer fileInArchive.Close()

		dstFile, err := os.Create(outPath)
		if err != nil {
			return err
		}

		// Read from zip in chunks to update progress
		buffer := make([]byte, MiB)
		for {
			n, readErr := fileInArchive.Read(buffer)
			if n > 0 {
				_, writeErr := dstFile.Write(buffer[:n])
				if writeErr != nil {
					dstFile.Close()
					os.Remove(dstFile.Name())
					return writeErr
				}

				done += int64(n)
				status.progress, status.speed, status.eta = statify(done, totalSize, startTime)
				status.progressInfo = fmt.Sprintf("%d/%d", i+1, len(reader.File))
				status.popup = fmt.Sprintf("Unpacking at %.2f MiB/s (ETA: %s)", status.speed, status.eta)
			}
			if readErr != nil {
				if readErr == io.EOF {
					break
				}
				dstFile.Close()
				return readErr
			}
		}
		dstFile.Close()
	}

	return nil
}
