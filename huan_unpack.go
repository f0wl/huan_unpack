package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/md5"
	"crypto/sha256"
	"debug/pe"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"text/tabwriter"

	"github.com/AlecAivazis/survey/v2"
	"github.com/fatih/color"
)

// check errors as they occur and panic :o
func check(e error) {
	if e != nil {
		panic(e)
	}
}

// ioReader acts as a wrapper function to make opening the file even easier
func ioReader(file string) io.ReaderAt {
	r, err := os.Open(file)
	check(err)
	return r
}

func aesCBCDecrypt(data, key, iv []byte) []byte {
	aesBlockDecrypter, err := aes.NewCipher([]byte(key))
	check(err)
	aesDecrypter := cipher.NewCBCDecrypter(aesBlockDecrypter, iv)
	aesDecrypter.CryptBlocks(data, data)
	return data
}

// calcSHA256 reads the sample file and calculates its SHA-256 hashsum
func calcSHA256(file string) string {
	f, readErr := os.Open(file)
	check(readErr)
	defer f.Close()

	h := sha256.New()
	_, hashErr := io.Copy(h, f)
	check(hashErr)
	return hex.EncodeToString(h.Sum(nil))
}

// calcMD5 reads the sample file and calculates its SHA-256 hashsum
func calcMD5(file string) string {

	f, readErr := os.Open(file)
	check(readErr)
	defer f.Close()

	h := md5.New()
	_, hashErr := io.Copy(h, f)
	check(hashErr)
	return hex.EncodeToString(h.Sum(nil))
}

// getFileInfo returns the size on disk of the specified file
func getFileInfo(file string) int64 {
	f, readErr := os.Open(file)
	check(readErr)
	defer f.Close()

	fileInfo, fileErr := f.Stat()
	check(fileErr)

	return fileInfo.Size()
}

func main() {

	fmt.Println("    _  _ _  _  __  __  _     _  _ __  _ ___  __   ____  __  ")
	fmt.Println("   | || | || |/  \\|  \\| |   | || |  \\| | _,\\/  \\ / _/ |/ /  ")
	fmt.Println("   | >< | \\/ | /\\ | | ' |___| \\/ | | ' | v_/ /\\ | \\_|   <   ")
	fmt.Println("   |_||_|\\__/|_||_|_|\\__|____\\__/|_|\\__|_| |_||_|\\__/_|\\_\\  ")
	fmt.Printf("\n   Unpacker for Huan PE Crypter\n")
	fmt.Printf("   Marius 'f0wL' Genheimer | https://dissectingmalwa.re\n\n")

	if len(os.Args) < 2 {
		fmt.Println("Usage: go run huan_unpack.go path/to/packed.exe")
		os.Exit(1)
	}

	// calculate hash sums of the sample
	md5sum := calcMD5(os.Args[1])
	sha256sum := calcSHA256(os.Args[1])

	w1 := tabwriter.NewWriter(os.Stdout, 1, 1, 1, ' ', 0)
	fmt.Fprintln(w1, "→ File size (bytes): \t", getFileInfo(os.Args[1]))
	fmt.Fprintln(w1, "→ Sample MD5: \t", md5sum)
	fmt.Fprintln(w1, "→ Sample SHA-256: \t", sha256sum)
	w1.Flush()
	fmt.Print("\n")

	// read the PE
	sample := ioReader(os.Args[1])

	// parse the PE with debug/pe
	pe, parseErr := pe.NewFile(sample)
	check(parseErr)

	sectionName := ""
	prompt := &survey.Input{
		Message: "Section name [.huan]: ",
	}
	survey.AskOne(prompt, &sectionName)

	if sectionName == "" {
		sectionName = ".huan"
	}

	// dump out the contents of the .rsrc section
	sectionData, dumpErr := pe.Section(sectionName).Data()

	if dumpErr != nil {
		color.Red("\n✗ Looks like this sample might not be crypted with Huan. Please verify manually.\n")
		os.Exit(1)
		check(dumpErr)
	} else {
		color.Green("\n✓ Successfully dumped the .huan section")
	}

	// slice out file sizes, AES key and IV
	plaintextLen := binary.LittleEndian.Uint32(sectionData[0:4])
	ciphertextLen := binary.LittleEndian.Uint32(sectionData[4:8])
	extractedKey := sectionData[8:24]
	extractedIV := sectionData[24:40]
	fmt.Fprintln(w1, "→ Plaintext Length: \t", plaintextLen)
	fmt.Fprintln(w1, "→ Ciphertext Length: \t", ciphertextLen)
	fmt.Fprintln(w1, "→ Extracted Key: \t", hex.EncodeToString(extractedKey))
	fmt.Fprintln(w1, "→ Extracted IV: \t", hex.EncodeToString(extractedIV))
	w1.Flush()

	// encrypted payload
	encData := sectionData[40 : ciphertextLen+40]
	// decrypt the payload with AES CBC
	decData := aesCBCDecrypt(encData, extractedKey, extractedIV)
	filename := "decrypted-" + md5sum + ".bin"
	writeErr := ioutil.WriteFile(filename, decData, 0644)
	check(writeErr)

	color.Green("\n✓ Wrote decrypted payload to %v\n", filename)
	fmt.Printf("→ Decrypted file SHA-256: %v\n", calcSHA256(filename))
	fmt.Printf("→ Decrypted file header: \n\n")
	fmt.Print(hex.Dump(encData[:128]))
}
