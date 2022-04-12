package util

import (
	"bufio"
	"crypto/aes"
	"crypto/cipher"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

var iv = []byte{0x12, 0xA9, 0x1C, 0x11, 0x73, 0xBB, 0xF4, 0x1D, 0x12, 0xA1, 0x1C, 0x11, 0x73, 0xB1, 0xF4, 0xCD}
var defaultKey = []byte("b.Wls1AjaX.b3841jfu92.fuwF4F2cab")

func Encrypt(userKey string, plainText []byte) []byte {
	key := make([]byte, len(defaultKey))
	copy(key, defaultKey)
	copy(key, []byte(userKey))

	c, err := aes.NewCipher([]byte(key))
	if err != nil {
		panic(err)
	}

	cfb := cipher.NewCFBEncrypter(c, iv)
	cipherText := make([]byte, len(plainText))
	cfb.XORKeyStream(cipherText, plainText)
	return cipherText
}

func Decrypt(userKey string, cipherText []byte) []byte {
	key := make([]byte, len(defaultKey))
	copy(key, defaultKey)
	copy(key, []byte(userKey))

	c, err := aes.NewCipher([]byte(key))
	if err != nil {
		panic(err)
	}
	cfb := cipher.NewCFBDecrypter(c, iv)

	plainText := make([]byte, len(cipherText))
	cfb.XORKeyStream(plainText, cipherText)
	return plainText
}

func PadKey(key string, keySize int) (string, error) {
	padChar := byte(0x73)
	if len(key) > keySize {
		return "", fmt.Errorf("chave não pode possuir mais que %d caractéres", keySize)
	}
	padKey := make([]byte, keySize)
	copy(padKey, []byte(key))

	for i := len(key); i < len(padKey); i++ {
		padKey[i] = padChar
	}
	return string(padKey), nil
}

func ReadKey() (string, error) {
	scanner := bufio.NewScanner(os.Stdin)
	if scanner.Scan() {
		return scanner.Text(), nil
	}
	return "", nil
}

func ExecPass(name string) (string, error) {
	cmd := exec.Command("pass", name)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return "", fmt.Errorf(string(out))
	}
	return string(out), nil

}

func ReadPassList(storeDir string) []string {
	paths := make([]string, 0)
	filepath.WalkDir(storeDir, func(path string, dirEntry fs.DirEntry, err error) error {
		if dirEntry.IsDir() {
			return nil
		}

		ext := filepath.Ext(path)
		if ext != ".gpg" {
			return nil
		}

		name := strings.Replace(path, fmt.Sprintf("%s%s", storeDir, string(filepath.Separator)), "", 1)

		name = strings.Replace(name, ext, "", 1)
		name = strings.ReplaceAll(name, string(filepath.Separator), "/")

		paths = append(paths, name)
		return nil
	})

	return paths

}
