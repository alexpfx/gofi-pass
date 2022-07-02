package gofipass

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"os"
	"path/filepath"
	"strings"

	"github.com/alexpfx/gofi-pass/internal/util"
)

func NewBackup(storeDir, targetFile, key string) Backup {
	return &backup{storeDir: storeDir, targetFile: targetFile, key: key}
}

func NewRestore(encodedFile, key string) Restore {
	return &restore{encodedFile: encodedFile, key: key}
}

type Backup interface {
	Run() error
}

type Restore interface {
	Run() error
}

type backup struct {
	storeDir   string
	targetFile string
	key        string
}
type restore struct {
	encodedFile string
	key         string
}

func (b *backup) Run() error {
	passList := util.ReadPassList(b.storeDir)
	list := make([]passStruct, 0)

	for _, n := range passList {
		p, _ := util.ExecPass(n)
		fmt.Println(p)
		list = append(list, passStruct{Name: n, Pass: strings.TrimSpace(p)})
	}

	jsonStr, err := json.Marshal(list)
	if err != nil {
		return fmt.Errorf("erro ao codificar json %s", err)
	}

	key, err := util.PadKey(b.key, 32)
	if err != nil {
		return err
	}

	cipherText := util.Encrypt(key, jsonStr)

	dir := filepath.Dir(b.targetFile)
	if _, err := os.Stat(dir); os.IsNotExist(err) {
		err := os.MkdirAll(dir, os.ModePerm)
		if err != nil {
			return err
		}
	}

	f, err := os.Create(b.targetFile)
	if err != nil {
		log.Fatalf("erro ao criar arquivo com senhas criptografadas %s", err)
	}

	_, err = io.Copy(f, bytes.NewReader(cipherText))
	if err != nil {
		log.Fatalf("erro ao copiar conteúdo para arquivo com senhas criptografadas %s", err)
	}

	return err
}

// Run implements Restore
func (r *restore) Run() error {
	cipherText, err := ioutil.ReadFile(r.encodedFile)
	if err != nil {
		return err
	}
	userKey, err := util.ReadKey()
	if err != nil {
		return err
	}

	key, err := util.PadKey(userKey, 32)
	if err != nil {
		return err
	}
	bs := util.Decrypt(key, cipherText)

	var passList []passStruct

	err = json.Unmarshal(bs, &passList)
	if err != nil {
		return err
	}
	return nil
}

type passStruct struct {
	Name string
	Pass string
}
