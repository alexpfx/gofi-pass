package main

import (
	"bufio"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/alexpfx/gofi"
	gofipass "github.com/alexpfx/gofi-pass/internal/gofi-pass"
	"github.com/alexpfx/gofi-pass/internal/util"
	"github.com/alexpfx/gofi/dmenu"

	"github.com/urfave/cli/v2"
)

const minLen = 8
const maxLen = 32

func main() {

	userHome, _ := os.UserHomeDir()
	defaultPassStore := filepath.Join(userHome, ".password-store")
	userConfigDir, _ := os.UserConfigDir()
	defaultBackupFile := filepath.Join(userConfigDir, "gofi-pass", ".userpass.bkp")
	var storeDir string
	var bkpFile string

	app := cli.App{
		Flags: []cli.Flag{
			&cli.StringFlag{
				Name:        "file",
				Aliases:     []string{"f"},
				Value:       defaultBackupFile,
				Destination: &bkpFile,
			},
		},
		Commands: []*cli.Command{
			{
				Name:    "restore",
				Aliases: []string{"r"},
				Action: func(ctx *cli.Context) error {
					if bkpFile == "" {
						return errors.New("bkpFile deve ser informado")
					}
					key, err := readCheckKey()
					if err != nil {
						return err
					}
					rst := gofipass.NewRestore(bkpFile, key)
					return rst.Run()
				},
			},
			{
				Name:    "backup",
				Aliases: []string{"bk"},
				Flags: []cli.Flag{
					&cli.StringFlag{
						Name:        "store-dir",
						Aliases:     []string{"d"},
						Value:       defaultPassStore,
						Destination: &storeDir,
					},
				},

				Action: func(ctx *cli.Context) error {
					if bkpFile == "" {
						return errors.New("bkpFile deve ser informado")
					}
					if storeDir == "" {
						return errors.New("storeDir deve ser informado")
					}
					key, err := readCheckKey()
					if err != nil {
						return err
					}

					bkp := gofipass.NewBackup(storeDir, bkpFile, key)
					return bkp.Run()
				},
			},
			{
				Name:    "pass",
				Aliases: []string{"p"},
				Action: func(ctx *cli.Context) error {
					scanner := bufio.NewScanner(os.Stdin)
					scanner.Scan()
					t := scanner.Text()
					if t == "" {
						return fmt.Errorf("password não escolhida")
					}
					cmd := exec.Command("pass", t)
					out, err := cmd.CombinedOutput()
					if err != nil {
						return fmt.Errorf(string(out))
					}

					strOut := string(out)

					if strOut == "" {
						return fmt.Errorf("password não escolhida")
					}

					cmd = exec.Command("xdotool", "type", "--delay", "1", strOut)
					_, err = cmd.CombinedOutput()
					if err != nil {
						return fmt.Errorf(err.Error())
					}
					return nil
				},
			},
			{
				Name:    "menu",
				Aliases: []string{"m"},
				Flags: []cli.Flag{
					&cli.StringFlag{
						Name:  "store-dir",
						Value: defaultPassStore,
					},
				},
				Action: func(ctx *cli.Context) error {
					storeDir := ctx.String("store-dir")
					passList := util.ReadPassList(storeDir)

					sb := strings.Builder{}

					for _, v := range passList {
						sb.WriteString(fmt.Sprint(v, "|"))
					}
					dm := dmenu.New(dmenu.Config{
						Sep:    "|",
						Prompt: "Select",
						Lines:  10,
					})

					res, _ := gofi.CallRofi(sb.String(), dm.Build())
					fmt.Print(res)
					return nil
				},
			},
		},
	}

	err := app.Run(os.Args)
	if err != nil {
		gerr := gofi.New(gofi.Config{
			Error: err.Error(),
		})
		gofi.CallRofi("", gerr.Build())
	}

}

func readCheckKey() (string, error) {
	userKey, err := util.ReadKey()
	if err != nil {
		return "", err
	}
	if len(userKey) < minLen || len(userKey) >= maxLen {
		return "", fmt.Errorf("chave deve ter entre %d e %d caractéres", minLen, maxLen)
	}

	return util.PadKey(userKey, maxLen)
}
