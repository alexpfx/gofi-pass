package main

import (
	"bufio"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/alexpfx/gofi"
	"github.com/alexpfx/gofi/dmenu"

	"github.com/urfave/cli/v2"
)

func main() {

	userHome, _ := os.UserHomeDir()
	defaultStoreDir := filepath.Join(userHome, ".password-store/")

	app := cli.App{
		Commands: []*cli.Command{
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
					out, err := cmd.Output()

					if err != nil {
						return err
					}
					strOut := strings.TrimSpace(string(out))
					if strOut == "" {
						return fmt.Errorf("password não escolhida")
					}

					cmd = exec.Command("xdotool", "type", "--delay", "1", strOut)
					err = cmd.Start()
					return err
				},
			},
			{
				Name:    "menu",
				Aliases: []string{"m"},
				Flags: []cli.Flag{
					&cli.StringFlag{
						Name:  "store-dir",
						Value: defaultStoreDir,
					},
				},
				Action: func(ctx *cli.Context) error {
					storeDir := ctx.String("store-dir")
					passList := readPassList(storeDir)

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
		//log.Fatal(err)
	}

}

func readPassList(storeDir string) []string {
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
