package main

import (
	"fmt"
	"github.com/jpbede/gobgpq3"
	"github.com/urfave/cli"
	"log"
	"os"
)

func main() {
	app := cli.NewApp()
	app.Name = "gobgpq3"
	//app.Usage = "make an explosive entrance"

	app.Commands = []cli.Command{
		{
			Name:      "prefixes",
			Aliases:   []string{"p"},
			Usage:     "list of prefixes originated by as-set",
			ArgsUsage: "[as-set]",
			Action: func(c *cli.Context) error {
				prefixes, _ := gobgpq3.GetOriginatedByASSet(c.Args().First())

				for _, prefix := range prefixes {
					fmt.Println("ip prefix-list PL-TEST permit " + prefix)
				}

				return nil
			},
		},
	}

	err := app.Run(os.Args)
	if err != nil {
		log.Fatal(err)
	}
}
