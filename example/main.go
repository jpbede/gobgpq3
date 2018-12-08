package main

import (
	"github.com/davecgh/go-spew/spew"
	"github.com/jpbede/gobgpq3"
)

func main() {
	origins, err := gobgpq3.GetOriginatedByASSet("AS-JPBE")

	spew.Dump(origins)
	spew.Dump(err)
}
