package main

import (
	"github.com/davecgh/go-spew/spew"
	"github.com/jpbede/gobgpq3"
)

func main() {
	origins, _ := gobgpq3.GetOriginatedByASSet("AS-JPBE")

	spew.Dump(origins)
}