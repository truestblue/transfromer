package main

import (
	"regexp"
	"io"
	"io/ioutil"
	"fmt"
	"os"
	"bytes"
)
const FILEIN = "/Users/bluegaston/test.php"
//const FILEIN = "/Users/bluegaston/Desktop/Polyverse/polyscripted-php/tests/php-tests.php"
const FILEOUT = "/Users/bluegaston/Desktop/Polyverse/polyscripted-php/tests/transfromed.txt"


var ValidWord = regexp.MustCompile("\\w").MatchString

const (
	UserDef  = iota
	Quoted   = iota
	//Brackets = iota
	Scan     = iota
	Escaped = iota
)

const DubQUOTE = rune('"')
const VARIABLE = rune('$')
const BACKSLASH = rune('\\')

func initReader() io.RuneReader {
	original, err := ioutil.ReadFile(FILEIN)

	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}

	return bytes.NewReader(original)
}

func writeOut(b []byte) {
	if err := ioutil.WriteFile(FILEOUT, b, 0666); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
	fmt.Printf("buff: %s numReplaced: %d", bufOut.String(), numReplaced)
}
