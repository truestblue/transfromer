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
const FILEOUT = "/Users/bluegaston/transformer.php"

//const FILEIN = "tests/php-tests.php"
//const FILEOUT = "tests/transformed.php"

var state = NonPhp
var ValidWord = regexp.MustCompile("\\w").MatchString
var NewLine = regexp.MustCompile("\\r\\n|\\r|\\n|;").MatchString

var bracketDepth = 0
var PhpFlag = []byte("<?php")
var endComment = []byte("*/")

const (
	UserDef        = iota
	Quoted         = iota
	Brackets       = iota
	Scan           = iota
	Escaped        = iota
	NonPhp         = iota
	FwdSearch      = iota
	MultiComment   = iota
	OneLineComment = iota
)

const (
	DubQUOTE  = rune('"')
	VARIABLE  = rune('$')
	BACKSLASH = rune('\\')
	LBRACKET  = rune('<')
	RBRACKET  = rune('>')
	HASHTAG   = rune('#')
	ASTRIX    = rune('*')
	FwdSLASH  = rune('/')
)


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
}
