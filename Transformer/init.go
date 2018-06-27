package main

import (
	"regexp"
	"io"
	"io/ioutil"
	"fmt"
	"os"
	"bytes"
	"flag"
	"errors"
)

var FILEIN = ""
var FILEOUT = ""





var state = NonPhp
var ValidWord = regexp.MustCompile("\\w").MatchString
var NewLine = regexp.MustCompile("\\r\\n|\\r|\\n|;").MatchString

var PhpFlag = []byte("<?php")
var endComment = []byte("*/")

const (
	UserDef        = iota
	Quoted         = iota
	Scan           = iota
	Escaped        = iota
	NonPhp         = iota
	FwdSlash       = iota
	MultiComment   = iota
	OneLineComment = iota
	Question 	   = iota
)

const (
	DubQUOTE  = rune('"')
	VARIABLE  = rune('$')
	BACKSLASH = rune('\\')
	RBRACKET  = rune('>')
	HASHTAG   = rune('#')
	ASTRIX    = rune('*')
	FwdSLASH  = rune('/')
	QUESTION  = rune('?')
)


func initReader() io.RuneReader {

	parseCmdLn()

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

func parseCmdLn() { //TODO: This should take multiple files eventually.
	flag.StringVar(&FILEIN, "f", "", "File to transform needed")

	flag.Parse()
	FILEOUT = "ps-" + FILEIN

	if FILEIN == "" || FILEOUT == "" {
		err := errors.New("required field '-f' missing. Please input filename" )
		fmt.Println(err)
		os.Exit(1)
	}

}
