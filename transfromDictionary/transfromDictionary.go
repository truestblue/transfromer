package main

import (
	"bytes"
	"log"
	"io"
)

//TODO: TAKE FILE NAME AS INPUT
//TODO: REFACTOR
//TODO: Put it in Polyverse php folder.
//TODO: Take in outputted dictionary from polyscripted-php

var bufTok = bytes.Buffer{}
var bufOut = bytes.Buffer{}
var state = Scan

var numReplaced = 0

func main() {
	r := initReader()

	for {
		c, _, err := r.ReadRune()
		if err != nil {
			if err == io.EOF {
				break
			} else {
				log.Fatal(err)
			}
		}

		processState(c)
	}

	writeOut(bufOut.Bytes())
}

func processState(c rune) {
	bufTok.WriteRune(c)

	switch state {
	case Escaped:
		//do-nothing
		break
	case UserDef:
		if !ValidWord(string(c)) {
			RestartScan()
		}
	case Quoted:
		if c == DubQUOTE {
			RestartScan()
		}
		//print until end quote
	case Scan:
		if !ValidWord(string(c)) {
			endWord(lookUpBuffer(), c)
		}
	}

}

func RestartScan() {
	bufOut.Write(bufTok.Bytes())
	bufTok.Reset()
	state = Scan
}

func transitionState(c rune) {
	switch c {
	case DubQUOTE:
		state = Quoted
	case VARIABLE:
		state = UserDef
	case BACKSLASH:
		state = Escaped
	}
}

func endWord(str string, c rune) {
	bufOut.WriteString(str)
	bufOut.WriteRune(c)
	bufTok.Reset()
	transitionState(c)
}

