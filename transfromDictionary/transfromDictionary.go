package main

import (
	"bytes"
	"log"
	"io"
	"fmt"
)

//TODO: TAKE FILE NAME AS INPUT
//TODO: Put it in Polyverse php folder.

var bufTok = bytes.Buffer{}
var bufOut = bytes.Buffer{}

var numReplaced = 0

func main() {
	r := initReader()
	initMapping()

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
	fmt.Printf("buf: %s ", bufOut.String())
	bufOut.Write(bufTok.Bytes())
	writeOut(bufOut.Bytes())
}

func processState(c rune) {
	bufTok.WriteRune(c)

	switch state {
	case NonPhp:
		if bytes.Contains(bufTok.Bytes(), PhpFlag) {
			RestartScan()
		}
	case Escaped:
		RestartScan()
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
	case MultiComment:
		if bytes.Contains(bufTok.Bytes(), endComment) {
			RestartScan()
		}

	case OneLineComment:
		if NewLine(string(c)) {
			RestartScan()
		}

	case FwdSearch:
		if c == ASTRIX {
			state = MultiComment
		} else if c == FwdSLASH {
			state = OneLineComment
		} else {
			RestartScan()
		}
	case Brackets:
		if rune(c) == LBRACKET {
			bracketDepth++
		} else if rune(c) == RBRACKET {
			bracketDepth--
		}
		if bracketDepth == 0 {
			RestartScan()
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
	case LBRACKET:
		bracketDepth++
		state = Brackets
	case RBRACKET:
		state = NonPhp
	case HASHTAG:
		state = OneLineComment
	case FwdSLASH:
		state = FwdSearch
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


