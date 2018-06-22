package main

import (
	"fmt"
	"bytes"
	"log"
	"io"
	"regexp"
	"io/ioutil"
	"os"
)


var lookup = map[string]string{
	"yuyuyuyu": "yyy",
}

var ValidWord = regexp.MustCompile("\\w").MatchString

const (
	UserDef  = iota
	Quoted   = iota
	//Brackets = iota
	Scan     = iota
)

const D_QUOTE = rune('"')
const END = rune(')')

const VARIABLE = rune('$')
const BACKSLASH = rune('\\')

func initReader() io.RuneReader {
	original, err := ioutil.ReadFile("/Users/bluegaston/Desktop/Polyverse/polyscripted-php/tests/php-tests.php")

	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}

	return bytes.NewReader(original)
}

var bufTok = bytes.Buffer{}
var bufOut = bytes.Buffer{}
var state = Scan

func main() {
	var Escaped = false
	r := initReader()
	numReplaced := 0
	//i := 0

	for {
		//i++
		//fmt.Printf("buff: %s [%d] \n", bufOut.String(), i)
		c, _, err := r.ReadRune()
		if err != nil {
			if err == io.EOF {
				break
			} else {
				log.Fatal(err)
			}
		}

		bufTok.WriteRune(c)
		if !Escaped {
			switch state {
			case UserDef:
				//print until end of variable
				if !ValidWord(string(c)) {
					RestartScan()
				}
			case Quoted:
				if c == D_QUOTE {
					RestartScan()
				}
				//print until end quote
			case Scan:
				if !ValidWord(string(c)) {
					if lookUpBuffer(c) {
						numReplaced++
					}
					bufTok.Reset()
					Escaped = checkRune(c)
				}

			}
		} else {
			Escaped = false
		}

	}
	fmt.Printf("%s \n replaced: %d", bufOut.String(), numReplaced)


}

func RestartScan() {
	state = Scan
	bufOut.Write(bufTok.Bytes())
	bufTok.Reset()
}

func checkRune(c rune) bool {
	switch c {
	case D_QUOTE:
		state = Quoted
	case VARIABLE:
		state = UserDef
	case BACKSLASH:
		return true
	}
	return false
}

func lookUpBuffer(c rune) bool {

	s := bufTok.String()
	if s == "<nil>" {
		return false
	}
	x:=len(s) - 1
	subs := string([]rune(s)[:x])
	//fmt.Printf("STRING IN LOOKUP: %s, to %s\n", s, subs)
	if val, ok := lookup[subs]; ok {
		bufOut.WriteString(val)
		bufOut.WriteRune(c)
		return true
	} else {
		bufOut.WriteString(s)
		return false
	}
}
