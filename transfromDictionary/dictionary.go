package main

import (
	"os"
	"encoding/gob"
)

var lookup = make(map[string]string)

//TODO process dictionary

func lookUpBuffer() string {
	s := bufTok.String()
	if s == "<nil>" {
		return "<nil>"
	}

	sOut := string([]rune(s)[:(len(s) - 1)])

	if val, ok := lookup[sOut]; ok {
		numReplaced++
		return val
	} else {
		return sOut
	}
}


//Grab dictionary -- FromFile
func initMapping() {
	decodeFile, err := os.Open("../tempDictionary/tempDictionary.gob")
	if err != nil {
		panic(err)
	}
	defer decodeFile.Close()

	decoder := gob.NewDecoder(decodeFile)
	decoder.Decode(&lookup)
}

	//"echo": "ocho",
	//"do": "od",
	//"while": "elihw",
	//"hi": "ih",
	//"n": "u",

