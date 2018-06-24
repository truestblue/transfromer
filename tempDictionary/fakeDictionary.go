package main

import (
	"os"
	"encoding/gob"
)

func main() {

	var lookup = map[string]string{
		"echo": "ocho",
		"do": "od",
		"while": "elihw",
		"hi": "ih",
		"n": "u",
	}

	// Create a file for IO
	encodeFile, err := os.Create("tempDictionary.gob")
	if err != nil {
		panic(err)
	}

	// Since this is a binary format large parts of it will be unreadable
	encoder := gob.NewEncoder(encodeFile)

	// Write to the file
	if err := encoder.Encode(lookup); err != nil {
		panic(err)
	}
	encodeFile.Close()


}