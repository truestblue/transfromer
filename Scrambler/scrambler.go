package main

//TODO: CLEAN UP, REFACTOR

//TODO: Automate test

//TODO: Put in polyscript folder/docker

import (
	"os"
	"bufio"
	"bytes"
	"fmt"
)

func main() {

	scrambleFile(LEX)
	fmt.Println("Mapping Built. \n Lex Scrambled.")
	b.Reset()
	scrambleFile(YAK)
	fmt.Println("Yak Scrambled.")
	serializeMap()
	fmt.Println("Map Serialized")

}

func scrambleFile(file int) {
	switch file {
	case LEX:
		scanLines(LEXFILE, lexFlag, LEX)
	case YAK:
		scanLines(YAKFILE, yakFlag, YAK)
	}
}

func scanLines(fileIn string, flag []byte, state int) {
	file, err := os.Open(fileIn)
	check(err)
	defer file.Close()

	fileScanner := bufio.NewScanner(file)

	for fileScanner.Scan() {
		line := fileScanner.Bytes()

		if bytes.HasPrefix(line, flag) && keywordsRegex.Match(line) {
			getWords(line, state)
		} else {
			writeLineToBuff(line)
		}
	}
	writeFile(fileIn)
}

func getWords(s []byte, state int) {
	keyWord := keywordsRegex.Find(s)
	index := keywordsRegex.FindIndex(s)
	suffix := string(s[index[1]])
	prefix := string(s[index[0]-1])

	if ValidWord(suffix) || ValidWord(prefix) { //word found was part of larger word, return
		writeLineToBuff(s)
		return
	}

	if _, ok := polyWords[string(keyWord)]; !ok && state != YAK {
		polyWords[string(keyWord)] = RandomStringGen() // Add to map, generate random string (need checks here?)
	}

	out := keywordsRegex.ReplaceAll([]byte(s), []byte(polyWords[string(keyWord)])) //Replace word with random string
	writeLineToBuff(out)
}