package main

import (
	"os"
	"bufio"
	"regexp"
	"io/ioutil"
	"bytes"
	"fmt"
	"encoding/gob"
)

var MapCheck = 0

const YAKFILE = "zend_language_parser.y"
const LEXFILE = "zend_language_scanner.l"
const YAKFILEOUT = "zend_language_parser_out.y"
const LEXFILEOUT = "zend_language_scanner_out.l"
var lexFlag = []byte("<ST_IN_SCRIPTING>\"")
var yakFlag = []byte("%token")

const RandStrLen = 12

const (
	YAK = iota
	LEX = iota
)

var polyWords = make(map[string]string)

var b = bytes.Buffer{}

var ValidWord = regexp.MustCompile("\\w").MatchString

var keywordsRegex = regexp.MustCompile(
	"((a(bstract|nd|rray|s))|" +
		"(c(a(llable|se|tch)|l(ass|one)|on(st|tinue)))|" +
		"(d(e(clare|fault)|ie|o))|" +
		"(e(cho|lse(if)?|mpty|nd(declare|for(each)?|if|switch|while)|val|x(it|tends)))|" +
		"(f(inal(ly)|or(each)?|unction))|" +
		"(g(lobal|oto))|" +
		"(i(f|mplements|n(clude(_once)?|st(anceof|eadof)|terface)|sset))|" +
		"(n(amespace|ew))|" +
		"(p(r(i(nt|vate)|otected)|ublic))|" +
		"(re(quire(_once)?|turn))|" +
		"(s(tatic|witch))(![a-z])|" +
		"(t(hrow|r(ait|y)))|(u(nset|se))|" +
		"(__halt_compiler|break|list|(x)?or|var|while))")

func main() {
	scrambleFile(LEX)
	scrambleFile(YAK)
	serializeMap()

	fmt.Println(MapCheck)

}


func scrambleFile(file int) {
	switch file {
	case LEX:
		scanLines(LEXFILE, LEXFILEOUT, lexFlag, LEX)
	case YAK:
		scanLines(YAKFILE, YAKFILEOUT, yakFlag, YAK)
	}
}
func scanLines(fileIn string, fileOut string, flag []byte, state int) {
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
	writeFile(fileOut)
}

func getWords(s []byte, state int) {
	keyWord := keywordsRegex.Find(s)
	index := keywordsRegex.FindIndex(s)
	suffix := string(s[index[1]])
	prefix := string(s[index[0] - 1])



	if ValidWord(suffix) || ValidWord(prefix) {
		writeLineToBuff(s)
		return
	}



	if _, ok := polyWords[string(keyWord)]; !ok  && state != YAK {
		polyWords[string(keyWord)] = RandomStringGen(RandStrLen)
	}


	out := keywordsRegex.ReplaceAll([]byte(s), []byte(polyWords[string(keyWord)]))

	writeLineToBuff(out)
	}


func check(e error) {
	if e != nil {
		panic(e)
	}
}

func writeFile(fileOut string) {
	err := ioutil.WriteFile(fileOut, b.Bytes(), 0644)
	check(err)
}

func writeLineToBuff(s []byte) {
	b.Write([]byte(s))
	b.WriteString("\n")
}

func serializeMap() {
	encodeFile, err := os.Create("../tempDictionary.gob")
	if err != nil {
		panic(err)
	}

	encoder := gob.NewEncoder(encodeFile)

	if err := encoder.Encode(polyWords); err != nil {
		panic(err)
	}
	encodeFile.Close()
}