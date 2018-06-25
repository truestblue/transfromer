package main

import (
	"os"
	"bufio"
	"strings"
	"regexp"
	"io/ioutil"
	"bytes"
	"fmt"
)

var MapCheck = 0

const YAKFILE = "zend_language_parser.y"
const LEXFILE = "zend_language_scanner.l"
const YAKFILEOUT = "zend_language_parser_out.y"
const LEXFILEOUT = "zend_language_scanner_out.l"
const lexFlag = "<ST_IN_SCRIPTING>\""
const yakFlag = "%token"

const RandStrLen = 12

var polyWords = make(map[string]string)

var b = bytes.Buffer{}

var keywordsRegex = regexp.MustCompile(
	"((a(bstract|nd|rray|s))|(c(a(llable|se|tch)|l(ass|one)|on(st|tinue)))" +
		"|(d(e(clare|fault)|ie|o))|(e(cho|lse(if)?|mpty|nd(declare|for(each)?|if|switch|while)" +
		"|val|x(it|tends)))|(f(inal|or(each)?|unction))|(g(lobal|oto))|(i(f|mplements|n(clude(_once)?" +
		"|st(anceof|eadof)|terface)|sset))|(n(amespace|ew))|(p(r(i(nt|vate)|otected)|ublic))" +
		"|(re(quire(_once)?|turn))|(s(tatic|witch))|(t(hrow|r(ait|y)))|(u(nset|se))|" +
		"(__halt_compiler|break|list|(x)?or|var|while))")

func main() {

	lexFile, err := os.Open(LEXFILE)
	check(err)
	fileScanner := bufio.NewScanner(lexFile)

	for fileScanner.Scan() {
		line := fileScanner.Text()

		if strings.HasPrefix(line, lexFlag) {
			getWords(line)
		} else {
			writeLineToBuff(line)
		}

	}
	writeFile(LEXFILEOUT)
	lexFile.Close()

	yakFile, err := os.Open(YAKFILE)
	check(err)

	fileScanner = bufio.NewScanner(yakFile)
	b.Reset()

	for fileScanner.Scan() {
		line := fileScanner.Text()

		if strings.HasPrefix(line, yakFlag) {
			yakReplace(line)
		} else {
			writeLineToBuff(line)
		}
	}

	writeFile(YAKFILEOUT)

	//serializeMap()
}

func getWords(s string) {

	strs := strings.Split(s, "\"")

	for i := 0; i < len(strs)-1; i++ {
		strCur := strs[i]
		if keywordsRegex.Match([]byte(strCur)) {
			MapCheck++
			randomize := RandomStringGen(RandStrLen)
			polyWords[strCur] = randomize
			strCur = randomize
		}
		b.WriteString(strCur + "\"")
	}
	writeLineToBuff(strs[len(strs)-1])
}

func yakReplace(s string) {

	strs := strings.Split(s, "\"")

	for i := 0; i < len(strs); i++ {
		strCur := strs[i]
		if keywordsRegex.Match([]byte(strCur)) {
			MapCheck--

			fmt.Println(MapCheck)

		}
		b.WriteString(strCur + "\"")
	}
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

func writeLineToBuff(s string) {
	b.Write([]byte(s))
	b.WriteString("\n")
}
