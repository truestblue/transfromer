package main

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


//TODO: Grab dictionary -- FromFile
//func dictionaryInit() {
//
//}

var lookup = map[string]string{
	"echo": "ocho",
	"do": "od",
	"while": "elihw",
	"hi": "ih",
	"n": "u",
}
