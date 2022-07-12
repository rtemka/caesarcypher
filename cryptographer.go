package caesarcypher

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
	"log"
	"unicode"
	"unicode/utf8"
)

// in most texts
const mostFrequentChar = ' '

// if we found rune that is not in our alphabet
const skipRune = unicode.ReplacementChar

// cryptoAlphabet returns slice of runes that is our program working with
func cryptoAlphabet() []rune {
	return []rune{'А', 'Б', 'В', 'Г', 'Д', 'Е', 'Ё', 'Ж', 'З', 'И', 'Й', 'К', 'Л', 'М',
		'Н', 'О', 'П', 'Р', 'С', 'Т', 'У', 'Ф', 'Х', 'Ц', 'Ч', 'Ш', 'Щ', 'Ъ', 'Ы', 'Ь', 'Э', 'Ю', 'Я',
		'а', 'б', 'в', 'г', 'д', 'е', 'ё', 'ж', 'з', 'и', 'й', 'к', 'л', 'м',
		'н', 'о', 'п', 'р', 'с', 'т', 'у', 'ф', 'х', 'ц', 'ч', 'ш', 'щ', 'ъ', 'ы', 'ь', 'э', 'ю', 'я',
		':', ',', '"', '?', '-', '—', '.', '!', ' '}
}

// entity holding cypher logic
type cypher struct {
	lookup   map[rune]int
	alphabet []rune
	key      int
	logger   *log.Logger
}

type Encrypter struct {
	c *cypher
	w io.Writer
}

type Decrypter struct {
	c    *cypher
	r    io.Reader
	hr   io.Reader               // helper stream
	decf func(w io.Writer) error // decrypt function
}

// NewCypher returns instance of cypher
func NewCypher(key int, l *log.Logger) (*cypher, error) {

	// get our alphabet
	alphabet := cryptoAlphabet()
	size := len(alphabet)

	if key > size {
		return nil, fmt.Errorf("invalid key: %d. Must be not greater than %d", key, size)
	}

	if key < 0 {
		return nil, fmt.Errorf("invalid key: %d. Can't be less than zero", key)
	}

	lookup := make(map[rune]int, size)

	// maps alphabet char on their indexes
	for i := range alphabet {
		lookup[alphabet[i]] = i
	}

	return &cypher{lookup: lookup, alphabet: alphabet, key: key, logger: l}, nil
}

// NewEncrypter returns instance of Encrypter that writes
// result to w
func (c *cypher) NewEncrypter(w io.Writer) *Encrypter {
	return &Encrypter{c: c, w: w}
}

// NewDecrypter returns instance of Decrypter that
// decrypt contents of r using known key
func (c *cypher) NewDecrypter(r io.Reader) *Decrypter {
	dec := Decrypter{c: c, r: r}
	dec.decf = dec.decrypt
	return &dec
}

// BruteForce switch Decrypter to brute force method
func (dec *Decrypter) BruteForce() *Decrypter {
	dec.decf = dec.bruteForce
	return dec
}

// FrequencyAnalysis switch Decrypter to frequency analysis method
func (dec *Decrypter) FrequencyAnalysis() *Decrypter {
	dec.decf = dec.frequencyAnalysis
	return dec
}

// Helper adds helper reader to Decrypter, it's meant to used
// only when frequency analysis is performed
func (dec *Decrypter) Helper(helper io.Reader) *Decrypter {
	dec.hr = helper
	return dec
}

// Encrypt reads the contents of r, encrypting it
// and writes to the stream
func (enc *Encrypter) Encrypt(r io.Reader) error {

	// encrypting logic
	f := func(char rune) rune {
		// if char is not in our alphabet
		// then encrypt it as skipRune
		pos, ok := enc.c.lookup[char]
		if !ok {
			return skipRune
		}

		// calculate the position after shift
		pos += enc.c.key
		if pos > len(enc.c.alphabet)-1 {
			pos = pos - len(enc.c.alphabet)
		}

		// encrypt it as shifted rune
		return enc.c.alphabet[pos]
	}

	// pass our logic to processor
	return process(r, enc.w, f)
}

// decrypt reads the inner r and decrypt it contents to w
func (dec *Decrypter) Decrypt(w io.Writer) error {
	return dec.decf(w)
}

// decrypt reads inner r and decrypt it contents to w
// using known key
func (dec *Decrypter) decrypt(w io.Writer) error {

	f := func(char rune) rune {
		pos, ok := dec.c.lookup[char]
		if !ok {
			return skipRune
		}

		// backward shift
		pos -= dec.c.key
		if pos < 0 {
			pos = len(dec.c.alphabet) + pos
		}

		return dec.c.alphabet[pos]
	}

	// pass our logic to processor
	return process(dec.r, w, f)
}

// bruteForce reads inner r and tries to decrypt it contents to w
// sequentially selecting the keys
func (dec *Decrypter) bruteForce(w io.Writer) error {

	b, err := io.ReadAll(dec.r)
	if err != nil {
		return err
	}
	match := false

	dec.c.logger.Printf("Brute-forcing ...\n")

	for ; dec.c.key < len(dec.c.alphabet); dec.c.key++ {

		// we run the text through a function that looks for patterns
		// function returns statistics over the text
		stat := dec.c.findCommonPatterns(b)

		// if text statistic exceeds the threshold
		// then the key is found
		pass := stat*100/len(b) >= 1

		info := statInfo(stat, len(b)/100, pass)
		dec.c.logger.Printf("trying possible key %3d -> %s\n", dec.c.key, info)

		if pass {
			match = true
			break
		}
	}

	if !match {
		dec.c.logger.Printf("Result: fail to brute-forcing\n")
		return nil
	}
	dec.c.logger.Printf("Result: success. Decrypting...\n")

	dec.r = bytes.NewReader(b)

	return dec.decrypt(w)
}

// frequencyAnalysis reads r and tries to decrypt it contents to w
// using the frequency analysis method
func (dec *Decrypter) frequencyAnalysis(w io.Writer) error {

	dec.c.logger.Printf("Decrypting by frequency analysis...\n")

	var mfrDecrypted = mostFrequentChar

	if dec.hr != nil {
		// read the helper
		b, err := io.ReadAll(dec.hr)
		if err != nil {
			return err
		}

		// find most frequent rune
		mfrDecrypted, err = dec.c.countMostFrequent(b)
		if err != nil {
			return err
		}
	}

	// read the encrypted
	b, err := io.ReadAll(dec.r)
	if err != nil {
		return err
	}

	// find most frequent rune
	mfrEncrypted, err := dec.c.countMostFrequent(b)
	if err != nil {
		return err
	}

	// get positions in alphabet
	posDec, posEnc := dec.c.lookup[mfrDecrypted], dec.c.lookup[mfrEncrypted]

	// calculate key
	if posDec <= posEnc {
		dec.c.key = posEnc - posDec
	} else {
		dec.c.key = len(dec.c.alphabet) + posEnc - posDec
	}

	/// we run the text through a function that looks for patterns
	// function returns statistics over the text
	stat := dec.c.findCommonPatterns(b)

	// if text statistic exceeds the threshold
	// then the key is found
	pass := stat*100/len(b) >= 1
	info := statInfo(stat, len(b)/100, pass)
	dec.c.logger.Printf("trying possible key %3d -> %s\n", dec.c.key, info)

	// if key is not found we try most frequent rune overall
	if !pass {
		dec.c.logger.Println("Avoiding helper, trying statistically most frequent character which is space")

		posDec, posEnc := dec.c.lookup[mostFrequentChar], dec.c.lookup[mfrEncrypted]

		if posDec <= posEnc {
			dec.c.key = posEnc - posDec
		} else {
			dec.c.key = len(dec.c.alphabet) + posEnc - posDec
		}

		stat := dec.c.findCommonPatterns(b)
		pass := stat*100/len(b) >= 1
		info := statInfo(stat, len(b)/100, pass)
		dec.c.logger.Printf("trying possible key %3d -> %s\n", dec.c.key, info)

		if !pass {
			return nil
		}
	}

	dec.c.logger.Printf("Result: success. Decrypting...\n")

	dec.r = bytes.NewReader(b)

	return dec.decrypt(w)
}

// countMostFrequent returns most frequent rune
// in provided text
func (c *cypher) countMostFrequent(b []byte) (rune, error) {

	fm := make(map[rune]int, len(c.alphabet))
	var mostFrequentChar rune

	for r, size, bs := skipRune, 0, b[:]; len(bs) > 0; bs = bs[size:] {

		r, size = utf8.DecodeRune(bs)

		if _, ok := c.lookup[r]; !ok {
			continue
		}

		fm[r]++
		i := fm[r]

		if i > fm[mostFrequentChar] {
			mostFrequentChar = r
		}
	}

	return mostFrequentChar, nil
}

// findCommonPatterns returns the statistics over the
// provided text (i.e how many times the pattern emerges in text)
func (c *cypher) findCommonPatterns(b []byte) int {
	stat := 0
	foundMode := 1
	// foundMode 1 == found [letter]
	// foundMode 2 == found [letter] -> [punctuation]
	// foundMode 3 ==  found [letter] -> [punctuation] -> [space]
	// foundMode 4 ==  success

runes:
	for r, size, bs := skipRune, 0, b[:]; len(bs) > 0; bs = bs[size:] {

		r, size = utf8.DecodeRune(bs)

		pos, ok := c.lookup[r]
		if !ok {
			continue
		}

		pos -= c.key
		if pos < 0 {
			pos = len(c.alphabet) + pos
		}

		char := c.alphabet[pos]

		switch char {
		case '-', '—':
			if foundMode == 2 {
				break runes
			}
		case ' ':
			if foundMode == 2 {
				foundMode++
			}
		case '.', ',', '!', '?', ':':
			if foundMode != 1 {
				break runes
			}
			foundMode++
		default:
			if foundMode == 3 {
				stat++
			}
			foundMode = 1
		}
	}
	return stat
}

func statInfo(stat, expected int, result bool) string {
	msg := fmt.Sprintf("found pattern matches %4d; expected threshold %4d", stat, expected)
	if result {
		return msg + " -> Result: -> success"
	} else {
		return msg + " -> Result: -> fail"
	}
}

// process reads runes from the source r and writes to
// the destination w, passing the data through
// the encryption/decryption function, which it receives as the third parameter
func process(r io.Reader, w io.Writer, f func(rune) rune) error {

	rw := bufio.NewReadWriter(
		bufio.NewReader(r),
		bufio.NewWriter(w),
	)

	for {
		char, _, err := rw.ReadRune()
		if err == io.EOF {
			break
		}
		if err != nil {
			return err
		}

		out := f(char)

		_, err = rw.WriteRune(out)
		if err != nil {
			return err
		}

	}

	rw.Flush()

	return nil
}
