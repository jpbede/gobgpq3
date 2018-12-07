package gobgpq3

import (
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"
	"sync"
)

// GetOriginatedByASN get prefixes originated by a single autnum
func GetOriginatedByASN(autnum string) (string, error) {
	result := whois("!g"+autnum, "whois.radb.net")
	return parse(result)
}

// GetOriginatedByASSet get prefixes originated by a as-set of autnums
func GetOriginatedByASSet(asset string) (string, error) {
	result := whois("!i"+asset+",1", "whois.radb.net")
	parsedResult, _ := parse(result)
	autnums := strings.Split(parsedResult, " ")

	var wg sync.WaitGroup
	var allPrefixes []string

	wg.Add(len(autnums))

	for _, autnum := range autnums {
		go func(autnum string) {
			prefixes, _ := GetOriginatedByASN(autnum)

			if prefixes != "" {
				extPrefixes := strings.Split(prefixes, " ")

				for _, prefix := range extPrefixes {
					allPrefixes = append(allPrefixes, strings.TrimSpace(prefix))
				}
			}

			wg.Done()
		}(autnum)
	}

	wg.Wait()

	return strings.Join(removeDuplicates(allPrefixes), " "), nil
}

func parse(result string) (string, error) {
	lines := strings.Split(result, "\n")

	var dataLength int

	for index, line := range lines {

		if line != "" {

			if index == 0 || index == 2 {
				switch line[:1] {
				case "A":
					dataLength, _ = strconv.Atoi(line[1:])
					break
				case "C":
					break
				case "D":
					break
				case "E":
					break
				case "F":
					break
				}
			} else {
				result = line
			}
		}

	}

	if len(result) > dataLength {
		return "", errors.New("invalid data length")
	}

	return result, nil
}

func whois(query, server string) string {
	conn, err := net.Dial("tcp", server+":43")

	if err != nil {
		fmt.Println("Error")
	}

	defer conn.Close()

	conn.Write([]byte(query + "\r\n"))

	buf := make([]byte, 1024)

	result := []byte{}

	for {
		numBytes, err := conn.Read(buf)
		sbuf := buf[0:numBytes]
		result = append(result, sbuf...)
		if err != nil {
			break
		}
	}

	return string(result)
}

func removeDuplicates(elements []string) []string {
	// Use map to record duplicates as we find them.
	encountered := map[string]bool{}
	result := []string{}

	for v := range elements {
		if encountered[elements[v]] == true {
			// Do not add duplicate.
		} else {
			// Record this element as an encountered element.
			encountered[elements[v]] = true
			// Append to result slice.
			result = append(result, elements[v])
		}
	}
	// Return the new slice.
	return result
}
