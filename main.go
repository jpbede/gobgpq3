package gobgpq3

import (
	"errors"
	"github.com/ivpusic/grpool"
	"net"
	"regexp"
	"runtime"
	"strconv"
	"strings"
)

var whoisServer = "whois.radb.net"
var workerCount = 1000

// SetWhoisServer set's a other whois to be used instead of whois.radb.net
func SetWhoisServer(server string) {
	whoisServer = server
}

// GetOriginated4ByASN get ipv4 prefixes originated by a single autnum
func GetOriginated4ByASN(autnum string) ([]string, error) {
	if !isValidAutNum(autnum) {
		return nil, errors.New("invalid AutNum")
	}
	result, err := whois("!g"+autnum, whoisServer)
	if err != nil {
		return nil, err
	}
	return parse(result)
}

// GetOriginated6ByASN get ipv6 prefixes originated by a single autnum
func GetOriginated6ByASN(autnum string) ([]string, error) {
	if !isValidAutNum(autnum) {
		return nil, errors.New("invalid AutNum")
	}
	result, err := whois("!6"+autnum, whoisServer)
	if err != nil {
		return nil, err
	}
	return parse(result)
}

// GetOriginatedByASSet get prefixes originated by a as-set of autnums
func GetOriginatedByASSet(asset string) ([]string, error) {
	result, err := whois("!i"+asset+",1", whoisServer)
	if err != nil {
		return nil, err
	}
	autnums, _ := parse(result)

	numCPUs := runtime.NumCPU()
	runtime.GOMAXPROCS(numCPUs)

	pool := grpool.NewPool(workerCount, len(autnums))
	defer pool.Release()

	pool.WaitCount(len(autnums))

	var allPrefixes []string

	for _, asn := range autnums {

		autnum := asn // reassign for grpool

		pool.JobQueue <- func() {
			defer pool.JobDone()

			prefixes4, _ := GetOriginated4ByASN(autnum)
			prefixes6, _ := GetOriginated6ByASN(autnum)

			var mergedPrefixes []string

			if len(prefixes4) > 0 || len(prefixes6) > 0 {
				mergedPrefixes = append(mergedPrefixes, prefixes4...)
				mergedPrefixes = append(mergedPrefixes, prefixes6...)

				for _, prefix := range mergedPrefixes {
					allPrefixes = append(allPrefixes, strings.TrimSpace(prefix))
				}
			}
		}
	}

	pool.WaitAll()

	return removeDuplicates(allPrefixes), nil
}

func isValidAutNum(autnum string) bool {
	var validAutNum = regexp.MustCompile("^AS.")
	return validAutNum.MatchString(autnum)
}

func parse(result string) ([]string, error) {
	lines := strings.Split(result, "\n")

	var dataLength int
	var parsedResult []string

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
		return parsedResult, errors.New("invalid data length")
	}

	parsedResult = strings.Split(result, " ")
	return parsedResult, nil
}

func whois(query, server string) (string, error) {
	conn, err := net.Dial("tcp", server+":43")

	if err != nil {
		return "", err
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

	return string(result), nil
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
