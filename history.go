package main

import (
	"bufio"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"strings"
)

func writeToFile(file io.ReadCloser, filename string) error {
	// Create the file
	out, err := os.Create(filename)
	if err != nil {
		return err
	}
	defer out.Close()

	// Write the body to file
	_, err = io.Copy(out, file)
	return err
}

// Code for this function came from - https://golangcode.com/how-to-check-if-a-string-is-a-url/
// isValidUrl tests a string to determine if it is a well-structured url or not.
func isValidUrl(toTest string) bool {
	_, err := url.ParseRequestURI(toTest)
	if err != nil {
		return false
	}

	u, err := url.Parse(toTest)
	if err != nil || u.Scheme == "" || u.Host == "" {
		return false
	}

	return true
}

// https://golangcode.com/check-if-a-file-exists/
func fileExists(filename string) bool {
	info, err := os.Stat(filename)
	if os.IsNotExist(err) {
		return false
	}
	return !info.IsDir()
}

func downloadFromUrl(url string) (string, error) {

	filename := "mlget.download.data.tmp"

	r, err := http.Get(url)
	if err != nil {
		log.Println("Cannot get from URL", err)
		return "", err
	}

	defer r.Body.Close()

	if !fileExists(filename) {

		file, _ := os.Create(filename)
		defer file.Close()

		writer := bufio.NewWriter(file)
		io.Copy(writer, r.Body)
		writer.Flush()

		return filename, nil

	} else {
		return "", fmt.Errorf("file %s already exists - delete and try again", filename)
	}
}

func parseFileForHashEntries(filename string) ([]Hash, error) {
	hashes := []Hash{}
	var _filename string
	var err error

	if isValidUrl(filename) {
		_filename, err = downloadFromUrl(filename)
		if err != nil {
			return nil, err
		}
	} else {
		_filename = filename
	}

	file, err := os.Open(_filename)
	if err != nil {
		fmt.Println("Error reading file")
		fmt.Println(err)
	}

	defer func() ([]string, error) {
		if err = file.Close(); err != nil {
			fmt.Println(err)
			return nil, err
		}
		return nil, nil
	}()

	f := func(c rune) bool {
		return c == '|'
	}

	scanner := bufio.NewScanner(file)
	for scanner.Scan() { // internally, it advances token based on separator
		text := scanner.Text()
		if len(strings.TrimSpace(text)) > 0 {
			hash := strings.FieldsFunc(strings.TrimSpace(text), f)[0]
			tags := []string{}
			comments := []string{}
			if len(strings.FieldsFunc(text, f)) > 1 {
				fields := strings.FieldsFunc(text, f)[1:len(strings.FieldsFunc(text, f))]
				tagSection := false
				commentSection := false
				for _, f := range fields {
					if f == "TAGS" {
						tagSection = true
						commentSection = false
					} else if f == "COMMENTS" {
						tagSection = false
						commentSection = true
					} else if f != "TAGS" && f != "COMMENTS" && tagSection {
						tags = append(tags, f)
					} else if f != "TAGS" && f != "COMMENTS" && commentSection {
						comments = append(comments, f)
					}
				}
			}
			pHash := Hash{}
			pHash, err = parseFileHashEntry(hash, tags, comments)
			if err == nil {
				hashes = append(hashes, pHash)
			} else {
				// Try splitting on \t and check to see if any of the values match a hash
				// This is useful for reading files from the web that list sample hashes
				// This still assumes there is only one hash per line as it stops after the
				// first hash is found on that line
				s := func(c rune) bool {
					return c == '\t'
				}

				line := strings.FieldsFunc(strings.TrimSpace(text), s)
				if len(line) > 0 {
					for _, element := range line {
						lHash := Hash{}
						lHash, err := parseFileHashEntry(strings.TrimSpace(element), tags, comments)
						if err == nil {
							hashes = append(hashes, lHash)
							break
						} else {

							matches, err := extractHashes(strings.TrimSpace(element))
							if err != nil {
								fmt.Println(err)
							}
							for m := range matches {
								tags := []string{}
								comments := []string{}
								lHash, err = parseFileHashEntry(matches[m], tags, comments)
								if err == nil {
									hashes = append(hashes, lHash)
								}
							}
						}
					}
				}
			}
		}
	}

	if _filename == "mlget.download.data.tmp" {
		os.Remove(_filename)
	}

	return hashes, nil
}

func writeUnfoundHashesToFile(filename string, hashes Hashes) error {
	f, err := os.Create(filename)
	if err != nil {
		return err
	}
	defer f.Close()

	w := bufio.NewWriter(f)
	defer w.Flush()

	for _, h := range hashes.Hashes {
		w.WriteString(h.Hash + "|TAGS|" + strings.Join(h.Tags, "|") + "|COMMENTS|" + strings.Join(h.Comments, "|") + "\n")
	}
	return nil
}

func parseFileHashEntry(hash string, tags []string, comments []string) (Hash, error) {
	ht, err := hashType(hash)
	if err != nil {
		fmt.Printf("\n Skipping %s because it's %s\n", hash, err)
		return Hash{}, err
	}
	fmt.Printf("\nHash found: %s\n", hash) // token in unicode-char
	hashS := Hash{Hash: hash, HashType: ht}
	if len(tags) > 0 {
		hashS.Tags = tags
	}
	if len(comments) > 0 {
		hashS.Comments = comments
	}
	return hashS, nil
}
