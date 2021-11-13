package main

import (
	"bufio"
	"fmt"
	"io"
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

func parseFileForHashEntries(filename string) ([]Hash, error) {
	hashes := []Hash{}
	file, err := os.Open(filename)
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
	for scanner.Scan() { // internally, it advances token based on sperator
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
			}
		}
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
	fmt.Printf("Hash found: %s\n", hash) // token in unicode-char
	hashS := Hash{Hash: hash, HashType: ht}
	if len(tags) > 0 {
		hashS.Tags = tags
	}
	if len(comments) > 0 {
		hashS.Comments = comments
	}
	return hashS, nil
}
