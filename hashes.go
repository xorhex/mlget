package main

import (
	"crypto"
	"errors"
	"fmt"
	"io"
	"log"
	"os"
	"regexp"
	"strings"
)

var alwaysDeleteInvalidFile = false

type Hashes struct {
	Hashes []Hash
}

type Hash struct {
	Hash     string
	HashType HashTypeOption
	Tags     []string
	Comments []string
}

type HashTypeOption int64

const (
	NotAValidHashType HashTypeOption = iota
	md5
	sha1
	sha256
)

func (hto HashTypeOption) String() string {
	switch hto {
	case md5:
		return "md5"
	case sha1:
		return "sha1"
	case sha256:
		return "sha256"
	}
	return ""
}

func addHash(hashes Hashes, hash Hash) (Hashes, error) {
	if hashes.hashExists(hash.Hash) {
		hsh, err := hashes.getByHash(hash.Hash)
		if err != nil {
			return hashes, err
		}
		for _, t := range hash.Tags {
			if !hsh.TagExists(t) {
				hsh.Tags = append(hsh.Tags, t)
			}
		}

	} else {
		hashes.Hashes = append(hashes.Hashes, hash)
	}
	return hashes, nil
}

func (hs Hashes) hashExists(hash string) bool {
	for _, h := range hs.Hashes {
		if h.Hash == hash {
			return true
		}
	}
	return false
}

func (hs Hashes) getByHash(hash string) (Hash, error) {
	for _, h := range hs.Hashes {
		if h.Hash == hash {
			return h, nil
		}
	}
	return Hash{}, fmt.Errorf("Hash not found")
}

func (h Hash) TagExists(tag string) bool {
	for _, t := range h.Tags {
		if t == tag {
			return true
		}
	}
	return false
}

func (h Hash) ValidateFile(filename string) (bool, string) {
	f, err := os.Open(filename)
	if err != nil {
		log.Fatal(err)
	}
	defer f.Close()

	var sum []byte

	if h.HashType == md5 {
		hasher := crypto.MD5.New()
		if _, err := io.Copy(hasher, f); err != nil {
			log.Fatal(err)
		}
		sum = hasher.Sum(nil)
	} else if h.HashType == sha1 {
		hasher := crypto.SHA1.New()
		if _, err := io.Copy(hasher, f); err != nil {
			log.Fatal(err)
		}
		sum = hasher.Sum(nil)
	} else if h.HashType == sha256 {
		hasher := crypto.SHA256.New()
		if _, err := io.Copy(hasher, f); err != nil {
			log.Fatal(err)
		}
		sum = hasher.Sum(nil)
	}
	if (fmt.Sprintf("%x", sum)) == strings.ToLower(h.Hash) {
		return true, fmt.Sprintf("%x", sum)
	} else {
		return false, fmt.Sprintf("%x", sum)
	}
}

func (h Hash) Validate(bytes []byte) (bool, string) {
	var sum []byte

	if h.HashType == md5 {
		hasher := crypto.MD5.New()
		hasher.Write(bytes)
		sum = hasher.Sum(nil)
	} else if h.HashType == sha1 {
		hasher := crypto.SHA1.New()
		hasher.Write(bytes)
		sum = hasher.Sum(nil)
	} else if h.HashType == sha256 {
		hasher := crypto.SHA256.New()
		hasher.Write(bytes)
		sum = hasher.Sum(nil)
	}
	if (fmt.Sprintf("%x", sum)) == strings.ToLower(h.Hash) {
		return true, fmt.Sprintf("%x", sum)
	} else {
		return false, fmt.Sprintf("%x", sum)
	}
}

func deleteInvalidFile(filename string) {
	if !alwaysDeleteInvalidFile {
		var delete_file string
		fmt.Printf("    [?] Delete invalid file? [A/Y/n] Always delete/Yes, this time/No, not this time\n")
		fmt.Scanln(&delete_file)
		if strings.ToUpper(delete_file) == "Y" || delete_file == "" || strings.ToUpper(delete_file) == "A" {
			os.Remove(filename)
			fmt.Printf("    [!] Deleted invalid file\n")
			if strings.ToUpper(delete_file) == "A" {
				alwaysDeleteInvalidFile = true
			}
		} else {
			fmt.Printf("    [!] Keeping invalid file\n")
		}
	} else {
		os.Remove(filename)
		fmt.Printf("    [!] Deleted invalid file\n")
	}
}

func hashType(hash string) (HashTypeOption, error) {
	match, _ := regexp.MatchString("^[A-Fa-f0-9]{64}$", hash)
	if match {
		return sha256, nil
	}
	match, _ = regexp.MatchString("^[A-Fa-f0-9]{40}$", hash)
	if match {
		return sha1, nil
	}
	match, _ = regexp.MatchString("^[A-Fa-f0-9]{32}$", hash)
	if match {
		return md5, nil
	}
	return NotAValidHashType, errors.New("not a valid hash")
}

func extractHashes(text string) ([]string, error) {
	hashes := make([]string, 0)

	re := regexp.MustCompile(`>\s*[A-Fa-f0-9]{64}\s*<`)
	matches := re.FindAllStringSubmatch(text, 100)
	for m := range matches {
		hashes = append(hashes, strings.TrimSpace(matches[m][0][1:len(matches[m][0])-1]))
	}
	re = regexp.MustCompile(`>\s*[A-Fa-f0-9]{40}\s*<`)
	matches = re.FindAllStringSubmatch(text, 100)
	for m := range matches {
		hashes = append(hashes, strings.TrimSpace(matches[m][0][1:len(matches[m][0])-1]))
	}
	re = regexp.MustCompile(`>\s*[A-Fa-f0-9]{32}\s*<`)
	matches = re.FindAllStringSubmatch(text, 100)
	for m := range matches {
		hashes = append(hashes, strings.TrimSpace(matches[m][0][1:len(matches[m][0])-1]))
	}

	if len(hashes) > 0 {
		return hashes, fmt.Errorf("no hashes found")
	}

	return hashes, nil
}
