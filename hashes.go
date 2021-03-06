package main

import (
	"errors"
	"fmt"
	"regexp"
)

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
