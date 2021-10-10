package main

import (
	"log"
	"os"
	"path"
	"testing"
)

func TestJoeSandbox(t *testing.T) {
	home, _ := os.UserHomeDir()
	cfg, err := LoadConfig(path.Join(home, ".mlget.yml"))
	if err != nil {
		log.Fatal()
		t.Errorf("%v", err)
	}

	hash := Hash{HashType: md5, Hash: "28eefc36104bebb595fb38cae21a7d0a"}

	result, _ := JoeSandbox.QueryAndDownload(cfg, hash, false)

	if !result {
		t.Errorf("JoeSandbox failed")
	} else {
		os.Remove(hash.Hash)
	}
}

func TestCapeSandbox(t *testing.T) {
	home, _ := os.UserHomeDir()
	cfg, err := LoadConfig(path.Join(home, ".mlget.yml"))
	if err != nil {
		log.Fatal()
		t.Errorf("%v", err)
	}

	hash := Hash{HashType: md5, Hash: "28eefc36104bebb595fb38cae21a7d0a"}

	result, _ := CapeSandbox.QueryAndDownload(cfg, hash, false)

	if !result {
		t.Errorf("CapeSandbox failed")
	} else {
		os.Remove(hash.Hash)
	}
}

func TestInquestLabs(t *testing.T) {
	home, _ := os.UserHomeDir()
	cfg, err := LoadConfig(path.Join(home, ".mlget.yml"))
	if err != nil {
		log.Fatal()
		t.Errorf("%v", err)
	}

	hash := Hash{HashType: sha256, Hash: "75b2831d387a27b3ecfda6be6ff0523de50ec86e6ac3e7a2ce302690570b7d18"}

	result, _ := InQuest.QueryAndDownload(cfg, hash, false)

	if !result {
		t.Errorf("InquestLabs failed")
	} else {
		os.Remove(hash.Hash)
	}
}

func TestVirusTotal(t *testing.T) {
	home, _ := os.UserHomeDir()
	cfg, err := LoadConfig(path.Join(home, ".mlget.yml"))
	if err != nil {
		log.Fatal()
		t.Errorf("%v", err)
	}

	hash := Hash{HashType: sha256, Hash: "21cc9c0ae5f97b66d69f1ff99a4fed264551edfe0a5ce8d5449942bf8f0aefb2"}

	result, _ := VirusTotal.QueryAndDownload(cfg, hash, false)

	if !result {
		t.Errorf("VirusTotal failed")
	} else {
		os.Remove(hash.Hash)
	}
}

func TestMWDB(t *testing.T) {
	home, _ := os.UserHomeDir()
	cfg, err := LoadConfig(path.Join(home, ".mlget.yml"))
	if err != nil {
		log.Fatal()
		t.Errorf("%v", err)
	}

	hash := Hash{HashType: sha256, Hash: "75b2831d387a27b3ecfda6be6ff0523de50ec86e6ac3e7a2ce302690570b7d18"}

	result, _ := MWDB.QueryAndDownload(cfg, hash, false)

	if !result {
		t.Errorf("MWDB failed")
	} else {
		os.Remove(hash.Hash)
	}
}

func TestPolyswarm(t *testing.T) {
	home, _ := os.UserHomeDir()
	cfg, err := LoadConfig(path.Join(home, ".mlget.yml"))
	if err != nil {
		log.Fatal()
		t.Errorf("%v", err)
	}

	hash := Hash{HashType: sha256, Hash: "75b2831d387a27b3ecfda6be6ff0523de50ec86e6ac3e7a2ce302690570b7d18"}

	result, _ := Polyswarm.QueryAndDownload(cfg, hash, false)

	if !result {
		t.Errorf("PolySwarm failed")
	} else {
		os.Remove(hash.Hash)
	}
}

func TestHybridAnalysis(t *testing.T) {
	home, _ := os.UserHomeDir()
	cfg, err := LoadConfig(path.Join(home, ".mlget.yml"))
	if err != nil {
		log.Fatal()
		t.Errorf("%v", err)
	}

	hash := Hash{HashType: sha256, Hash: "ed2f501408a7a6e1a854c29c4b0bc5648a6aa8612432df829008931b3e34bf56"}

	result, _ := HybridAnalysis.QueryAndDownload(cfg, hash, false)

	if !result {
		t.Errorf("HybridAnalysis failed")
	} else {
		os.Remove(hash.Hash)
	}
}

func TestTriage(t *testing.T) {
	home, _ := os.UserHomeDir()
	cfg, err := LoadConfig(path.Join(home, ".mlget.yml"))
	if err != nil {
		log.Fatal()
		t.Errorf("%v", err)
	}

	hash := Hash{HashType: sha256, Hash: "75b2831d387a27b3ecfda6be6ff0523de50ec86e6ac3e7a2ce302690570b7d18"}

	result, _ := Triage.QueryAndDownload(cfg, hash, false)

	if !result {
		t.Errorf("Triage failed")
	} else {
		os.Remove(hash.Hash)
	}
}

func TestMalShare(t *testing.T) {
	home, _ := os.UserHomeDir()
	cfg, err := LoadConfig(path.Join(home, ".mlget.yml"))
	if err != nil {
		log.Fatal()
		t.Errorf("%v", err)
	}

	hash := Hash{HashType: sha256, Hash: "75b2831d387a27b3ecfda6be6ff0523de50ec86e6ac3e7a2ce302690570b7d18"}

	result, _ := Malshare.QueryAndDownload(cfg, hash, false)

	if !result {
		t.Errorf("Malshare failed")
	} else {
		os.Remove(hash.Hash)
	}
}

func TestMalwareBazaar(t *testing.T) {
	home, _ := os.UserHomeDir()
	cfg, err := LoadConfig(path.Join(home, ".mlget.yml"))
	if err != nil {
		log.Fatal()
		t.Errorf("%v", err)
	}

	hash := Hash{HashType: sha256, Hash: "75b2831d387a27b3ecfda6be6ff0523de50ec86e6ac3e7a2ce302690570b7d18"}

	result, _ := MalwareBazaar.QueryAndDownload(cfg, hash, false)

	if !result {
		t.Errorf("Malshare failed")
	} else {
		os.Remove(hash.Hash)
	}
}
