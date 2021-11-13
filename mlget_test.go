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

	var osq ObjectiveSeeQuery
	result, _ := JoeSandbox.QueryAndDownload(cfg, hash, false, osq)

	if !result {
		t.Errorf("JoeSandbox failed")
	} else {
		os.Remove(hash.Hash)
	}
}

func TestObjectiveSee(t *testing.T) {
	home, _ := os.UserHomeDir()
	cfg, err := LoadConfig(path.Join(home, ".mlget.yml"))
	if err != nil {
		log.Fatal()
		t.Errorf("%v", err)
	}

	hash := Hash{HashType: sha256, Hash: "458a9ac086116fa011c1a7bd49ac15f386cd95e39eb6b7cd5c5125aef516c78c"}

	osq, _ := loadObjectiveSeeJson(getConfigsByType(ObjectiveSee, cfg)[0].Host)
	result, _ := ObjectiveSee.QueryAndDownload(cfg, hash, true, osq)

	if !result {
		t.Errorf("Objective-See failed")
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

	var osq ObjectiveSeeQuery
	hash := Hash{HashType: md5, Hash: "28eefc36104bebb595fb38cae21a7d0a"}

	result, _ := CapeSandbox.QueryAndDownload(cfg, hash, false, osq)

	if !result {
		t.Errorf("CapeSandbox failed")
	} else {
		os.Remove(hash.Hash)
	}
}

func TestInquestLabsLookUp(t *testing.T) {
	home, _ := os.UserHomeDir()
	cfg, err := LoadConfig(path.Join(home, ".mlget.yml"))
	if err != nil {
		log.Fatal()
		t.Errorf("%v", err)
	}

	hash := Hash{HashType: md5, Hash: "b3f868fa1af24f270e3ecc0ecb79325e"}

	var osq ObjectiveSeeQuery
	result, _ := InQuest.QueryAndDownload(cfg, hash, false, osq)

	if !result {
		t.Errorf("InquestLabs failed")
	} else {
		os.Remove(hash.Hash)
	}
}

func TestInquestLabsNoLookUp(t *testing.T) {
	home, _ := os.UserHomeDir()
	cfg, err := LoadConfig(path.Join(home, ".mlget.yml"))
	if err != nil {
		log.Fatal()
		t.Errorf("%v", err)
	}

	hash := Hash{HashType: sha256, Hash: "6b425804d43bb369211bbec59808807730a908804ca9b8c09081139179bbc868"}

	var osq ObjectiveSeeQuery
	result, _ := InQuest.QueryAndDownload(cfg, hash, false, osq)

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

	var osq ObjectiveSeeQuery
	result, _ := VirusTotal.QueryAndDownload(cfg, hash, false, osq)

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

	var osq ObjectiveSeeQuery
	result, _ := MWDB.QueryAndDownload(cfg, hash, false, osq)

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

	var osq ObjectiveSeeQuery
	result, _ := Polyswarm.QueryAndDownload(cfg, hash, false, osq)

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

	var osq ObjectiveSeeQuery
	result, _ := HybridAnalysis.QueryAndDownload(cfg, hash, false, osq)

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

	var osq ObjectiveSeeQuery
	result, _ := Triage.QueryAndDownload(cfg, hash, false, osq)

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

	var osq ObjectiveSeeQuery
	result, _ := Malshare.QueryAndDownload(cfg, hash, false, osq)

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

	//hash := Hash{HashType: sha256, Hash: "75b2831d387a27b3ecfda6be6ff0523de50ec86e6ac3e7a2ce302690570b7d18"}
	hash := Hash{HashType: sha256, Hash: "bbe855f9259345af18de5f2cfd759eb78782b664bb22c43f19177dab51d782da"}

	var osq ObjectiveSeeQuery
	result, _ := MalwareBazaar.QueryAndDownload(cfg, hash, false, osq)

	if !result {
		t.Errorf("Malshare failed")
	} else {
		os.Remove(hash.Hash)
	}
}

func TestMalpedia(t *testing.T) {
	home, _ := os.UserHomeDir()
	cfg, err := LoadConfig(path.Join(home, ".mlget.yml"))
	if err != nil {
		log.Fatal()
		t.Errorf("%v", err)
	}

	hash := Hash{HashType: sha256, Hash: "78668c237097651d64c97b25fc86c74096bfe1ed53e1004445f118ea5feaa3ad"}

	var osq ObjectiveSeeQuery
	result, _ := Malpedia.QueryAndDownload(cfg, hash, false, osq)

	if !result {
		t.Errorf("Malpedia failed")
	} else {
		os.Remove(hash.Hash)
	}
}

func TestUnpacme(t *testing.T) {
	home, _ := os.UserHomeDir()
	cfg, err := LoadConfig(path.Join(home, ".mlget.yml"))
	if err != nil {
		log.Fatal()
		t.Errorf("%v", err)
	}

	hash := Hash{HashType: sha256, Hash: "c8c69f36f89061f4ce86b108c0ff12ade49d665eace2d60ba179a2341bd54c40"}

	var osq ObjectiveSeeQuery
	result, _ := UnpacMe.QueryAndDownload(cfg, hash, false, osq)

	if !result {
		t.Errorf("Unpacme failed")
	} else {
		os.Remove(hash.Hash)
	}
}

func TestVxShare(t *testing.T) {
	home, _ := os.UserHomeDir()
	cfg, err := LoadConfig(path.Join(home, ".mlget.yml"))
	if err != nil {
		log.Fatal()
		t.Errorf("%v", err)
	}

	hash := Hash{HashType: sha256, Hash: "1c11c963a417674e1414bac05fdbfa5cfa09f92c7b0d9882aeb55ce2a058d668"}

	var osq ObjectiveSeeQuery
	result, _ := VxShare.QueryAndDownload(cfg, hash, false, osq)

	if !result {
		t.Errorf("VxShare failed")
	} else {
		os.Remove(hash.Hash)
	}
}

func TestFileScanIo(t *testing.T) {
	home, _ := os.UserHomeDir()
	cfg, err := LoadConfig(path.Join(home, ".mlget.yml"))
	if err != nil {
		log.Fatal()
		t.Errorf("%v", err)
	}

	hash := Hash{HashType: sha256, Hash: "2799af2efd698da215afc9c88da3b1e84b00137433d9444a5c11d69092b3f80d"}

	var osq ObjectiveSeeQuery
	result, _ := FileScanIo.QueryAndDownload(cfg, hash, false, osq)

	if !result {
		t.Errorf("FileScanIo failed")
	} else {
		os.Remove(hash.Hash)
	}
}
