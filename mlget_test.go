package main

import (
	"errors"
	"fmt"
	"log"
	"os"
	"path"
	"testing"

	"gopkg.in/yaml.v2"
)

type TestConfigEntry struct {
	Name string `yaml:"name"`
	Hash string `yaml:"hash"`
}

func parseTestConfig(path string, testName string) (TestConfigEntry, error) {
	var tce TestConfigEntry

	_, err := os.Stat(path)
	if os.IsNotExist(err) {
		return tce, err
	}

	f, err := os.ReadFile(path)
	if err != nil {
		fmt.Printf("%v", err)
		return tce, err
	}

	data := make(map[string]TestConfigEntry)

	err = yaml.Unmarshal(f, &data)
	if err != nil {
		fmt.Printf("%v", err)
		return tce, err
	}

	var filteredTestConfig []TestConfigEntry
	for _, v := range data {
		if v.Name == testName {
			filteredTestConfig = append(filteredTestConfig, v)
		}
	}

	if len(filteredTestConfig) != 1 {
		return tce, errors.New("No test config entry found")
	}
	return filteredTestConfig[0], nil
}

func TestJoeSandbox(t *testing.T) {
	home, _ := os.UserHomeDir()
	cfg, err := LoadConfig(path.Join(home, ".mlget.yml"))
	if err != nil {
		log.Fatal()
		t.Errorf("%v", err)
	}

	scfg, err := parseTestConfig("./mlget-test-config/samples.yaml", t.Name())
	if err != nil {
		log.Fatal()
		t.Errorf("%v", err)
	}

	ht, _ := hashType(scfg.Hash)
	hash := Hash{HashType: ht, Hash: scfg.Hash}

	var osq ObjectiveSeeQuery
	result, filename, _ := JoeSandbox.QueryAndDownload(cfg, hash, false, osq)

	if !result {
		t.Errorf("JoeSandbox failed")
	} else {
		valid, errmsg := hash.ValidateFile(filename)

		if !valid {
			os.Remove(hash.Hash)
			t.Errorf(errmsg)
		} else {
			os.Remove(hash.Hash)
		}
	}
}

func TestObjectiveSee(t *testing.T) {
	home, _ := os.UserHomeDir()
	cfg, err := LoadConfig(path.Join(home, ".mlget.yml"))
	if err != nil {
		log.Fatal()
		t.Errorf("%v", err)
	}

	scfg, err := parseTestConfig("./mlget-test-config/samples.yaml", t.Name())
	if err != nil {
		log.Fatal()
		t.Errorf("%v", err)
	}

	ht, _ := hashType(scfg.Hash)
	hash := Hash{HashType: ht, Hash: scfg.Hash}

	osq, _ := loadObjectiveSeeJson(getConfigsByType(ObjectiveSee, cfg)[0].Host)
	result, _, _ := ObjectiveSee.QueryAndDownload(cfg, hash, true, osq)

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

	scfg, err := parseTestConfig("./mlget-test-config/samples.yaml", t.Name())
	if err != nil {
		log.Fatal()
		t.Errorf("%v", err)
	}

	ht, _ := hashType(scfg.Hash)
	hash := Hash{HashType: ht, Hash: scfg.Hash}

	var osq ObjectiveSeeQuery
	result, filename, _ := CapeSandbox.QueryAndDownload(cfg, hash, false, osq)

	if !result {
		t.Errorf("CapeSandbox failed")
	} else {
		valid, errmsg := hash.ValidateFile(filename)

		if !valid {
			os.Remove(hash.Hash)
			t.Errorf(errmsg)
		} else {
			os.Remove(hash.Hash)
		}
	}
}

func TestInquestLabsLookUp(t *testing.T) {
	home, _ := os.UserHomeDir()
	cfg, err := LoadConfig(path.Join(home, ".mlget.yml"))
	if err != nil {
		log.Fatal()
		t.Errorf("%v", err)
	}

	scfg, err := parseTestConfig("./mlget-test-config/samples.yaml", t.Name())
	if err != nil {
		log.Fatal()
		t.Errorf("%v", err)
	}

	ht, _ := hashType(scfg.Hash)
	hash := Hash{HashType: ht, Hash: scfg.Hash}

	var osq ObjectiveSeeQuery
	result, filename, _ := InQuest.QueryAndDownload(cfg, hash, false, osq)

	if !result {
		t.Errorf("InquestLabs failed")
	} else {
		valid, errmsg := hash.ValidateFile(filename)

		if !valid {
			os.Remove(hash.Hash)
			t.Errorf(errmsg)
		} else {
			os.Remove(hash.Hash)
		}
	}
}

func TestInquestLabsNoLookUp(t *testing.T) {
	home, _ := os.UserHomeDir()
	cfg, err := LoadConfig(path.Join(home, ".mlget.yml"))
	if err != nil {
		log.Fatal()
		t.Errorf("%v", err)
	}

	scfg, err := parseTestConfig("./mlget-test-config/samples.yaml", t.Name())
	if err != nil {
		log.Fatal()
		t.Errorf("%v", err)
	}

	ht, _ := hashType(scfg.Hash)
	hash := Hash{HashType: ht, Hash: scfg.Hash}

	var osq ObjectiveSeeQuery
	result, filename, _ := InQuest.QueryAndDownload(cfg, hash, false, osq)

	if !result {
		t.Errorf("InquestLabs failed")
	} else {
		valid, errmsg := hash.ValidateFile(filename)

		if !valid {
			os.Remove(hash.Hash)
			t.Errorf(errmsg)
		} else {
			os.Remove(hash.Hash)
		}
	}
}

func TestVirusTotal(t *testing.T) {
	home, _ := os.UserHomeDir()
	cfg, err := LoadConfig(path.Join(home, ".mlget.yml"))
	if err != nil {
		log.Fatal()
		t.Errorf("%v", err)
	}

	scfg, err := parseTestConfig("./mlget-test-config/samples.yaml", t.Name())
	if err != nil {
		log.Fatal()
		t.Errorf("%v", err)
	}

	ht, _ := hashType(scfg.Hash)
	hash := Hash{HashType: ht, Hash: scfg.Hash}

	var osq ObjectiveSeeQuery
	result, filename, _ := VirusTotal.QueryAndDownload(cfg, hash, false, osq)

	if !result {
		t.Errorf("VirusTotal failed")
	} else {
		valid, errmsg := hash.ValidateFile(filename)

		if !valid {
			os.Remove(hash.Hash)
			t.Errorf(errmsg)
		} else {
			os.Remove(hash.Hash)
		}
	}
}

func TestMWDB(t *testing.T) {
	home, _ := os.UserHomeDir()
	cfg, err := LoadConfig(path.Join(home, ".mlget.yml"))
	if err != nil {
		log.Fatal()
		t.Errorf("%v", err)
	}

	scfg, err := parseTestConfig("./mlget-test-config/samples.yaml", t.Name())
	if err != nil {
		log.Fatal()
		t.Errorf("%v", err)
	}

	ht, _ := hashType(scfg.Hash)
	hash := Hash{HashType: ht, Hash: scfg.Hash}

	var osq ObjectiveSeeQuery
	result, filename, _ := MWDB.QueryAndDownload(cfg, hash, false, osq)

	if !result {
		t.Errorf("MWDB failed")
	} else {
		valid, errmsg := hash.ValidateFile(filename)

		if !valid {
			os.Remove(hash.Hash)
			t.Errorf(errmsg)
		} else {
			os.Remove(hash.Hash)
		}
	}
}

func TestPolyswarm(t *testing.T) {
	home, _ := os.UserHomeDir()
	cfg, err := LoadConfig(path.Join(home, ".mlget.yml"))
	if err != nil {
		log.Fatal()
		t.Errorf("%v", err)
	}

	scfg, err := parseTestConfig("./mlget-test-config/samples.yaml", t.Name())
	if err != nil {
		log.Fatal()
		t.Errorf("%v", err)
	}

	ht, _ := hashType(scfg.Hash)
	hash := Hash{HashType: ht, Hash: scfg.Hash}

	var osq ObjectiveSeeQuery
	result, filename, _ := Polyswarm.QueryAndDownload(cfg, hash, false, osq)

	if !result {
		t.Errorf("PolySwarm failed")
	} else {
		valid, errmsg := hash.ValidateFile(filename)

		if !valid {
			os.Remove(hash.Hash)
			t.Errorf(errmsg)
		} else {
			os.Remove(hash.Hash)
		}
	}
}

func TestHybridAnalysis(t *testing.T) {
	home, _ := os.UserHomeDir()
	cfg, err := LoadConfig(path.Join(home, ".mlget.yml"))
	if err != nil {
		log.Fatal()
		t.Errorf("%v", err)
	}

	scfg, err := parseTestConfig("./mlget-test-config/samples.yaml", t.Name())
	if err != nil {
		log.Fatal()
		t.Errorf("%v", err)
	}

	ht, _ := hashType(scfg.Hash)
	hash := Hash{HashType: ht, Hash: scfg.Hash}

	var osq ObjectiveSeeQuery
	result, filename, _ := HybridAnalysis.QueryAndDownload(cfg, hash, false, osq)

	if !result {
		t.Errorf("HybridAnalysis failed")
	} else {
		valid, errmsg := hash.ValidateFile(filename)

		if !valid {
			os.Remove(hash.Hash)
			t.Errorf(errmsg)
		} else {
			os.Remove(hash.Hash)
		}
	}
}

func TestHybridAnalysisNotFound(t *testing.T) {
	home, _ := os.UserHomeDir()
	cfg, err := LoadConfig(path.Join(home, ".mlget.yml"))
	if err != nil {
		log.Fatal()
		t.Errorf("%v", err)
	}

	scfg, err := parseTestConfig("./mlget-test-config/samples.yaml", t.Name())
	if err != nil {
		log.Fatal()
		t.Errorf("%v", err)
	}

	ht, _ := hashType(scfg.Hash)
	hash := Hash{HashType: ht, Hash: scfg.Hash}

	var osq ObjectiveSeeQuery
	result, _, _ := HybridAnalysis.QueryAndDownload(cfg, hash, false, osq)

	if result {
		t.Errorf("HybridAnalysis failed")
	}
}

func TestTriage(t *testing.T) {
	home, _ := os.UserHomeDir()
	cfg, err := LoadConfig(path.Join(home, ".mlget.yml"))
	if err != nil {
		log.Fatal()
		t.Errorf("%v", err)
	}

	scfg, err := parseTestConfig("./mlget-test-config/samples.yaml", t.Name())
	if err != nil {
		log.Fatal()
		t.Errorf("%v", err)
	}

	ht, _ := hashType(scfg.Hash)
	hash := Hash{HashType: ht, Hash: scfg.Hash}

	var osq ObjectiveSeeQuery
	result, filename, _ := Triage.QueryAndDownload(cfg, hash, false, osq)

	if !result {
		t.Errorf("Triage failed")
	} else {
		valid, errmsg := hash.ValidateFile(filename)

		if !valid {
			os.Remove(hash.Hash)
			t.Errorf(errmsg)
		} else {
			os.Remove(hash.Hash)
		}
	}
}

func TestTriageV2(t *testing.T) {
	home, _ := os.UserHomeDir()
	cfg, err := LoadConfig(path.Join(home, ".mlget.yml"))
	if err != nil {
		log.Fatal()
		t.Errorf("%v", err)
	}

	scfg, err := parseTestConfig("./mlget-test-config/samples.yaml", t.Name())
	if err != nil {
		log.Fatal()
		t.Errorf("%v", err)
	}

	ht, _ := hashType(scfg.Hash)
	hash := Hash{HashType: ht, Hash: scfg.Hash}

	var osq ObjectiveSeeQuery
	result, filename, _ := Triage.QueryAndDownload(cfg, hash, true, osq)

	if !result {
		t.Errorf("Triage failed")
	} else {
		if filename == "0d8d46ec44e737e6ef6cd7df8edf95d83807e84be825ef76089307b399a6bcbb" {
			os.Remove(hash.Hash)
		} else {
			os.Remove(hash.Hash)
			t.Errorf("File name not found")
		}
	}
}

func TestMalShare(t *testing.T) {
	home, _ := os.UserHomeDir()
	cfg, err := LoadConfig(path.Join(home, ".mlget.yml"))
	if err != nil {
		log.Fatal()
		t.Errorf("%v", err)
	}

	scfg, err := parseTestConfig("./mlget-test-config/samples.yaml", t.Name())
	if err != nil {
		log.Fatal()
		t.Errorf("%v", err)
	}

	ht, _ := hashType(scfg.Hash)
	hash := Hash{HashType: ht, Hash: scfg.Hash}

	var osq ObjectiveSeeQuery
	result, filename, _ := Malshare.QueryAndDownload(cfg, hash, false, osq)

	if !result {
		t.Errorf("Malshare failed")
	} else {
		valid, errmsg := hash.ValidateFile(filename)

		if !valid {
			os.Remove(hash.Hash)
			t.Errorf(errmsg)
		} else {
			os.Remove(hash.Hash)
		}
	}
}

func TestMalwareBazaar(t *testing.T) {
	home, _ := os.UserHomeDir()
	cfg, err := LoadConfig(path.Join(home, ".mlget.yml"))
	if err != nil {
		log.Fatal()
		t.Errorf("%v", err)
	}

	scfg, err := parseTestConfig("./mlget-test-config/samples.yaml", t.Name())
	if err != nil {
		log.Fatal()
		t.Errorf("%v", err)
	}

	ht, _ := hashType(scfg.Hash)
	hash := Hash{HashType: ht, Hash: scfg.Hash}

	var osq ObjectiveSeeQuery
	result, filename, _ := MalwareBazaar.QueryAndDownload(cfg, hash, false, osq)

	if !result {
		t.Errorf("MalwareBazaar failed")
	} else {
		valid, errmsg := hash.ValidateFile(filename)

		if !valid {
			os.Remove(hash.Hash)
			t.Errorf(errmsg)
		} else {
			os.Remove(hash.Hash)
		}
	}
}

func TestMalpedia(t *testing.T) {
	home, _ := os.UserHomeDir()
	cfg, err := LoadConfig(path.Join(home, ".mlget.yml"))
	if err != nil {
		log.Fatal()
		t.Errorf("%v", err)
	}

	scfg, err := parseTestConfig("./mlget-test-config/samples.yaml", t.Name())
	if err != nil {
		log.Fatal()
		t.Errorf("%v", err)
	}

	ht, _ := hashType(scfg.Hash)
	hash := Hash{HashType: ht, Hash: scfg.Hash}

	var osq ObjectiveSeeQuery
	result, filename, _ := Malpedia.QueryAndDownload(cfg, hash, false, osq)

	if !result {
		t.Errorf("Malpedia failed")
	} else {
		valid, errmsg := hash.ValidateFile(filename)

		if !valid {
			os.Remove(hash.Hash)
			t.Errorf(errmsg)
		} else {
			os.Remove(hash.Hash)
		}
	}
}

func TestUnpacme(t *testing.T) {
	home, _ := os.UserHomeDir()
	cfg, err := LoadConfig(path.Join(home, ".mlget.yml"))
	if err != nil {
		log.Fatal()
		t.Errorf("%v", err)
	}

	scfg, err := parseTestConfig("./mlget-test-config/samples.yaml", t.Name())
	if err != nil {
		log.Fatal()
		t.Errorf("%v", err)
	}

	ht, _ := hashType(scfg.Hash)
	hash := Hash{HashType: ht, Hash: scfg.Hash}

	var osq ObjectiveSeeQuery
	result, filename, _ := UnpacMe.QueryAndDownload(cfg, hash, false, osq)

	if !result {
		t.Errorf("Unpacme failed")
	} else {
		valid, errmsg := hash.ValidateFile(filename)

		if !valid {
			os.Remove(hash.Hash)
			t.Errorf(errmsg)
		} else {
			os.Remove(hash.Hash)
		}
	}
}

func TestVxShare(t *testing.T) {
	home, _ := os.UserHomeDir()
	cfg, err := LoadConfig(path.Join(home, ".mlget.yml"))
	if err != nil {
		log.Fatal()
		t.Errorf("%v", err)
	}

	scfg, err := parseTestConfig("./mlget-test-config/samples.yaml", t.Name())
	if err != nil {
		log.Fatal()
		t.Errorf("%v", err)
	}

	ht, _ := hashType(scfg.Hash)
	hash := Hash{HashType: ht, Hash: scfg.Hash}

	var osq ObjectiveSeeQuery
	result, filename, _ := VxShare.QueryAndDownload(cfg, hash, false, osq)

	if !result {
		t.Errorf("VxShare failed")
	} else {
		valid, errmsg := hash.ValidateFile(filename)

		if !valid {
			os.Remove(hash.Hash)
			t.Errorf(errmsg)
		} else {
			os.Remove(hash.Hash)
		}
	}
}

func TestFileScanIo(t *testing.T) {
	home, _ := os.UserHomeDir()
	cfg, err := LoadConfig(path.Join(home, ".mlget.yml"))
	if err != nil {
		log.Fatal()
		t.Errorf("%v", err)
	}

	scfg, err := parseTestConfig("./mlget-test-config/samples.yaml", t.Name())
	if err != nil {
		log.Fatal()
		t.Errorf("%v", err)
	}

	ht, _ := hashType(scfg.Hash)
	hash := Hash{HashType: ht, Hash: scfg.Hash}

	var osq ObjectiveSeeQuery
	result, filename, _ := FileScanIo.QueryAndDownload(cfg, hash, false, osq)

	if !result {
		t.Errorf("FileScanIo failed")
	} else {
		valid, errmsg := hash.ValidateFile(filename)

		if !valid {
			os.Remove(hash.Hash)
			t.Errorf(errmsg)
		} else {
			os.Remove(hash.Hash)
		}
	}

}

func TestURLScanIo(t *testing.T) {
	home, _ := os.UserHomeDir()
	cfg, err := LoadConfig(path.Join(home, ".mlget.yml"))
	if err != nil {
		log.Fatal()
		t.Errorf("%v", err)
	}

	scfg, err := parseTestConfig("./mlget-test-config/samples.yaml", t.Name())
	if err != nil {
		log.Fatal()
		t.Errorf("%v", err)
	}

	ht, _ := hashType(scfg.Hash)
	hash := Hash{HashType: ht, Hash: scfg.Hash}

	var osq ObjectiveSeeQuery
	result, filename, _ := URLScanIO.QueryAndDownload(cfg, hash, false, osq)

	if !result {
		t.Errorf("URLScanIO failed")
	} else {
		valid, errmsg := hash.ValidateFile(filename)

		if !valid {
			os.Remove(hash.Hash)
			t.Errorf(errmsg)
		} else {
			os.Remove(hash.Hash)
		}
	}

}

func TestAssemblyLine(t *testing.T) {
	home, _ := os.UserHomeDir()
	cfg, err := LoadConfig(path.Join(home, ".mlget.yml"))
	if err != nil {
		log.Fatal()
		t.Errorf("%v", err)
	}

	scfg, err := parseTestConfig("./mlget-test-config/samples.yaml", t.Name())
	if err != nil {
		log.Fatal()
		t.Errorf("%v", err)
	}

	ht, _ := hashType(scfg.Hash)
	hash := Hash{HashType: ht, Hash: scfg.Hash}

	var osq ObjectiveSeeQuery
	result, filename, _ := AssemblyLine.QueryAndDownload(cfg, hash, false, osq)

	if !result {
		t.Errorf("Assemblyline failed")
	} else {
		valid, errmsg := hash.ValidateFile(filename)

		if !valid {
			os.Remove(filename)
			t.Errorf(errmsg)
		} else {
			os.Remove(filename)
		}
	}

}

func TestVirusExchange(t *testing.T) {
	home, _ := os.UserHomeDir()
	cfg, err := LoadConfig(path.Join(home, ".mlget.yml"))
	if err != nil {
		log.Fatal()
		t.Errorf("%v", err)
	}

	scfg, err := parseTestConfig("./mlget-test-config/samples.yaml", t.Name())
	if err != nil {
		log.Fatal()
		t.Errorf("%v", err)
	}

	ht, _ := hashType(scfg.Hash)
	hash := Hash{HashType: ht, Hash: scfg.Hash}

	var osq ObjectiveSeeQuery
	result, filename, _ := VirusExchange.QueryAndDownload(cfg, hash, false, osq)

	if result {
		t.Errorf("VirusExchange was a success - this is unexpected. This means the link returned by the API was fixed or there is another issue going on.")
		valid, errmsg := hash.ValidateFile(filename)

		if !valid {
			os.Remove(filename)
			t.Errorf(errmsg)
		} else {
			os.Remove(filename)
		}
	}
}

func TestVirusExchangeV2(t *testing.T) {
	home, _ := os.UserHomeDir()
	cfg, err := LoadConfig(path.Join(home, ".mlget.yml"))
	if err != nil {
		log.Fatal()
		t.Errorf("%v", err)
	}

	scfg, err := parseTestConfig("./mlget-test-config/samples.yaml", t.Name())
	if err != nil {
		log.Fatal()
		t.Errorf("%v", err)
	}

	ht, _ := hashType(scfg.Hash)
	hash := Hash{HashType: ht, Hash: scfg.Hash}

	var osq ObjectiveSeeQuery
	result, filename, _ := VirusExchange.QueryAndDownload(cfg, hash, false, osq)

	if !result {
		t.Errorf("VirusExchange failed")
	} else {
		valid, errmsg := hash.ValidateFile(filename)

		if !valid {
			os.Remove(filename)
			t.Errorf(errmsg)
		} else {
			os.Remove(filename)
		}
	}
}
