package main

import (
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strings"

	"gopkg.in/yaml.v2"
)

type OldConfig struct {
	MalShare struct {
		ApiKey string `yaml:"api"`
		Host   string `yaml:"host"`
	} `yaml:"malshare"`
	MalwareBazar struct {
		Host string `yaml:"host"`
	} `yaml:"malwarebazar"`
	MWDB struct {
		ApiKey string `yaml:"api"`
		Host   string `yaml:"host"`
	} `yaml:"mwdb"`
	VT struct {
		ApiKey string `yaml:"api"`
		Host   string `yaml:"host"`
	} `yaml:"virustotal"`
	Triage struct {
		ApiKey string `yaml:"api"`
		Host   string `yaml:"host"`
	} `yaml:"triage"`
	HybridAnalysis struct {
		ApiKey string `yaml:"api"`
		Host   string `yaml:"host"`
	} `yaml:"hybridanalysis"`
	PolySwarm struct {
		ApiKey string `yaml:"api"`
		Host   string `yaml:"host"`
	} `yaml:"polyswarm"`
	CapeSandbox struct {
		ApiKey string `yaml:"api"`
		Host   string `yaml:"host"`
	} `yaml:"capesandbox"`
	JoeSandbox struct {
		ApiKey string `yaml:"api"`
		Host   string `yaml:"host"`
	} `yaml:"joesandbox"`
	InquestLabs struct {
		ApiKey string `yaml:"api"`
		Host   string `yaml:"host"`
	} `yaml:"inquestlabs"`
	UploadToMWDBOption struct {
		ApiKey string `yaml:"api"`
		Host   string `yaml:"host"`
	} `yaml:"uploadtomwdb"`
}

type MalwareRepoType int64

const (
	NotSupported MalwareRepoType = iota
	JoeSandbox
	MWDB
	HybridAnalysis
	CapeSandbox
	InQuest
	MalwareBazaar
	Triage
	Malshare
	VirusTotal
	Polyswarm

	//UploadMWDB must always be last, or other things won't work as expected
	UploadMWDB
)

var MalwareRepoList = []MalwareRepoType{JoeSandbox, MWDB, HybridAnalysis, CapeSandbox, InQuest, MalwareBazaar, Triage, Malshare, VirusTotal, Polyswarm, UploadMWDB}

func (malrepo MalwareRepoType) QueryAndDownload(repos []RepositoryConfigEntry, hash Hash, doNotExtract bool) (bool, string) {
	matchingConfigRepos := getConfigsByType(malrepo, repos)
	if len(matchingConfigRepos) == 0 {
		fmt.Printf("    [!] %s is not found in the yml config file\n", malrepo)
	}
	for _, mcr := range matchingConfigRepos {
		found := false
		filename := ""
		fmt.Printf("  [*] %s: %s\n", mcr.Type, mcr.Host)
		switch malrepo {
		case MalwareBazaar:
			found, filename = malwareBazaar(mcr.Host, hash, doNotExtract)
		case MWDB:
			found, filename = mwdb(mcr.Host, mcr.Api, hash)
		case Malshare:
			found, filename = malshare(mcr.Host, mcr.Api, hash)
		case Triage:
			found, filename = triage(mcr.Host, mcr.Api, hash)
		case InQuest:
			found, filename = inquestlabs(mcr.Host, mcr.Api, hash)
		case HybridAnalysis:
			found, filename = hybridAnlysis(mcr.Host, mcr.Api, hash, doNotExtract)
		case Polyswarm:
			found, filename = polyswarm(mcr.Host, mcr.Api, hash)
		case VirusTotal:
			found, filename = virustotal(mcr.Host, mcr.Api, hash)
		case JoeSandbox:
			found, filename = joesandbox(mcr.Host, mcr.Api, hash)
		case CapeSandbox:
			found, filename = capesandbox(mcr.Host, mcr.Api, hash)
		case UploadMWDB:
			found, filename = mwdb(mcr.Host, mcr.Api, hash)
		}
		if found {
			return found, filename
		}
	}
	return false, ""
}

func (malrepo MalwareRepoType) VerifyRepoParams(repo RepositoryConfigEntry) bool {
	switch malrepo {
	case NotSupported:
		return false
	case MalwareBazaar:
		if repo.Host != "" {
			return true
		}
	default:
		if repo.Host != "" && repo.Api != "" {
			return true
		}
	}
	return false
}

func (malrepo MalwareRepoType) CreateEntry() (RepositoryConfigEntry, error) {
	var host string
	var api string

	var default_url string

	switch malrepo {
	case NotSupported:
		return RepositoryConfigEntry{}, fmt.Errorf("malware repository rype, %s, is not supported", malrepo.String())
	case MalwareBazaar:
		default_url = "https://mb-api.abuse.ch/api/v1"
	case Malshare:
		default_url = "https://malshare.com"
	case MWDB:
		default_url = "https://mwdb.cert.pl/api"
	case CapeSandbox:
		default_url = "https://www.capesandbox.com/apiv2"
	case JoeSandbox:
		default_url = "https://jbxcloud.joesecurity.org/api"
	case InQuest:
		default_url = "https://labs.inquest.net/api"
	case HybridAnalysis:
		default_url = "https://www.hybrid-analysis.com/api/v2"
	case Triage:
		default_url = "https://api.tria.ge/v0"
	case VirusTotal:
		default_url = "https://www.virustotal.com/api/v3"
	case Polyswarm:
		default_url = "https://api.polyswarm.network/v2"
	}
	if default_url != "" {
		fmt.Printf("Enter Host [ Press enter for default - %s ]:\n", default_url)
	} else {
		fmt.Printf("Enter Host:\n")
	}
	fmt.Print(">> ")
	fmt.Scanln(&host)
	if host == "" {
		fmt.Println("Using the default url")
		host = default_url
	}
	if malrepo != MalwareBazaar {
		fmt.Println("Enter API Key:")
		fmt.Print(">> ")
		fmt.Scanln(&api)
	}
	return RepositoryConfigEntry{Host: host, Api: api, Type: malrepo.String()}, nil
}

func (malrepo MalwareRepoType) String() string {
	switch malrepo {
	case JoeSandbox:
		return "JoeSandbox"
	case MWDB:
		return "MWDB"
	case HybridAnalysis:
		return "HybridAnalysis"
	case CapeSandbox:
		return "CapeSandbox"
	case InQuest:
		return "InQuest"
	case MalwareBazaar:
		return "MalwareBazaar"
	case Triage:
		return "Triage"
	case Malshare:
		return "Malshare"
	case VirusTotal:
		return "VirusTotal"
	case Polyswarm:
		return "Polyswarm"
	case UploadMWDB:
		return "UploadMWDB"

	}
	return "NotSupported"
}

func allowedMalwareRepoTypes() {
	for mr := range MalwareRepoList {
		fmt.Printf("    %s\n", MalwareRepoType(mr).String())
	}
}

func printAllowedMalwareRepoTypeOptions() {
	fmt.Println("")
	for _, mr := range MalwareRepoList {
		fmt.Printf("  [%d]    %s\n", mr, mr.String())
	}
}

func queryAndDownloadAll(repos []RepositoryConfigEntry, hash Hash, doNotExtract bool, skipUploadMWDBEntries bool) (bool, string) {
	found := false
	filename := ""
	sort.Slice(repos[:], func(i, j int) bool {
		return repos[i].QueryOrder < repos[j].QueryOrder
	})
	// Hack for now
	// Due to Multiple entries of the same type, for each type instance in the config  it will
	// try to download for type (number of entries for type in config squared)
	// This array is meant to ensure that for each type it will only try it once
	var completedTypes []MalwareRepoType
	for _, repo := range repos {
		if repo.Type == UploadMWDB.String() && skipUploadMWDBEntries {
			continue
		}
		mr := getMalwareRepoByName(repo.Type)
		if !contains(completedTypes, mr) {
			found, filename = mr.QueryAndDownload(repos, hash, doNotExtract)
			if found {
				break
			}
			completedTypes = append(completedTypes, mr)
		}
	}
	return found, filename
}

func getMalwareRepoByFlagName(name string) MalwareRepoType {
	switch strings.ToLower(name) {
	case strings.ToLower("js"):
		return JoeSandbox
	case strings.ToLower("md"):
		return MWDB
	case strings.ToLower("ha"):
		return HybridAnalysis
	case strings.ToLower("cs"):
		return CapeSandbox
	case strings.ToLower("iq"):
		return InQuest
	case strings.ToLower("mb"):
		return MalwareBazaar
	case strings.ToLower("tr"):
		return Triage
	case strings.ToLower("ms"):
		return Malshare
	case strings.ToLower("vt"):
		return VirusTotal
	case strings.ToLower("ps"):
		return Polyswarm
	}
	return NotSupported
}

func getMalwareRepoByName(name string) MalwareRepoType {
	switch strings.ToLower(name) {
	case strings.ToLower("JoeSandbox"):
		return JoeSandbox
	case strings.ToLower("MWDB"):
		return MWDB
	case strings.ToLower("HybridAnalysis"):
		return HybridAnalysis
	case strings.ToLower("CapeSandbox"):
		return CapeSandbox
	case strings.ToLower("InQuest"):
		return InQuest
	case strings.ToLower("MalwareBazaar"):
		return MalwareBazaar
	case strings.ToLower("Triage"):
		return Triage
	case strings.ToLower("Malshare"):
		return Malshare
	case strings.ToLower("VirusTotal"):
		return VirusTotal
	case strings.ToLower("Polyswarm"):
		return Polyswarm
	case strings.ToLower("UploadMWDB"):
		return UploadMWDB
	}
	return NotSupported
}

func getConfigsByType(repoType MalwareRepoType, repos []RepositoryConfigEntry) []RepositoryConfigEntry {
	var filteredRepos []RepositoryConfigEntry
	for _, v := range repos {
		if v.Type == repoType.String() {
			filteredRepos = append(filteredRepos, v)
		}
	}
	return filteredRepos
}

type RepositoryConfigEntry struct {
	Type       string `yaml:"type"`
	Host       string `yaml:"url"`
	Api        string `yaml:"api"`
	QueryOrder int    `yaml:"queryorder"`
}

func LoadConfig(filename string) ([]RepositoryConfigEntry, error) {
	cfg, err := parseFile(filename)
	if os.IsNotExist(err) {
		fmt.Printf("%s does not exists.  Creating...\n", filename)
		filename, err = initConfig(filename)
		if err != nil {
			log.Fatal(err)
			return nil, err
		}
		cfg, err = parseFile(filename)
		if err != nil {
			log.Fatal(err)
			return nil, err
		}
	} else if err != nil {
		log.Fatal(err)
		return nil, err
	}
	return verifyConfig(cfg)
}

func verifyConfig(repos map[string]RepositoryConfigEntry) ([]RepositoryConfigEntry, error) {
	var verifiedConfigRepos []RepositoryConfigEntry

	uploadToMWDBCount := 0

	for k, v := range repos {
		mr := getMalwareRepoByName(v.Type)
		if mr == NotSupported {
			fmt.Printf("%s is not a supported type.  Skipping...\n\nSupported types include:\n", v.Type)
			allowedMalwareRepoTypes()
			fmt.Println("")
		} else {
			if v.Type == UploadMWDB.String() {
				uploadToMWDBCount++
			}
			valid := mr.VerifyRepoParams(v)
			if !valid {
				fmt.Printf("  Skipping %s (Type: %s, URL: %s, API: %s) as it's missing a parameter.\n", k, v.Type, v.Host, v.Api)
			} else {
				verifiedConfigRepos = append(verifiedConfigRepos, v)
			}
		}
	}
	return verifiedConfigRepos, nil
}

func parseFile(path string) (map[string]RepositoryConfigEntry, error) {

	_, err := os.Stat(path)
	if os.IsNotExist(err) {
		return nil, err
	}

	f, err := ioutil.ReadFile(path)
	if err != nil {
		fmt.Printf("%v", err)
		return nil, err
	}

	data := make(map[string]RepositoryConfigEntry)

	err = yaml.Unmarshal(f, &data)
	if err != nil {
		fmt.Printf("%v", err)
		return nil, err
	}

	//Count number of entries where the type is not set
	nullTypeSetCount := 0
	for _, v := range data {
		if v.Type == "" {
			nullTypeSetCount++
		}
	}
	if nullTypeSetCount == len(data) {
		var cfg OldConfig
		parseV1File(path, &cfg)

		if cfg.CapeSandbox.ApiKey != "" {
			return migrateConfig(path, cfg)
		} else if cfg.HybridAnalysis.ApiKey != "" {
			return migrateConfig(path, cfg)
		} else if cfg.InquestLabs.ApiKey != "" {
			return migrateConfig(path, cfg)
		} else if cfg.MWDB.ApiKey != "" {
			return migrateConfig(path, cfg)
		} else if cfg.MalShare.ApiKey != "" {
			return migrateConfig(path, cfg)
		} else if cfg.Triage.ApiKey != "" {
			return migrateConfig(path, cfg)
		} else if cfg.PolySwarm.ApiKey != "" {
			return migrateConfig(path, cfg)
		} else if cfg.VT.ApiKey != "" {
			return migrateConfig(path, cfg)
		} else if cfg.JoeSandbox.ApiKey != "" {
			return migrateConfig(path, cfg)
		} else if cfg.MalwareBazar.Host != "" {
			return migrateConfig(path, cfg)
		}
	}

	return data, nil
}

func AddToConfig(filename string) (string, error) {
	repoConfigEntries, err := parseFile(filename)
	if err != nil {
		fmt.Printf("Error parsing %s - %v", filename, err)
		return "", err
	}

	data, err := createNewEntries(0)
	if err != nil {
		fmt.Printf("Error creating new config entries : %v", err)
		return "", err
	}

	finalConfigEntryList := make(map[string]RepositoryConfigEntry)

	entryNumber := 0

	// Add items from reporConfigEntries (pre-existing items) to the final list
	for _, v := range repoConfigEntries {
		finalConfigEntryList["repository "+fmt.Sprint(entryNumber)] = v
		entryNumber++
	}

	// Add items not found in repoConfigEnties (the pre-existing items)
	for _, v1 := range data {
		found := false
		for _, v2 := range repoConfigEntries {
			if v1.Type == v2.Type && v1.Host == v1.Api {
				found = true
			}
		}
		if !found {
			finalConfigEntryList["repository "+fmt.Sprint(entryNumber)] = v1
			entryNumber++
		}
	}
	return writeConfigToFile(filename, finalConfigEntryList)
}

func initConfig(filename string) (string, error) {
	data, err := createNewEntries(0)
	if err != nil {
		fmt.Printf("Error creating new Repository Config Entries: %v\n", err)
		return "", err
	}
	return writeConfigToFile(filename, data)
}

func createNewEntries(entryNumber int) (map[string]RepositoryConfigEntry, error) {
	data := make(map[string]RepositoryConfigEntry)

	var option int64

	for {

		fmt.Printf("\nEnter the corresponding Repository Config Entry number you want to add to .mlget.yml.\n")
		fmt.Printf("Enter 0 to exit.\n")
		printAllowedMalwareRepoTypeOptions()

		fmt.Print(">> ")

		fmt.Scan(&option)

		if option > int64(NotSupported) && option <= int64(UploadMWDB) {
			entry, err := MalwareRepoType(option).CreateEntry()
			if err != nil {
				continue
			}
			data["repository "+fmt.Sprint(entryNumber)] = entry
			entryNumber++
		} else if option == 0 {
			break
		}
	}
	return data, nil
}

func writeConfigToFile(filename string, repoConfigEntries map[string]RepositoryConfigEntry) (string, error) {
	_, err := os.Stat(filename)
	if err == nil {
		os.Remove(filename)
	}

	file, err := os.OpenFile(filename, os.O_CREATE|os.O_WRONLY, 0600)
	if err != nil {
		fmt.Printf("error creating file: %v\n", err)
		return "", err
	}
	defer file.Close()

	enc := yaml.NewEncoder(file)

	err = enc.Encode(repoConfigEntries)
	if err != nil {
		fmt.Printf("error encoding: %v\n", err)
		return "", err
	} else {
		fmt.Printf("Config written to %s\n\n", file.Name())
	}

	return file.Name(), nil
}

func migrateConfig(filename string, cfg OldConfig) (map[string]RepositoryConfigEntry, error) {
	configEntryIndex := 0
	newRepositoryEntries := make(map[string]RepositoryConfigEntry)

	fmt.Println("Migrate config file (backup file will be created first)[Y|n]?")
	var response string
	fmt.Scanln(&response)

	if response == "" || strings.ToLower(response) == "y" {

		if cfg.CapeSandbox.ApiKey != "" {
			newRepositoryEntries["repository "+fmt.Sprint(configEntryIndex)] = RepositoryConfigEntry{Host: cfg.CapeSandbox.Host, Api: cfg.CapeSandbox.ApiKey, Type: CapeSandbox.String(), QueryOrder: 2}
			configEntryIndex++
		}
		if cfg.HybridAnalysis.ApiKey != "" {
			newRepositoryEntries["repository "+fmt.Sprint(configEntryIndex)] = RepositoryConfigEntry{Host: cfg.HybridAnalysis.Host, Api: cfg.HybridAnalysis.ApiKey, Type: HybridAnalysis.String(), QueryOrder: 4}
			configEntryIndex++
		}
		if cfg.InquestLabs.ApiKey != "" {
			newRepositoryEntries["repository "+fmt.Sprint(configEntryIndex)] = RepositoryConfigEntry{Host: cfg.InquestLabs.Host, Api: cfg.InquestLabs.ApiKey, Type: InQuest.String(), QueryOrder: 6}
			configEntryIndex++
		}
		if cfg.MWDB.ApiKey != "" {
			newRepositoryEntries["repository "+fmt.Sprint(configEntryIndex)] = RepositoryConfigEntry{Host: cfg.MWDB.Host, Api: cfg.MWDB.ApiKey, Type: MWDB.String(), QueryOrder: 3}
			configEntryIndex++
		}
		if cfg.MalShare.ApiKey != "" {
			newRepositoryEntries["repository "+fmt.Sprint(configEntryIndex)] = RepositoryConfigEntry{Host: cfg.MalShare.Host, Api: cfg.MalShare.ApiKey, Type: Malshare.String(), QueryOrder: 5}
			configEntryIndex++
		}
		if cfg.Triage.ApiKey != "" {
			newRepositoryEntries["repository "+fmt.Sprint(configEntryIndex)] = RepositoryConfigEntry{Host: cfg.Triage.Host, Api: cfg.Triage.ApiKey, Type: Triage.String(), QueryOrder: 7}
			configEntryIndex++
		}
		if cfg.PolySwarm.ApiKey != "" {
			newRepositoryEntries["repository "+fmt.Sprint(configEntryIndex)] = RepositoryConfigEntry{Host: cfg.PolySwarm.Host, Api: cfg.PolySwarm.ApiKey, Type: Polyswarm.String(), QueryOrder: 10}
			configEntryIndex++
		}
		if cfg.VT.ApiKey != "" {
			newRepositoryEntries["repository "+fmt.Sprint(configEntryIndex)] = RepositoryConfigEntry{Host: cfg.VT.Host, Api: cfg.VT.ApiKey, Type: VirusTotal.String(), QueryOrder: 9}
			configEntryIndex++
		}
		if cfg.JoeSandbox.ApiKey != "" {
			newRepositoryEntries["repository "+fmt.Sprint(configEntryIndex)] = RepositoryConfigEntry{Host: cfg.JoeSandbox.Host, Api: cfg.JoeSandbox.ApiKey, Type: JoeSandbox.String(), QueryOrder: 8}
			configEntryIndex++
		}
		if cfg.UploadToMWDBOption.ApiKey != "" {
			newRepositoryEntries["repository "+fmt.Sprint(configEntryIndex)] = RepositoryConfigEntry{Host: cfg.UploadToMWDBOption.Host, Api: cfg.UploadToMWDBOption.ApiKey, Type: UploadMWDB.String()}
			configEntryIndex++
		}
		if cfg.MalwareBazar.Host != "" {
			newRepositoryEntries["repository "+fmt.Sprint(configEntryIndex)] = RepositoryConfigEntry{Host: cfg.MalwareBazar.Host, Type: MalwareBazaar.String(), QueryOrder: 1}
			configEntryIndex++
		}

		homeDir, err := os.UserHomeDir()
		if err != nil {
			fmt.Println(err)
			return nil, err
		}

		backupFileName := path.Join(homeDir, ".mlget-bak.yml")
		fmt.Printf("Creating a backup file %s\n", backupFileName)
		err = copyFile(filename, backupFileName)
		if err != nil {
			fmt.Println("Failed creating backup file, aborting!")
			return nil, fmt.Errorf("failed creating backup file (%s) : %v", backupFileName, err)
		}
		_, err = writeConfigToFile(filename, newRepositoryEntries)
		if err != nil {
			fmt.Println("Failed creating new config file, aborting!")
			return nil, fmt.Errorf("failed creating new config file : %v", err)
		}
	} else {
		return nil, fmt.Errorf("must update %s to latest configuration before contining", filename)
	}
	return newRepositoryEntries, nil
}

func copyFile(in string, out string) error {
	fin, err := os.Open(in)
	if err != nil {
		log.Fatal(err)
		return err
	}
	defer fin.Close()

	fout, err := os.Create(out)
	if err != nil {
		log.Fatal(err)
		return err
	}
	defer fout.Close()

	_, err = io.Copy(fout, fin)

	if err != nil {
		log.Fatal(err)
		return err
	}
	return nil
}

// parseYAML parses YAML from reader to data structure
func parseV1YAML(r io.Reader, str interface{}) error {
	return yaml.NewDecoder(r).Decode(str)
}

func parseV1File(path string, cfg interface{}) error {
	// open the configuration file
	f, err := os.OpenFile(path, os.O_RDONLY|os.O_SYNC, 0)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			fmt.Printf("Config does not exist.  Create config? [Y|n]")
			var answer string
			fmt.Scanln(&answer)

			if answer == "" || answer == "y" || answer == "Y" {
				filename, err := initConfig(path)
				if err != nil {
					fmt.Println("Not able to create file")
					fmt.Println(err)
					panic(err)
				}
				fmt.Printf("Created %s.  Make sure to fill out the API keys for the services you want to use.\n", filename)
				f, err = os.OpenFile(path, os.O_RDONLY|os.O_SYNC, 0)
				if err != nil {
					return err
				}
			} else {
				answer = "N"
			}

		} else {
			return err
		}
	}
	defer f.Close()

	// parse the file depending on the file type
	switch ext := strings.ToLower(filepath.Ext(path)); ext {
	case ".yml":
		err = parseV1YAML(f, cfg)
	default:
		return fmt.Errorf("file format '%s' doesn't supported by the parser", ext)
	}
	if err != nil {
		return fmt.Errorf("config file parsing error: %s", err.Error())
	}
	return nil
}

func contains(list []MalwareRepoType, x MalwareRepoType) bool {
	for _, item := range list {
		if item == x {
			return true
		}
	}
	return false
}