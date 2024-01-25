package main

import (
	"fmt"
	"log"
	"os"
	"sort"
	"strconv"
	"strings"

	"golang.org/x/exp/slices"
	"gopkg.in/yaml.v2"
)

type MalwareRepoType int64

const (
	NotSupported MalwareRepoType = iota //NotSupported must always be first, or other things won't work as expected

	AssemblyLine
	CapeSandbox
	FileScanIo
	HybridAnalysis
	InQuest
	JoeSandbox
	Malpedia
	Malshare
	MalwareBazaar
	MWDB
	ObjectiveSee
	Polyswarm
	Triage
	UnpacMe
	URLScanIO
	VirusExchange
	VirusTotal
	VxShare

	UploadAssemblyLine
	//UploadMWDB must always be last, or other things won't work as expected
	UploadMWDB
)

// var MalwareRepoList = []MalwareRepoType{CapeSandbox, HybridAnalysis, InQuest, JoeSandbox, Malpedia, Malshare, MalwareBazaar, MWDB, ObjectiveSee, Polyswarm, Triage, UnpacMe, VirusTotal, UploadMWDB}
func getMalwareRepoList() []MalwareRepoType {
	var malwareRepoList []MalwareRepoType
	for repo := range [UploadMWDB + 1]int64{} {
		if int64(repo) > int64(NotSupported) && int64(repo) <= int64(UploadMWDB) {
			malwareRepoList = append(malwareRepoList, MalwareRepoType(repo))
		}
	}
	return malwareRepoList
}

func (malrepo MalwareRepoType) QueryAndDownload(repos []RepositoryConfigEntry, hash Hash, doNotExtract bool, osq ObjectiveSeeQuery) (bool, string, MalwareRepoType) {
	matchingConfigRepos := getConfigsByType(malrepo, repos)
	if len(matchingConfigRepos) == 0 {
		fmt.Printf("    [!] %s is not found in the yml config file\n", malrepo)
	}
	for _, mcr := range matchingConfigRepos {
		found := false
		filename := ""
		checkedRepo := NotSupported
		fmt.Printf("  [*] %s: %s\n", mcr.Type, mcr.Host)
		switch malrepo {
		case MalwareBazaar:
			found, filename = malwareBazaar(mcr.Host, hash, doNotExtract, "infected")
			checkedRepo = MalwareBazaar
		case MWDB:
			found, filename = mwdb(mcr.Host, mcr.Api, hash)
			checkedRepo = MWDB
		case Malshare:
			found, filename = malshare(mcr.Host, mcr.Api, hash)
			checkedRepo = Malshare
		case Triage:
			found, filename = triage(mcr.Host, mcr.Api, hash)
			checkedRepo = Triage
		case InQuest:
			found, filename = inquestlabs(mcr.Host, mcr.Api, hash)
			checkedRepo = InQuest
		case HybridAnalysis:
			found, filename = hybridAnlysis(mcr.Host, mcr.Api, hash, doNotExtract)
			checkedRepo = HybridAnalysis
		case Polyswarm:
			found, filename = polyswarm(mcr.Host, mcr.Api, hash)
			checkedRepo = Polyswarm
		case VirusTotal:
			found, filename = virustotal(mcr.Host, mcr.Api, hash)
			checkedRepo = VirusTotal
		case JoeSandbox:
			found, filename = joesandbox(mcr.Host, mcr.Api, hash)
			checkedRepo = JoeSandbox
		case CapeSandbox:
			found, filename = capesandbox(mcr.Host, mcr.Api, hash)
			checkedRepo = CapeSandbox
		case ObjectiveSee:
			if len(osq.Malware) > 0 {
				found, filename = objectivesee(osq, hash, doNotExtract)
				checkedRepo = ObjectiveSee
			}
		case UnpacMe:
			found, filename = unpacme(mcr.Host, mcr.Api, hash)
			checkedRepo = UnpacMe
		case Malpedia:
			found, filename = malpedia(mcr.Host, mcr.Api, hash)
			checkedRepo = Malpedia
		case VxShare:
			found, filename = vxshare(mcr.Host, mcr.Api, hash, doNotExtract, "infected")
			checkedRepo = VxShare
		case FileScanIo:
			found, filename = filescanio(mcr.Host, mcr.Api, hash, doNotExtract, "infected")
			checkedRepo = FileScanIo
		case URLScanIO:
			found, filename = urlscanio(mcr.Host, mcr.Api, hash)
			checkedRepo = URLScanIO
		case VirusExchange:
			found, filename = virusexchange(mcr.Host, mcr.Api, hash)
			checkedRepo = VirusExchange
		case AssemblyLine:
			found, filename = assemblyline(mcr.Host, mcr.User, mcr.Api, mcr.IgnoreTLSErrors, hash)
			checkedRepo = AssemblyLine
		case UploadAssemblyLine:
			found, filename = assemblyline(mcr.Host, mcr.User, mcr.Api, mcr.IgnoreTLSErrors, hash)
			checkedRepo = UploadAssemblyLine
		case UploadMWDB:
			found, filename = mwdb(mcr.Host, mcr.Api, hash)
			checkedRepo = UploadMWDB
		}
		// So some repos we can't download from but we want to know that it exists at that service
		// At the moment, this is just Any.Run but suspect more will be added as time goes on
		if found {
			return found, filename, checkedRepo
		}
	}
	return false, "", NotSupported
}

func (malrepo MalwareRepoType) VerifyRepoParams(repo RepositoryConfigEntry) bool {
	switch malrepo {
	case NotSupported:
		return false
	case MalwareBazaar:
		if repo.Host != "" {
			return true
		}
	case ObjectiveSee:
		if repo.Host != "" {
			return true
		}
	case AssemblyLine:
		if repo.Host != "" && repo.Api != "" && repo.User != "" {
			return true
		}
	case UploadAssemblyLine:
		if repo.Host != "" && repo.Api != "" && repo.User != "" {
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
	var user string
	tls := false

	var default_url string

	switch malrepo {
	case NotSupported:
		return RepositoryConfigEntry{}, fmt.Errorf("malware repository rype, %s, is not supported", malrepo.String())
	case MalwareBazaar:
		default_url = "https://mb-api.abuse.ch/api/v1/"
	case Malshare:
		default_url = "https://malshare.com"
	case MWDB:
		default_url = "https://mwdb.cert.pl/api"
	case CapeSandbox:
		default_url = "https://www.capesandbox.com/apiv2"
	case JoeSandbox:
		default_url = "https://jbxcloud.joesecurity.org/api/v2"
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
	case ObjectiveSee:
		default_url = "https://objective-see.com/malware.json"
	case UnpacMe:
		default_url = "https://api.unpac.me/api/v1"
	case Malpedia:
		default_url = "https://malpedia.caad.fkie.fraunhofer.de/api"
	case VxShare:
		default_url = "https://virusshare.com/apiv2"
	case FileScanIo:
		default_url = "https://www.filescan.io/api"
	case URLScanIO:
		default_url = "https://urlscan.io/downloads"
	case VirusExchange:
		default_url = "https://virus.exchange/api"
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
	if malrepo == AssemblyLine || malrepo == UploadAssemblyLine {
		fmt.Println("Enter User Name:")
		fmt.Print(">> ")
		fmt.Scanln(&user)
		for {
			fmt.Println("Disable TLS Verification (true|false):")
			fmt.Print(">> ")
			var tlss string
			fmt.Scanln(&tlss)
			boolvalue, err := strconv.ParseBool(tlss)
			if err == nil {
				tls = boolvalue
				break
			}
			fmt.Println("Invalid option entered")
		}
	}
	if malrepo != MalwareBazaar && malrepo != ObjectiveSee {
		fmt.Println("Enter API Key:")
		fmt.Print(">> ")
		fmt.Scanln(&api)
	}
	return RepositoryConfigEntry{Host: host, User: user, Api: api, Type: malrepo.String(), IgnoreTLSErrors: tls}, nil
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
	case ObjectiveSee:
		return "ObjectiveSee"
	case UnpacMe:
		return "UnpacMe"
	case Malpedia:
		return "Malpedia"
	case VxShare:
		return "VxShare"
	case FileScanIo:
		return "FileScanIo"
	case URLScanIO:
		return "URLScanIO"
	case AssemblyLine:
		return "AssemblyLine"
	case UploadAssemblyLine:
		return "UploadAssemblyLine"
	case UploadMWDB:
		return "UploadMWDB"
	case VirusExchange:
		return "VirusExchange"
	}
	return "NotSupported"
}

func allowedMalwareRepoTypes() {
	for _, mr := range getMalwareRepoList() {
		fmt.Printf("    %s\n", mr.String())
	}
}

func printAllowedMalwareRepoTypeOptions() {
	fmt.Println("")
	for _, mr := range getMalwareRepoList() {
		fmt.Printf("  [%d]    %s\n", mr, mr.String())
	}
}

func queryAndDownloadAll(repos []RepositoryConfigEntry, hash Hash, doNotExtract bool, skipUpload bool, osq ObjectiveSeeQuery, doNotValidateHash bool, doNotValidateHashList []MalwareRepoType) (bool, string, MalwareRepoType) {
	found := false
	filename := ""
	checkedRepo := NotSupported
	sort.Slice(repos[:], func(i, j int) bool {
		return repos[i].QueryOrder < repos[j].QueryOrder
	})

	// Hack for now
	// Due to Multiple entries of the same type, for each type instance in the config it will
	// try to download for type the number of entries for type in config squared
	// This array is meant to ensure that for each type it will only try it once
	var completedTypes []MalwareRepoType

	for _, repo := range repos {
		if (repo.Type == UploadMWDB.String() || repo.Type == UploadAssemblyLine.String()) && skipUpload {
			continue
		}
		mr := getMalwareRepoByName(repo.Type)
		if !contains(completedTypes, mr) {
			found, filename, checkedRepo = mr.QueryAndDownload(repos, hash, doNotExtract, osq)
			if found {
				if !doNotValidateHash {
					if slices.Contains(doNotValidateHashList, checkedRepo) {
						if checkedRepo == ObjectiveSee {
							fmt.Printf("    [!] Not able to validate hash for repo %s\n", checkedRepo.String())
						} else {
							fmt.Printf("    [!] Not able to validate hash for repo %s when noextraction flag is set to %t\n", checkedRepo.String(), doNotExtractFlag)
						}
						break
					} else {
						valid, calculatedHash := hash.ValidateFile(filename)
						if !valid {
							fmt.Printf("    [!] Downloaded file hash %s\n        does not match searched for hash %s\nTrying another source.\n", calculatedHash, hash.Hash)
							deleteInvalidFile(filename)
							continue
						} else {
							fmt.Printf("    [+] Downloaded file %s validated as the requested hash\n", hash.Hash)
							break
						}
					}
				}
				break
			}
			completedTypes = append(completedTypes, mr)
		}
	}
	return found, filename, checkedRepo
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
	case strings.ToLower("os"):
		return ObjectiveSee
	case strings.ToLower("um"):
		return UnpacMe
	case strings.ToLower("mp"):
		return Malpedia
	case strings.ToLower("vx"):
		return VxShare
	case strings.ToLower("fs"):
		return FileScanIo
	case strings.ToLower("us"):
		return URLScanIO
	case strings.ToLower("al"):
		return AssemblyLine
	case strings.ToLower("ve"):
		return VirusExchange
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
	case strings.ToLower("ObjectiveSee"):
		return ObjectiveSee
	case strings.ToLower("UnpacMe"):
		return UnpacMe
	case strings.ToLower("Malpedia"):
		return Malpedia
	case strings.ToLower("VxShare"):
		return VxShare
	case strings.ToLower("FileScanIo"):
		return FileScanIo
	case strings.ToLower("URLScanIO"):
		return URLScanIO
	case strings.ToLower("AssemblyLine"):
		return AssemblyLine
	case strings.ToLower("UploadAssemblyLine"):
		return UploadAssemblyLine
	case strings.ToLower("UploadMWDB"):
		return UploadMWDB
	case strings.ToLower("VirusExchange"):
		return VirusExchange
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
	Type            string `yaml:"type"`
	Host            string `yaml:"url"`
	Api             string `yaml:"api"`
	QueryOrder      int    `yaml:"queryorder"`
	Password        string `yaml:"pwd"`
	User            string `yaml:"user"`
	IgnoreTLSErrors bool   `yaml:"ignoretlserrors"`
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

	for k, v := range repos {
		mr := getMalwareRepoByName(v.Type)
		if mr == NotSupported {
			fmt.Printf("%s is not a supported type.  Skipping...\n\nSupported types include:\n", v.Type)
			allowedMalwareRepoTypes()
			fmt.Println("")
		} else {
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

	f, err := os.ReadFile(path)
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

func contains(list []MalwareRepoType, x MalwareRepoType) bool {
	for _, item := range list {
		if item == x {
			return true
		}
	}
	return false
}
