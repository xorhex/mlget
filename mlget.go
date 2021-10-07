package main

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"mime/multipart"
	"net/http"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	flag "github.com/spf13/pflag"

	"github.com/yeka/zip"
	"gopkg.in/yaml.v2"
)

type Config struct {
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

type JoeSandboxQuery struct {
	Data []JoeSandboxQueryData `'json:"data"`
}

type JoeSandboxQueryData struct {
	Webid string `json:"webid"`
}

type InquestLabs struct {
	Data *InquestLabsQueryData `json:"data"`
}

type InquestLabsQueryData struct {
	Sha256 string `json:"sha256"`
}

type HybridAnalysis struct {
	Submit_name string `json:"submit_name"`
	Md5         string `json:"md5"`
	Sha1        string `json:"sha1"`
	Sha256      string `json:"sha256"`
	Sha512      string `json:"sha512"`
}

type MalwareBazarQuery struct {
	Data *MalwareBazarQueryData `json:"data"`
}

type MalwareBazarQueryData struct {
	Sha256_hash   string `json:"sha256_hash"`
	Sha3_384_hash string `json:"sha3_384_hash"`
	Sha1_hash     string `json:"sha1_hash"`
	Md5_hash      string `json:"md5_hash"`
	File_name     string `json:"file_name"`
}

type TriageQuery struct {
	Data []TriageQueryData `json:"data"`
}

type TriageQueryData struct {
	Id       string `json:"id"`
	Kind     string `json:"kind"`
	Filename string `json:"filename"`
}

type CommentItemResponse struct {
	Author    string `json:"author"`
	Comment   string `json:"comment"`
	Id        int32  `json:"id"`
	Timestamp string `json:"timestamp"`
}

type Hashes struct {
	Hashes []Hash
}

func AddHash(hashes Hashes, hash Hash) (Hashes, error) {
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

type Hash struct {
	Hash     string
	HashType string
	Tags     []string
	Comments []string
}

func (h Hash) TagExists(tag string) bool {
	for _, t := range h.Tags {
		if t == tag {
			return true
		}
	}
	return false
}

var apiFlag string
var helpFlag bool
var checkConfFlag bool
var doNotExtractFlag bool
var inputFileFlag string
var outputFileFlag bool
var uploadToMWDBAndDelete bool
var downloadOnlyFlag bool
var uploadToMWDB bool
var readFromFileAndUpdateWithNotFoundHashes string
var tagsFlag []string
var commentsFlag []string

func usage() {
	fmt.Println("mlget - A command line tool to download malware from a variety of sources")
	fmt.Println("")

	fmt.Printf("Usage: %s [OPTIONS] hash_arguments...\n", os.Args[0])
	flag.PrintDefaults()

	fmt.Println("")
	fmt.Println("Example Usage: mlget <sha256>")
	fmt.Println("Example Usage: mlget --from mb <sha256>")
	fmt.Println("Example Usage: mlget --tag tag_one --tag tag_two --uploaddelete <sha256> <sha1> <md5>")
}

func init() {
	flag.StringVar(&apiFlag, "from", "", "The service to download the malware from.\n  Must be one of:\n  - tg (Triage)\n  - mb (Malware Bazaar)\n  - ms (Malshare)\n  - ha (HybirdAnlysis)\n  - vt (VirusTotal)\n  - cp (Cape Sandbox)\n  - mw (Malware Database)\n  - ps (PolySwarm)\n  - iq (InquestLabs)\n  -js (JoeSandbox)\nIf omitted, all services will be tried.")
	flag.StringVar(&inputFileFlag, "read", "", "Read in a file of hashes (one per line)")
	flag.BoolVar(&outputFileFlag, "output", false, "Write to a file the hashes not found (for later use with the --read flag)")
	flag.BoolVar(&helpFlag, "help", false, "Print the help message")
	flag.BoolVar(&checkConfFlag, "config", false, "Parse and print the config file")
	flag.BoolVar(&doNotExtractFlag, "noextraction", false, "Do not extract malware from archive file.\nCurrently this only effects MalwareBazaar and HybridAnalysis")
	flag.BoolVar(&uploadToMWDB, "upload", false, "Upload downloaded files to the MWDB instance specified in the mlget.yml file.")
	flag.StringVar(&readFromFileAndUpdateWithNotFoundHashes, "readupdate", "", "Read hashes from file to download.  Replace entries in the file with just the hashes that were not found (for next time).")
	flag.BoolVar(&uploadToMWDBAndDelete, "uploaddelete", false, "Upload downloaded files to the MWDB instance specified in the mlget.yml file.\nDelete the files after successful upload")
	flag.StringSliceVar(&tagsFlag, "tag", []string{}, "Tag the sample when uploading to your own instance of MWDB.")
	flag.StringSliceVar(&commentsFlag, "comment", []string{}, "Add comment to the sample when uploading to your own instance of MWDB.")
	flag.BoolVar(&downloadOnlyFlag, "downloadonly", false, "Download from any source, including your personal instance of MWDB.\nWhen this flag is set; it will NOT update any output file with the hashes not found.")
}

func main() {
	home, err := os.UserHomeDir()
	if err != nil {
		fmt.Println(err)
		return
	}

	var cfg Config
	parseFile(path.Join(home, ".mlget.yml"), &cfg)

	flag.Parse()

	if helpFlag {
		usage()
		return
	}

	if checkConfFlag {
		fmt.Printf("%+v", cfg)

		return
	}

	args := flag.Args()

	if apiFlag != "" && downloadOnlyFlag {
		fmt.Printf(("Can't use both the --from flag and the --downloadonly flag together"))
		return
	}

	hashes := parseArgHashes(args, tagsFlag, commentsFlag)

	if inputFileFlag != "" {
		hshs, err := parseFileForHashEntries(inputFileFlag)
		if err != nil {
			fmt.Printf("Error reading from %s\n", inputFileFlag)
			fmt.Println(err)
		} else {
			for _, hsh := range hshs {
				hashes, _ = AddHash(hashes, hsh)
			}
		}
	} else if readFromFileAndUpdateWithNotFoundHashes != "" {
		hshs, err := parseFileForHashEntries(readFromFileAndUpdateWithNotFoundHashes)
		if err != nil {
			fmt.Printf("Error reading from %s\n", readFromFileAndUpdateWithNotFoundHashes)
			fmt.Println(err)
		} else {
			for _, hsh := range hshs {
				hashes, _ = AddHash(hashes, hsh)
			}
		}
	}

	var notFoundHashes Hashes

	if len(hashes.Hashes) == 0 {
		fmt.Println("No hashes found")
		usage()
		return
	}

	for _, h := range hashes.Hashes {
		fmt.Printf("\nLook up %s (%s)\n", h.Hash, h.HashType)

		var filename string
		var found bool

		// If upload to MWDB is filled out, check and see if the hash has already been uploaded
		alreadyUploaded := preUploadToMWDB(cfg.UploadToMWDBOption.Host, cfg.UploadToMWDBOption.ApiKey, h.Hash)
		// If found, then skip trying to download it.
		if alreadyUploaded && !downloadOnlyFlag {
			if len(h.Tags) == 0 && len(h.Comments) == 0 {
				fmt.Printf("  [!] Skipping %s\n", h)
			} else {
				if len(h.Tags) > 0 {
					// Add Tags
					addTagsToSampleInMWDB(h, cfg.UploadToMWDBOption.Host, cfg.UploadToMWDBOption.ApiKey)
				}
				if len(h.Comments) > 0 {
					// Add Comments
					addCommentsToSampleInMWDB(h, cfg.UploadToMWDBOption.Host, cfg.UploadToMWDBOption.ApiKey)
				}
			}
			continue
		} else if downloadOnlyFlag {
			found, filename = mwdb(cfg.UploadToMWDBOption.Host, cfg.UploadToMWDBOption.ApiKey, h)
			if !found {
				fmt.Println("    [!] Not Found")
				notFoundHashes, _ = AddHash(notFoundHashes, h)
			}
		}

		if apiFlag != "" {
			fmt.Printf("Looking on %s\n", apiFlag)
			switch apiFlag {
			case "mb":
				found, filename = malwareBazaar(cfg.MalwareBazar.Host, h, doNotExtractFlag)
				if !found {
					fmt.Println("    [!] Not Found")
					notFoundHashes, _ = AddHash(notFoundHashes, h)
				}
			case "ms":
				found, filename = malshare(cfg.MalShare.Host, cfg.MalShare.ApiKey, h)
				if !found {
					fmt.Println("    [!] Not Found")
					notFoundHashes, _ = AddHash(notFoundHashes, h)
				}
			case "tg":
				found, filename = traige(cfg.Triage.Host, cfg.Triage.ApiKey, h)
				if !found {
					fmt.Println("    [!] Not Found")
					notFoundHashes, _ = AddHash(notFoundHashes, h)
				}
			case "ha":
				found, filename = hybridAnlysis(cfg.HybridAnalysis.Host, cfg.HybridAnalysis.ApiKey, h, doNotExtractFlag)
				if !found {
					fmt.Println("    [!] Not Found")
					notFoundHashes, _ = AddHash(notFoundHashes, h)
				}
			case "ps":
				found, filename = polyswarm(cfg.PolySwarm.Host, cfg.PolySwarm.ApiKey, h)
				if !found {
					fmt.Println("    [!] Not Found")
					notFoundHashes, _ = AddHash(notFoundHashes, h)
				}
			case "mw":
				found, filename = mwdb(cfg.MWDB.Host, cfg.MWDB.ApiKey, h)
				if !found {
					fmt.Println("    [!] Not Found")
					notFoundHashes, _ = AddHash(notFoundHashes, h)
				}
			case "vt":
				found, filename = virustotal(cfg.VT.Host, cfg.VT.ApiKey, h)
				if !found {
					fmt.Println("    [!] Not Found")
					notFoundHashes, _ = AddHash(notFoundHashes, h)
				}
			case "js":
				found, filename = joesandbox(cfg.JoeSandbox.Host, cfg.JoeSandbox.ApiKey, h)
				if !found {
					fmt.Println("    [!] Not Found")
					notFoundHashes, _ = AddHash(notFoundHashes, h)
				}
			case "iq":
				found, filename = inquestlabs(cfg.InquestLabs.Host, cfg.InquestLabs.ApiKey, h)
				if !found {
					fmt.Println("    [!] Not Found")
					notFoundHashes, _ = AddHash(notFoundHashes, h)
				}
			case "cp":
				found, filename = capesandbox(cfg.CapeSandbox.Host, cfg.CapeSandbox.ApiKey, h)
				if !found {
					fmt.Println("    [!] Not Found")
					notFoundHashes, _ = AddHash(notFoundHashes, h)
				}
			}
			if uploadToMWDB || uploadToMWDBAndDelete {
				err := uploadSampleToMWDB(filename, h, uploadToMWDBAndDelete, cfg.UploadToMWDBOption.Host, cfg.UploadToMWDBOption.ApiKey)
				if err != nil {
					fmt.Printf("    [!] %s", err)
				}
			}
		} else {
			fmt.Println("Querying all services")

			fmt.Println("  [*] MalwareBazaar...")
			found, filename = malwareBazaar(cfg.MalwareBazar.Host, h, doNotExtractFlag)
			if found {
				if (uploadToMWDB || uploadToMWDBAndDelete) && !downloadOnlyFlag {
					err := uploadSampleToMWDB(filename, h, uploadToMWDBAndDelete, cfg.UploadToMWDBOption.Host, cfg.UploadToMWDBOption.ApiKey)
					if err != nil {
						fmt.Printf("    [!] %s", err)
					}
				}
				continue
			}

			fmt.Println("  [*] MWDB...")
			found, filename = mwdb(cfg.MWDB.Host, cfg.MalShare.ApiKey, h)
			if found {
				if (uploadToMWDB || uploadToMWDBAndDelete) && !downloadOnlyFlag {
					err := uploadSampleToMWDB(filename, h, uploadToMWDBAndDelete, cfg.UploadToMWDBOption.Host, cfg.UploadToMWDBOption.ApiKey)
					if err != nil {
						fmt.Printf("    [!] %s", err)
					}
				}
				continue
			}

			fmt.Println("  [*] Cape Sandbox...")
			found, filename = capesandbox(cfg.CapeSandbox.Host, cfg.CapeSandbox.ApiKey, h)
			if found {
				if (uploadToMWDB || uploadToMWDBAndDelete) && !downloadOnlyFlag {
					err := uploadSampleToMWDB(filename, h, uploadToMWDBAndDelete, cfg.UploadToMWDBOption.Host, cfg.UploadToMWDBOption.ApiKey)
					if err != nil {
						fmt.Printf("    [!] %s", err)
					}
				}
				continue
			}

			fmt.Println("  [*] MalShare...")
			found, filename = malshare(cfg.MalShare.Host, cfg.MalShare.ApiKey, h)
			if found {
				if (uploadToMWDB || uploadToMWDBAndDelete) && !downloadOnlyFlag {
					err := uploadSampleToMWDB(filename, h, uploadToMWDBAndDelete, cfg.UploadToMWDBOption.Host, cfg.UploadToMWDBOption.ApiKey)
					if err != nil {
						fmt.Printf("    [!] %s", err)
					}
				}
				continue
			}

			fmt.Println("  [*] Triage...")
			found, filename = traige(cfg.Triage.Host, cfg.Triage.ApiKey, h)
			if found {
				if (uploadToMWDB || uploadToMWDBAndDelete) && !downloadOnlyFlag {
					err := uploadSampleToMWDB(filename, h, uploadToMWDBAndDelete, cfg.UploadToMWDBOption.Host, cfg.UploadToMWDBOption.ApiKey)
					if err != nil {
						fmt.Printf("    [!] %s", err)
					}
				}
				continue
			}

			fmt.Println("  [*] Hybrid Analysis...")
			found, filename = hybridAnlysis(cfg.HybridAnalysis.Host, cfg.HybridAnalysis.ApiKey, h, doNotExtractFlag)
			if found {
				if (uploadToMWDB || uploadToMWDBAndDelete) && !downloadOnlyFlag {
					err := uploadSampleToMWDB(filename, h, uploadToMWDBAndDelete, cfg.UploadToMWDBOption.Host, cfg.UploadToMWDBOption.ApiKey)
					if err != nil {
						fmt.Printf("    [!] %s", err)
					}
				}
				continue
			}

			fmt.Println("  [*] InquestLabs...")
			found, filename = inquestlabs(cfg.InquestLabs.Host, cfg.InquestLabs.ApiKey, h)
			if found {
				if (uploadToMWDB || uploadToMWDBAndDelete) && !downloadOnlyFlag {
					err := uploadSampleToMWDB(filename, h, uploadToMWDBAndDelete, cfg.UploadToMWDBOption.Host, cfg.UploadToMWDBOption.ApiKey)
					if err != nil {
						fmt.Printf("    [!] %s", err)
					}
				}
				continue
			}

			fmt.Println("  [*] Joe Sandbox...")
			found, filename = joesandbox(cfg.JoeSandbox.Host, cfg.JoeSandbox.ApiKey, h)
			if found {
				if (uploadToMWDB || uploadToMWDBAndDelete) && !downloadOnlyFlag {
					err := uploadSampleToMWDB(filename, h, uploadToMWDBAndDelete, cfg.UploadToMWDBOption.Host, cfg.UploadToMWDBOption.ApiKey)
					if err != nil {
						fmt.Printf("    [!] %s", err)
					}
				}
				continue
			}

			fmt.Println("  [*] VirusTotal...")
			found, filename = virustotal(cfg.VT.Host, cfg.VT.ApiKey, h)
			if found {
				if (uploadToMWDB || uploadToMWDBAndDelete) && !downloadOnlyFlag {
					err := uploadSampleToMWDB(filename, h, uploadToMWDBAndDelete, cfg.UploadToMWDBOption.Host, cfg.UploadToMWDBOption.ApiKey)
					if err != nil {
						fmt.Printf("    [!] %s", err)
					}
				}
				continue
			}

			fmt.Println("  [*] PolySwarm...")
			found, filename = polyswarm(cfg.PolySwarm.Host, cfg.PolySwarm.ApiKey, h)
			if found {
				if (uploadToMWDB || uploadToMWDBAndDelete) && !downloadOnlyFlag {
					err := uploadSampleToMWDB(filename, h, uploadToMWDBAndDelete, cfg.UploadToMWDBOption.Host, cfg.UploadToMWDBOption.ApiKey)
					if err != nil {
						fmt.Printf("    [!] %s", err)
					}
				}
				continue
			}

			notFoundHashes, _ = AddHash(notFoundHashes, h)
		}
	}

	if len(notFoundHashes.Hashes) > 0 {
		fmt.Printf("\nHashes not found!\n")
		for i, s := range notFoundHashes.Hashes {
			fmt.Printf("    %d: %s\n", i, s)
		}
	}
	if !downloadOnlyFlag {
		if readFromFileAndUpdateWithNotFoundHashes != "" {
			err := writeUnfoundHashesToFile(readFromFileAndUpdateWithNotFoundHashes, notFoundHashes)
			if err != nil {
				fmt.Println("Error writing unfound hashes to file")
				fmt.Println(err)
			}
			fmt.Printf("\n\n%s refreshed to show only the hashes not found.\n", readFromFileAndUpdateWithNotFoundHashes)

		} else if outputFileFlag && len(notFoundHashes.Hashes) > 0 {
			var filename string
			if inputFileFlag != "" {
				filename = time.Now().Format("2006-01-02__3_4_5__pm__") + inputFileFlag
			} else {
				filename = time.Now().Format("2006-01-02__3_4_5__pm") + "_not_found_hashes.txt"
			}
			err := writeUnfoundHashesToFile(filename, notFoundHashes)
			if err != nil {
				fmt.Println("Error writing unfound hashes to file")
				fmt.Println(err)
			}
			fmt.Printf("\n\nUnfound hashes written to %s\n", filename)
		}
	}
}

func joesandbox(uri string, api string, hash Hash) (bool, string) {
	if api == "" {
		fmt.Println("    [!] !! Missing Key !!")
		return false, ""
	}

	fmt.Printf("    [-] Looking up sandbox ID for: %s\n", hash.Hash)

	query := uri + "/v2/analysis/search"

	_, error := url.ParseRequestURI(query)
	if error != nil {
		fmt.Printf("    [!] Error when parsing the query uri (%s).  Check the value in the config file.\n", query)
		fmt.Println(error)
		return false, ""
	}

	queryData := "q=" + hash.Hash + "&" + "apikey=" + api
	values, error := url.ParseQuery(queryData)
	if error != nil {
		fmt.Printf("    [!] Error when parsing the query data (%s).\n", queryData)
		fmt.Println(error)
		return false, ""
	}

	client := &http.Client{}
	response, error := client.PostForm(query, values)
	if error != nil {
		fmt.Println(error)
		return false, ""
	}

	defer response.Body.Close()

	if response.StatusCode == http.StatusOK {

		byteValue, error := ioutil.ReadAll(response.Body)
		if error != nil {
			fmt.Println(error)
			return false, ""
		}

		var data = JoeSandboxQuery{}
		error = json.Unmarshal(byteValue, &data)

		if error != nil {
			fmt.Println(error)
			return false, ""
		}

		if len(data.Data) > 0 {
			sandboxid := data.Data[0].Webid
			fmt.Printf("    [-] Hash %s Sandbox ID: %s\n", hash.Hash, sandboxid)

			// Download Sample using Sample ID
			return joesandboxDownload(uri, api, sandboxid, hash)
		} else {
			return false, ""
		}
	} else if response.StatusCode == http.StatusForbidden {
		fmt.Printf("    [!] Not authorized.  Check the URL in the config.\n        JoeSandbox does have more than one API endpoint.\n        Check your documentation.\n")
		return false, ""
	} else {
		return false, ""
	}

}

func joesandboxDownload(uri string, api string, sandboxid string, hash Hash) (bool, string) {
	query := uri + "/v2/analysis/download"

	_, error := url.ParseRequestURI(query)
	if error != nil {
		fmt.Printf("    [!] Error when parsing the query uri (%s).  Check the value in the config file.\n", query)
		fmt.Println(error)
		return false, ""
	}

	queryData := "webid=" + sandboxid + "&" + "apikey=" + api + "&" + "type=sample"
	values, error := url.ParseQuery(queryData)
	if error != nil {
		fmt.Printf("    [!] Error when parsing the query data (%s).\n", queryData)
		fmt.Println(error)
		return false, ""
	}

	client := &http.Client{}
	response, error := client.PostForm(query, values)
	if error != nil {
		fmt.Println(error)
		return false, ""
	}

	defer response.Body.Close()

	if response.StatusCode == http.StatusOK {
		error = writeToFile(response.Body, hash.Hash)
		if error != nil {
			fmt.Println(error)
			return false, ""
		}
		fmt.Printf("    [+] Downloaded %s\n", hash.Hash)
		return true, hash.Hash
	} else {
		return false, hash.Hash
	}
}

func capesandbox(uri string, api string, hash Hash) (bool, string) {
	if api == "" {
		fmt.Println("    [!] !! Missing Key !!")
		return false, ""
	}
	return capesandboxDownload(uri, api, hash)
}

func capesandboxDownload(uri string, api string, hash Hash) (bool, string) {
	query := uri + "/files/get/" + url.QueryEscape(hash.HashType) + "/" + url.QueryEscape(hash.Hash) + "/"

	request, err := http.NewRequest("GET", query, nil)
	if err != nil {
		fmt.Println(err)
		return false, ""
	}

	request.Header.Set("Authorization", "Token "+api)
	client := &http.Client{}
	response, error := client.Do(request)
	if error != nil {
		fmt.Println(error)
		return false, ""
	}
	defer response.Body.Close()

	if response.StatusCode == http.StatusOK {

		if response.Header["Content-Type"][0] == "application/json" {
			return false, ""
		}

		error = writeToFile(response.Body, hash.Hash)
		if error != nil {
			fmt.Println(error)
			return false, ""
		}
		fmt.Printf("    [+] Downloaded %s\n", hash.Hash)
		return true, hash.Hash
	} else if response.StatusCode == http.StatusForbidden {
		fmt.Printf("    [!] Not authorized.  Check the URL and APIKey in the config.\n")
		return false, ""
	} else {
		return false, ""
	}
}

func inquestlabs(uri string, api string, hash Hash) (bool, string) {
	if api == "" {
		fmt.Println("    [!] !! Missing Key !!")
		return false, ""
	}

	if hash.HashType != "sha256" {
		fmt.Printf("    [-] Looking up sha256 hash for %s\n", hash.Hash)

		query := uri + "/dfi/search/hash/" + url.PathEscape(hash.HashType) + "?hash=" + url.QueryEscape(hash.Hash)

		_, error := url.ParseQuery(query)
		if error != nil {
			fmt.Println("    [!] Issue creating hash lookup query url")
			fmt.Println(error)
			return false, ""
		}

		request, err := http.NewRequest("GET", query, nil)
		if err != nil {
			fmt.Println(err)
			return false, ""
		}

		client := &http.Client{}
		response, error := client.Do(request)
		if error != nil {
			fmt.Println(error)
			return false, ""
		}
		defer response.Body.Close()

		if response.StatusCode == http.StatusOK {

			byteValue, _ := ioutil.ReadAll(response.Body)

			var data = HybridAnalysis{}
			error = json.Unmarshal(byteValue, &data)

			if error != nil {
				fmt.Println(error)
				return false, ""
			}

			if data.Sha256 == "" {
				return false, ""
			}
			hash.HashType = "sha256"
			hash.Hash = data.Sha256
			fmt.Printf("    [-] Using hash %s\n", hash.Hash)

		} else if response.StatusCode == http.StatusForbidden {
			fmt.Printf("    [!] Not authorized.  Check the URL and APIKey in the config.\n")
			return false, ""
		}
	}

	if hash.HashType == "sha256" {
		return inquestlabsDownload(uri, api, hash)
	}
	return false, ""
}

func inquestlabsDownload(uri string, api string, hash Hash) (bool, string) {
	query := uri + "/dfi/download?sha256=" + url.QueryEscape(hash.Hash)

	_, error := url.ParseQuery(query)
	if error != nil {
		fmt.Println(error)
		return false, ""
	}

	request, err := http.NewRequest("GET", query, nil)
	if err != nil {
		fmt.Println(err)
		return false, ""
	}

	request.Header.Set("Authorization", api)
	client := &http.Client{}
	response, error := client.Do(request)
	if error != nil {
		fmt.Println(error)
		return false, ""
	}
	defer response.Body.Close()

	if response.StatusCode == http.StatusOK {

		error = writeToFile(response.Body, hash.Hash)
		if error != nil {
			fmt.Println(error)
			return false, ""
		}
		fmt.Printf("    [+] Downloaded %s\n", hash.Hash)
		return true, hash.Hash
	} else if response.StatusCode == http.StatusForbidden {
		fmt.Printf("    [!] Not authorized.  Check the URL and APIKey in the config.\n")
		return false, ""
	} else {
		return false, ""
	}
}

func virustotal(uri string, api string, hash Hash) (bool, string) {
	if api == "" {
		fmt.Println("    [!] !! Missing Key !!")
		return false, ""
	}
	return virustotalDownload(uri, api, hash)
}

func virustotalDownload(uri string, api string, hash Hash) (bool, string) {
	query := uri + "/files/" + url.PathEscape(hash.Hash) + "/download"

	request, err := http.NewRequest("GET", query, nil)
	if err != nil {
		fmt.Println(err)
		return false, ""
	}

	request.Header.Set("x-apikey", api)
	client := &http.Client{}
	response, error := client.Do(request)
	if error != nil {
		fmt.Println(error)
		return false, ""
	}
	defer response.Body.Close()

	if response.StatusCode == http.StatusOK {

		error = writeToFile(response.Body, hash.Hash)
		if error != nil {
			fmt.Println(error)
			return false, ""
		}
		fmt.Printf("    [+] Downloaded %s\n", hash.Hash)
		return true, hash.Hash
	} else if response.StatusCode == http.StatusForbidden {
		fmt.Printf("    [!] Not authorized.  Check the URL and APIKey in the config.\n")
		return false, ""
	} else {
		return false, ""
	}
}

func mwdb(uri string, api string, hash Hash) (bool, string) {
	if api == "" {
		fmt.Println("    [!] !! Missing Key !!")
		return false, ""
	}
	return mwdbDownload(uri, api, hash)
}

func mwdbDownload(uri string, api string, hash Hash) (bool, string) {
	query := uri + "/file/" + url.PathEscape(hash.Hash) + "/download"

	request, err := http.NewRequest("GET", query, nil)
	if err != nil {
		fmt.Println(err)
		return false, ""
	}

	request.Header.Set("Authorization", "Bearer "+api)
	client := &http.Client{}
	response, error := client.Do(request)
	if error != nil {
		fmt.Println(error)
		return false, ""
	}
	defer response.Body.Close()

	if response.StatusCode == http.StatusOK {

		error = writeToFile(response.Body, hash.Hash)
		if error != nil {
			fmt.Println(error)
			return false, ""
		}
		fmt.Printf("    [+] Downloaded %s\n", hash.Hash)
		return true, hash.Hash
	} else if response.StatusCode == http.StatusForbidden {
		fmt.Printf("    [!] Not authorized.  Check the URL and APIKey in the config.\n")
		return false, ""
	} else {
		return false, ""
	}
}

func polyswarm(uri string, api string, hash Hash) (bool, string) {
	if api == "" {
		fmt.Println("    [!] !! Missing Key !!")
		return false, ""
	}
	return polyswarmDownload(uri, api, hash)
}

func polyswarmDownload(uri string, api string, hash Hash) (bool, string) {
	query := "/download/" + url.PathEscape(hash.HashType) + "/" + url.PathEscape(hash.Hash)

	_, error := url.ParseQuery(query)
	if error != nil {
		fmt.Println(error)
		return false, ""
	}

	request, err := http.NewRequest("GET", uri+query, nil)
	if err != nil {
		fmt.Println(err)
		return false, ""
	}

	request.Header.Set("Authorization", api)
	client := &http.Client{}
	response, error := client.Do(request)
	if error != nil {
		fmt.Println(error)
		return false, ""
	}
	defer response.Body.Close()

	if response.StatusCode == http.StatusOK {

		error = writeToFile(response.Body, hash.Hash)
		if error != nil {
			fmt.Println(error)
			return false, ""
		}
		fmt.Printf("    [+] Downloaded %s\n", hash.Hash)
		return true, hash.Hash
	} else if response.StatusCode == http.StatusForbidden {
		fmt.Printf("    [!] Not authorized.  Check the URL and APIKey in the config.\n")
		return false, ""
	} else {
		return false, ""
	}
}

func hybridAnlysis(uri string, api string, hash Hash, doNotExtract bool) (bool, string) {
	if api == "" {
		fmt.Println("    [!] !! Missing Key !!")
		return false, ""
	}

	if hash.HashType != "sha256" {
		fmt.Printf("    [-] Looking up sha256 hash for %s\n", hash.Hash)

		pData := []byte("hash=" + hash.Hash)
		request, error := http.NewRequest("POST", uri+"/search/hash", bytes.NewBuffer(pData))

		if error != nil {
			fmt.Println(error)
			return false, ""
		}

		request.Header.Set("Content-Type", "application/json; charset=UTF-8")
		request.Header.Set("user-agent", "Falcon Sandbox")
		request.Header.Set("api-key", api)
		client := &http.Client{}
		response, error := client.Do(request)
		if error != nil {
			fmt.Println(error)
			return false, ""
		}
		defer response.Body.Close()

		if response.StatusCode == http.StatusForbidden {
			fmt.Printf("    [!] Not authorized.  Check the URL and APIKey in the config.\n")
			return false, ""
		}
		byteValue, _ := ioutil.ReadAll(response.Body)

		var data = HybridAnalysis{}
		error = json.Unmarshal(byteValue, &data)

		if error != nil {
			fmt.Println(error)
			return false, ""
		}

		if data.Sha256 == "" {
			return false, ""
		}
		hash.Hash = data.Sha256
		hash.HashType = "sha256"
		fmt.Printf("    [-] Using hash %s\n", hash.Hash)

	}

	if hash.HashType == "sha256" {
		return hybridAnlysisDownload(uri, api, hash, doNotExtract)
	}
	return false, ""
}

func hybridAnlysisDownload(uri string, api string, hash Hash, extract bool) (bool, string) {
	request, error := http.NewRequest("GET", uri+"/overview/"+url.PathEscape(hash.Hash)+"/sample", nil)

	request.Header.Set("accept", "application/gzip")
	request.Header.Set("user-agent", "Falcon Sandbox")
	request.Header.Set("api-key", api)

	if error != nil {
		fmt.Println(error)
		return false, ""
	}
	client := &http.Client{}
	response, error := client.Do(request)
	if error != nil {
		fmt.Println(error)
		return false, ""
	}
	defer response.Body.Close()

	if response.StatusCode == http.StatusForbidden {
		fmt.Printf("    [!] Not authorized.  Check the URL and APIKey in the config.\n")
		return false, ""
	} else if response.StatusCode != http.StatusOK {
		return false, ""
	}

	error = writeToFile(response.Body, hash.Hash+".gzip")
	if error != nil {
		fmt.Println(error)
		return false, ""
	}
	if doNotExtractFlag {
		fmt.Printf("    [+] Downloaded %s\n", hash.Hash+".gzip")
		return true, hash.Hash + ".gzip"
	} else {
		fmt.Println("    [-] Extracting...")
		err := extractGzip(hash.Hash)
		if err != nil {
			fmt.Println(error)
			return false, ""
		} else {
			fmt.Printf("    [-] Extracted %s\n", hash.Hash)
		}
		os.Remove(hash.Hash + ".gzip")
		fmt.Printf("    [+] Downloaded %s\n", hash.Hash)
		return true, hash.Hash

	}
}

func traige(uri string, api string, hash Hash) (bool, string) {
	if api == "" {
		fmt.Println("    [!] !! Missing Key !!")
		return false, ""
	}

	// Look up hash to get Sample ID
	query := "query=" + url.QueryEscape(hash.HashType) + ":" + url.QueryEscape(hash.Hash)
	_, error := url.ParseQuery(query)
	if error != nil {
		fmt.Println(error)
		return false, ""
	}
	request, error := http.NewRequest("GET", uri+"/search?"+query, nil)
	if error != nil {
		fmt.Println(error)
		return false, ""
	}

	request.Header.Set("Authorization", "Bearer "+api)

	client := &http.Client{}
	response, error := client.Do(request)
	if error != nil {
		fmt.Println(error)
		return false, ""
	}
	defer response.Body.Close()

	if response.StatusCode == http.StatusOK {

		byteValue, error := ioutil.ReadAll(response.Body)
		if error != nil {
			fmt.Println(error)
			return false, ""
		}

		var data = TriageQuery{}
		error = json.Unmarshal(byteValue, &data)

		if error != nil {
			fmt.Println(error)
			return false, ""
		}

		if len(data.Data) > 0 {
			sampleId := data.Data[0].Id
			fmt.Printf("    [-] Hash %s Sample ID: %s\n", hash.Hash, sampleId)

			// Download Sample using Sample ID
			return traigeDownload(uri, api, sampleId, hash)
		} else {
			return false, ""
		}
	} else if response.StatusCode == http.StatusForbidden {
		fmt.Printf("    [!] Not authorized.  Check the URL and APIKey in the config.\n")
		return false, ""
	} else {
		return false, ""
	}
}

func traigeDownload(uri string, api string, sampleId string, hash Hash) (bool, string) {
	request, error := http.NewRequest("GET", uri+"/samples/"+url.PathEscape(sampleId)+"/sample", nil)
	if error != nil {
		fmt.Println(error)
		return false, ""
	}

	request.Header.Set("Authorization", "Bearer "+api)

	client := &http.Client{}
	response, error := client.Do(request)
	if error != nil {
		fmt.Println(error)
		return false, ""
	}

	defer response.Body.Close()

	error = writeToFile(response.Body, hash.Hash)
	if error != nil {
		fmt.Println(error)
		return false, ""
	}
	fmt.Printf("    [+] Downloaded %s\n", hash.Hash)
	return true, hash.Hash
}

func malshare(url string, api string, hash Hash) (bool, string) {
	if api == "" {
		fmt.Println("    [!] !! Missing Key !!")
		return false, ""
	}

	return malshareDownload(url, api, hash)
}

func malshareDownload(uri string, api string, hash Hash) (bool, string) {
	query := "api_key=" + url.QueryEscape(api) + "&action=getfile&hash=" + url.QueryEscape(hash.Hash)

	_, error := url.ParseQuery(query)
	if error != nil {
		fmt.Println(error)
		return false, ""
	}

	client := &http.Client{}
	response, error := client.Get(uri + "/api.php?" + query)
	if error != nil {
		fmt.Println(error)
		return false, ""
	}
	defer response.Body.Close()

	if response.StatusCode == http.StatusOK {

		error = writeToFile(response.Body, hash.Hash)
		if error != nil {
			fmt.Println(error)
			return false, ""
		}
		fmt.Printf("    [+] Downloaded %s\n", hash)
		return true, hash.Hash
	} else if response.StatusCode == http.StatusForbidden {
		fmt.Printf("    [!] Not authorized.  Check the URL and APIKey in the config.\n")
		return false, ""
	} else {
		return false, ""
	}
}

func malwareBazaar(url string, hash Hash, doNotExtract bool) (bool, string) {
	if hash.HashType != "sha256" {
		fmt.Printf("    [-] Looking up sha256 hash for %s\n", hash.Hash)

		pData := []byte("query=get_info&hash=" + hash.Hash)
		request, error := http.NewRequest("POST", url, bytes.NewBuffer(pData))

		if error != nil {
			fmt.Println(error)
			return false, ""
		}

		request.Header.Set("Content-Type", "application/json; charset=UTF-8")
		client := &http.Client{}
		response, error := client.Do(request)
		if error != nil {
			fmt.Println(error)
			return false, ""
		}
		defer response.Body.Close()

		if response.StatusCode == http.StatusForbidden {
			fmt.Printf("    [!] Not authorized.  Check the URL and APIKey in the config.\n")
			return false, ""
		}

		byteValue, _ := ioutil.ReadAll(response.Body)

		var data = MalwareBazarQuery{}
		error = json.Unmarshal(byteValue, &data)

		if error != nil {
			fmt.Println(error)
			return false, ""
		}

		if data.Data == nil {
			return false, ""
		}
		hash.Hash = data.Data.Sha256_hash
		hash.HashType = "sha256"
		fmt.Printf("    [-] Using hash %s\n", hash.Hash)

	}

	if hash.HashType == "sha256" {
		return malwareBazaarDownload(url, hash, doNotExtract)
	}
	return false, ""
}

func malwareBazaarDownload(uri string, hash Hash, doNotExtract bool) (bool, string) {
	query := "query=get_file&sha256_hash=" + hash.Hash
	values, error := url.ParseQuery(query)
	if error != nil {
		fmt.Println(error)
		return false, ""
	}

	client := &http.Client{}
	response, error := client.PostForm(uri, values)
	if error != nil {
		fmt.Println(error)
		return false, ""
	}

	defer response.Body.Close()

	if response.Header["Content-Type"][0] == "application/json" {
		return false, ""
	}

	error = writeToFile(response.Body, hash.Hash+".zip")
	if error != nil {
		fmt.Println(error)
		return false, ""
	}

	fmt.Printf("    [+] Downloaded %s\n", hash.Hash+".zip")
	if doNotExtract {
		return true, hash.Hash + ".zip"
	} else {
		fmt.Println("    [-] Extracting...")
		files, err := extractPwdZip(hash.Hash)
		if err != nil {
			fmt.Println(err)
			return false, ""
		} else {
			for _, f := range files {
				fmt.Printf("    [-] Extracted %s\n", f.Name)
			}
		}
		os.Remove(hash.Hash + ".zip")
		return true, hash.Hash
	}
}

// End of Sample Collection Requests

func preUploadToMWDB(uri string, api string, hash string) bool {
	if api == "" {
		return false
	}
	fmt.Printf("  [*] Checking the UploadToMWDB for %s\n", hash)
	return preUploadToMWDBCheck(uri, api, hash)
}

func preUploadToMWDBCheck(uri string, api string, hash string) bool {
	query := uri + "/file/" + hash

	request, err := http.NewRequest("GET", query, nil)
	if err != nil {
		fmt.Println(err)
		return false
	}

	request.Header.Set("Authorization", "Bearer "+api)
	client := &http.Client{}
	response, error := client.Do(request)
	if error != nil {
		fmt.Println(error)
		return false
	}
	defer response.Body.Close()

	if response.StatusCode == http.StatusOK {
		fmt.Printf("    [!] File %s already exists in MWDB: %s \n", hash, uri)
		return true
	} else {
		fmt.Println("")
		return false
	}
}

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

func extractGzip(hash string) error {
	r, err := os.Open(hash + ".gzip")
	if err != nil {
		log.Fatal(err)
	}
	defer r.Close()

	gzreader, e1 := gzip.NewReader(r)
	if e1 != nil {
		fmt.Println(e1) // Maybe panic here, depends on your error handling.
	}

	err = writeToFile(io.NopCloser(gzreader), hash)
	return err
}

func extractPwdZip(hash string) ([]*zip.File, error) {

	r, err := zip.OpenReader(hash + ".zip")
	if err != nil {
		log.Fatal(err)
	}
	defer r.Close()

	files := r.File

	for _, f := range r.File {
		if f.IsEncrypted() {
			f.SetPassword("infected")
		}

		r, err := f.Open()
		if err != nil {
			log.Fatal(err)
		}

		out, error := os.Create(hash)
		if error != nil {
			return nil, error
		}
		defer out.Close()

		_, err = io.Copy(out, r)
		if err != nil {
			return nil, err
		}
	}
	return files, nil
}

func hashType(hash string) (string, error) {
	match, _ := regexp.MatchString("^[A-Fa-f0-9]{64}$", hash)
	if match {
		return "sha256", nil
	}
	match, _ = regexp.MatchString("^[A-Fa-f0-9]{40}$", hash)
	if match {
		return "sha1", nil
	}
	match, _ = regexp.MatchString("^[A-Fa-f0-9]{32}$", hash)
	if match {
		return "md5", nil
	}
	return "", errors.New("not a valid hash")
}

// parseYAML parses YAML from reader to data structure
func parseYAML(r io.Reader, str interface{}) error {
	return yaml.NewDecoder(r).Decode(str)
}

func parseFile(path string, cfg interface{}) error {
	// open the configuration file
	f, err := os.OpenFile(path, os.O_RDONLY|os.O_SYNC, 0)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			fmt.Printf("Config does not exist.  Create config? [Y|n]")
			var answer string
			fmt.Scanln(&answer)

			if answer == "" || answer == "y" || answer == "Y" {
				filename, err := initConfig()
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
		err = parseYAML(f, cfg)
	default:
		return fmt.Errorf("file format '%s' doesn't supported by the parser", ext)
	}
	if err != nil {
		return fmt.Errorf("config file parsing error: %s", err.Error())
	}
	return nil
}

func initConfig() (string, error) {

	home, err := os.UserHomeDir()
	if err != nil {
		fmt.Println(err)
		return "", err
	}

	file, err := os.OpenFile(path.Join(home, ".mlget.yml"), os.O_CREATE|os.O_WRONLY, 0600)
	if err != nil {
		fmt.Printf("error creating file: %v\n", err)
		return "", err
	}
	defer file.Close()

	enc := yaml.NewEncoder(file)

	err = enc.Encode(Config{
		MalShare: struct {
			ApiKey string "yaml:\"api\""
			Host   string "yaml:\"host\""
		}{Host: "https://malshare.com", ApiKey: ""},
		MWDB: struct {
			ApiKey string "yaml:\"api\""
			Host   string "yaml:\"host\""
		}{Host: "https://mwdb.cert.pl/api", ApiKey: ""},
		MalwareBazar: struct {
			Host string "yaml:\"host\""
		}{Host: "https://mb-api.abuse.ch/api/v1"},
		PolySwarm: struct {
			ApiKey string "yaml:\"api\""
			Host   string "yaml:\"host\""
		}{Host: "https://api.polyswarm.network/v2", ApiKey: ""},
		VT: struct {
			ApiKey string "yaml:\"api\""
			Host   string "yaml:\"host\""
		}{Host: "https://www.virustotal.com/api/v3", ApiKey: ""},
		HybridAnalysis: struct {
			ApiKey string "yaml:\"api\""
			Host   string "yaml:\"host\""
		}{Host: "https://www.hybrid-analysis.com/api/v2", ApiKey: ""},
		Triage: struct {
			ApiKey string "yaml:\"api\""
			Host   string "yaml:\"host\""
		}{Host: "https://api.tria.ge/v0", ApiKey: ""},
		InquestLabs: struct {
			ApiKey string "yaml:\"api\""
			Host   string "yaml:\"host\""
		}{Host: "https://labs.inquest.net/api", ApiKey: ""},
		CapeSandbox: struct {
			ApiKey string "yaml:\"api\""
			Host   string "yaml:\"host\""
		}{Host: "https://www.capesandbox.com/apiv2", ApiKey: ""},
		UploadToMWDBOption: struct {
			ApiKey string "yaml:\"api\""
			Host   string "yaml:\"host\""
		}{Host: "", ApiKey: ""},
		JoeSandbox: struct {
			ApiKey string "yaml:\"api\""
			Host   string "yaml:\"host\""
		}{Host: "https://jbxcloud.joesecurity.org/api", ApiKey: ""},
	})
	if err != nil {
		fmt.Printf("error encoding: %v\n", err)
		return "", err
	}

	return file.Name(), nil
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
		hash := strings.FieldsFunc(text, f)[0]
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
		hashes = append(hashes, pHash)
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

func uploadSampleToMWDB(filename string, hash Hash, delete bool, mwdbServer string, auth string) error {

	bodyBuf := &bytes.Buffer{}
	bodyWriter := multipart.NewWriter(bodyBuf)

	// this step is very important
	fileWriter, err := bodyWriter.CreateFormFile("file", filename)
	if err != nil {
		fmt.Println("error writing to buffer")
		return err
	}

	// open file handle
	fh, err := os.Open(filename)
	if err != nil {
		fmt.Println("error opening file")
		return err
	}
	defer fh.Close()

	//iocopy
	_, err = io.Copy(fileWriter, fh)
	if err != nil {
		return err
	}

	contentType := bodyWriter.FormDataContentType()
	bodyWriter.Close()

	request, error := http.NewRequest("POST", mwdbServer+"/file", bodyBuf)
	if error != nil {
		fmt.Println(error)
		return error
	}

	request.Header.Set("Authorization", "Bearer "+auth)
	request.Header.Set("Content-Type", contentType)

	client := &http.Client{}
	resp, err := client.Do(request)
	if err != nil {
		return err
	}

	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("error uploading file - status code %d returned", resp.StatusCode)

	} else {
		fmt.Printf("    [-] %s uploaded to MWDB (%s)\n", filename, mwdbServer)
		if delete {
			os.Remove(filename)
			fmt.Printf("    [-] %s deleted from disk\n", filename)
		}
	}

	err = addTagsToSampleInMWDB(hash, mwdbServer, auth)
	if err != nil {
		return err
	}

	err = addCommentsToSampleInMWDB(hash, mwdbServer, auth)
	if err != nil {
		return err
	}
	return nil
}

func addTagsToSampleInMWDB(hash Hash, mwdbServer string, auth string) error {
	for _, t := range hash.Tags {
		query := mwdbServer + "/file/" + hash.Hash + "/tag"

		_, error := url.ParseQuery(query)
		if error != nil {
			fmt.Println(error)
			return error
		}

		value_json := "{\"tag\":\"" + t + "\"}"
		request, error := http.NewRequest("PUT", query, strings.NewReader(value_json))
		if error != nil {
			fmt.Println(error)
			return error
		}

		request.Header.Set("Authorization", "Bearer "+auth)

		client := &http.Client{}
		respTag, err := client.Do(request)
		if err != nil {
			return err
		}

		if respTag.StatusCode == http.StatusOK {
			fmt.Printf("    [-] %s tagged as %s\n", hash.Hash, t)
		} else {
			fmt.Printf("    [!] Failed to tag %s as %s\n", hash.Hash, t)
		}
	}
	return nil
}

func addCommentsToSampleInMWDB(hash Hash, mwdbServer string, auth string) error {

	// Get existing comments
	getQuery := mwdbServer + "/file/" + hash.Hash + "/comment"
	_, error := url.ParseQuery(getQuery)
	if error != nil {
		fmt.Println(error)
		return error
	}
	getRequest, error := http.NewRequest("GET", getQuery, nil)
	if error != nil {
		fmt.Println(error)
		return error
	}
	getRequest.Header.Set("Authorization", "Bearer "+auth)

	getClient := &http.Client{}
	getResponse, error := getClient.Do(getRequest)
	if error != nil {
		fmt.Println(error)
		return error
	}
	defer getResponse.Body.Close()

	var getData []CommentItemResponse
	if getResponse.StatusCode == http.StatusOK {

		byteValue, error := ioutil.ReadAll(getResponse.Body)
		if error != nil {
			fmt.Println(error)
			return error
		}

		error = json.Unmarshal(byteValue, &getData)

		if error != nil {
			fmt.Println(error)
			return error
		}
	}

	for _, c := range hash.Comments {

		// Check to make sure the comment does not already exists before added it, if it does exist continue on to the next comment
		commentExists := false
		if len(getData) > 0 {
			for _, existingComment := range getData {
				if c == existingComment.Comment {
					commentExists = true
					break
				}
			}
		}
		if commentExists {
			fmt.Printf("    [!] %s comment already exists for %s\n", c, hash.Hash)
			continue
		}

		// Add net comment to sample
		query := mwdbServer + "/file/" + hash.Hash + "/comment"

		_, error := url.ParseQuery(query)
		if error != nil {
			fmt.Println(error)
			return error
		}

		value_json := "{\"comment\":\"" + c + "\"}"
		request, error := http.NewRequest("POST", query, strings.NewReader(value_json))
		if error != nil {
			fmt.Println(error)
			return error
		}

		request.Header.Set("Authorization", "Bearer "+auth)

		client := &http.Client{}
		respTag, err := client.Do(request)
		if err != nil {
			return err
		}

		if respTag.StatusCode == http.StatusOK {
			fmt.Printf("    [-] %s comment added for %s\n", c, hash.Hash)
		} else {
			fmt.Printf("    [!] Failed to comment %s for %s\n", c, hash.Hash)
		}
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

func parseArgHashes(hashes []string, tags []string, comments []string) Hashes {
	parsedHashes := Hashes{}
	for _, h := range hashes {
		ht, err := hashType(h)
		if err != nil {
			fmt.Printf("\n Skipping %s because it's %s\n", h, err)
			continue
		}
		fmt.Printf("Hash found: %s\n", h) // token in unicode-char
		hash := Hash{Hash: h, HashType: ht}
		if len(tags) > 0 {
			hash.Tags = tags
		}
		if len(comments) > 0 {
			hash.Comments = comments
		}
		parsedHashes, _ = AddHash(parsedHashes, hash)
	}
	return parsedHashes
}
