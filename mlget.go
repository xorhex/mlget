package main

import (
	"fmt"
	"os"
	"path"
	"time"

	flag "github.com/spf13/pflag"
)

var apiFlag string
var helpFlag bool
var checkConfFlag bool
var AddConfigEntryFlag bool
var doNotExtractFlag bool
var inputFileFlag string
var outputFileFlag bool
var uploadToMWDBAndDeleteFlag bool
var downloadOnlyFlag bool
var uploadToMWDBFlag bool
var readFromFileAndUpdateWithNotFoundHashesFlag string
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
	flag.StringVar(&apiFlag, "from", "", "The service to download the malware from.\n  Must be one of:\n  - tg (Triage)\n  - mb (Malware Bazaar)\n  - ms (Malshare)\n  - ha (Hybird Anlysis)\n  - vt (VirusTotal)\n  - cp (Cape Sandbox)\n  - mw (Malware Database)\n  - ps (PolySwarm)\n  - iq (Inquest Labs)\n  - js (Joe Sandbox)\n  - os (Objective-See)\nIf omitted, all services will be tried.")
	flag.StringVar(&inputFileFlag, "read", "", "Read in a file of hashes (one per line)")
	flag.BoolVar(&outputFileFlag, "output", false, "Write to a file the hashes not found (for later use with the --read flag)")
	flag.BoolVar(&helpFlag, "help", false, "Print the help message")
	flag.BoolVar(&checkConfFlag, "config", false, "Parse and print the config file")
	flag.BoolVar(&AddConfigEntryFlag, "addtoconfig", false, "Add entry to the config file")
	flag.BoolVar(&doNotExtractFlag, "noextraction", false, "Do not extract malware from archive file.\nCurrently this only effects MalwareBazaar and HybridAnalysis")
	flag.BoolVar(&uploadToMWDBFlag, "upload", false, "Upload downloaded files to the MWDB instance specified in the mlget.yml file.")
	flag.StringVar(&readFromFileAndUpdateWithNotFoundHashesFlag, "readupdate", "", "Read hashes from file to download.  Replace entries in the file with just the hashes that were not found (for next time).")
	flag.BoolVar(&uploadToMWDBAndDeleteFlag, "uploaddelete", false, "Upload downloaded files to the MWDB instance specified in the mlget.yml file.\nDelete the files after successful upload")
	flag.StringSliceVar(&tagsFlag, "tag", []string{}, "Tag the sample when uploading to your own instance of MWDB.")
	flag.StringSliceVar(&commentsFlag, "comment", []string{}, "Add comment to the sample when uploading to your own instance of MWDB.")
	flag.BoolVar(&downloadOnlyFlag, "downloadonly", false, "Download from any source, including your personal instance of MWDB.\nWhen this flag is set; it will NOT update any output file with the hashes not found.\nAnd it will not upload to any of the UploadMWDB instances.")
}

func main() {
	homeDir, err := os.UserHomeDir()
	if err != nil {
		fmt.Println(err)
		return
	}

	configFileName := path.Join(homeDir, ".mlget.yml")

	cfg, err := LoadConfig(configFileName)
	if err != nil {
		fmt.Println(err)
		return
	}

	flag.Parse()

	if helpFlag {
		usage()
		return
	}

	if AddConfigEntryFlag {
		AddToConfig(configFileName)
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

	var osq ObjectiveSeeQuery
	osConfigs := getConfigsByType(ObjectiveSee, cfg)
	// Can have multiple Objective-See configs but only the first one to load will be used
	for _, osc := range osConfigs {
		osq, err = loadObjectiveSeeJson(osc.Host)
		if err != nil {
			fmt.Println("Unable to load Objective-See json data.  Skipping...")
			continue
		}
		fmt.Println("")
		break
	}

	hashes := parseArgHashes(args, tagsFlag, commentsFlag)

	if inputFileFlag != "" {
		hshs, err := parseFileForHashEntries(inputFileFlag)
		if err != nil {
			fmt.Printf("Error reading from %s\n", inputFileFlag)
			fmt.Println(err)
		} else {
			for _, hsh := range hshs {
				hashes, _ = addHash(hashes, hsh)
			}
		}
	} else if readFromFileAndUpdateWithNotFoundHashesFlag != "" {
		hshs, err := parseFileForHashEntries(readFromFileAndUpdateWithNotFoundHashesFlag)
		if err != nil {
			fmt.Printf("Error reading from %s\n", readFromFileAndUpdateWithNotFoundHashesFlag)
			fmt.Println(err)
		} else {
			for _, hsh := range hshs {
				hashes, _ = addHash(hashes, hsh)
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

		if (uploadToMWDBFlag || uploadToMWDBAndDeleteFlag) && !downloadOnlyFlag {
			if SyncSampleAcrossUploadMWDBsIfExists(cfg, h) {
				continue
			}
		}

		if apiFlag != "" {
			flaggedRepo := getMalwareRepoByFlagName(apiFlag)
			if flaggedRepo == NotSupported {
				fmt.Printf("Invalid or unsupported malware repo type: %s\nCheck the help for the values to pass to the --from parameter\n", apiFlag)
				continue
			}

			fmt.Printf("Looking on %s\n", getMalwareRepoByFlagName(apiFlag))

			found, filename := flaggedRepo.QueryAndDownload(cfg, h, doNotExtractFlag, osq)
			if !found {
				fmt.Println("    [!] Not Found")
				notFoundHashes, _ = addHash(notFoundHashes, h)
			} else {
				if (uploadToMWDBFlag || uploadToMWDBAndDeleteFlag) && !downloadOnlyFlag {
					err := UploadSampleToMWDBs(cfg, filename, h, uploadToMWDBAndDeleteFlag)
					if err != nil {
						fmt.Printf("    [!] %s", err)
					}
				}
			}

		} else {
			fmt.Println("Querying all services")

			found, filename := queryAndDownloadAll(cfg, h, doNotExtractFlag, !downloadOnlyFlag, osq)
			if found {
				if (uploadToMWDBFlag || uploadToMWDBAndDeleteFlag) && !downloadOnlyFlag {
					err := UploadSampleToMWDBs(cfg, filename, h, uploadToMWDBAndDeleteFlag)
					if err != nil {
						fmt.Printf("    [!] %s", err)
					}
				}
				continue
			}

			notFoundHashes, _ = addHash(notFoundHashes, h)
		}
	}

	if len(notFoundHashes.Hashes) > 0 {
		fmt.Printf("\nHashes not found!\n")
		for i, s := range notFoundHashes.Hashes {
			fmt.Printf("    %d: %s\n", i, s)
		}
	}
	if !downloadOnlyFlag {
		if readFromFileAndUpdateWithNotFoundHashesFlag != "" {
			err := writeUnfoundHashesToFile(readFromFileAndUpdateWithNotFoundHashesFlag, notFoundHashes)
			if err != nil {
				fmt.Println("Error writing unfound hashes to file")
				fmt.Println(err)
			}
			fmt.Printf("\n\n%s refreshed to show only the hashes not found.\n", readFromFileAndUpdateWithNotFoundHashesFlag)

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
		parsedHashes, _ = addHash(parsedHashes, hash)
	}
	return parsedHashes
}
