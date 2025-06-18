package main

import (
	"crypto"
	"fmt"
	"io"
	"log"
	"os"
	"path"
	"sync"
	"time"

	flag "github.com/spf13/pflag"
	"golang.org/x/exp/slices"
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
var versionFlag bool
var noValidationFlag bool
var precheckdir bool
var uploadToAssemblyLineFlag bool
var uploadToAssemblyLineAndDeleteFlag bool
var forceResubmission bool

var version string = "3.4.3"

func usage() {
	fmt.Println("mlget - A command line tool to download malware from a variety of sources")
	fmt.Println("")

	fmt.Printf("Usage: %s [OPTIONS] hash_arguments...\n", os.Args[0])
	flag.PrintDefaults()

	fmt.Println("")
	fmt.Println("Example Usage: mlget <sha256> <md5> <sha1> <sha256>")
	fmt.Println("Example Usage: mlget --from mb <sha256>")
	fmt.Println("Example Usage: mlget --tag tag_one --tag tag_two --uploaddelete <sha256> <sha1> <md5>")
}

func init() {
	flag.StringVar(&apiFlag, "from", "", "The service to download the malware from.\n  Must be one of:\n  - al (AssemblyLine)\n  - cs (Cape Sandbox)\n  - fs (FileScanIo)\n  - ha (Hybird Anlysis)\n  - iq (Inquest Labs)\n  - js (Joe Sandbox)\n  - mp (Malpedia)\n  - ms (Malshare)\n  - mb (Malware Bazaar)\n  - mw (Malware Database)\n  - os (Objective-See)\n  - ps (PolySwarm)\n  - tr (Triage)\n  - um (UnpacMe)\n  - us (URLScanIO)\n  - ve (VExchange)\n  - vt (VirusTotal)\n  - vx (VxShare)\nIf omitted, all services will be tried.")
	flag.StringVar(&inputFileFlag, "read", "", "Read in a file of hashes (one per line)")
	flag.BoolVar(&outputFileFlag, "output", false, "Write to a file the hashes not found (requires using --read)")
	flag.BoolVar(&helpFlag, "help", false, "Print the help message")
	flag.BoolVar(&checkConfFlag, "config", false, "Parse and print the config file")
	flag.BoolVar(&AddConfigEntryFlag, "addtoconfig", false, "Add entry to the config file")
	flag.BoolVar(&doNotExtractFlag, "noextraction", false, "Do not extract malware from archive file.\nCurrently this only effects MalwareBazaar and HybridAnalysis")
	flag.BoolVar(&uploadToMWDBFlag, "uploadmwdb", false, "Upload downloaded files to the Upload MWDB instances specified in the mlget.yml file.")
	flag.BoolVar(&uploadToAssemblyLineFlag, "uploadal", false, "Upload downloaded files to the Upload AssemblyLine instances specified in the mlget.yml file.")
	flag.StringVar(&readFromFileAndUpdateWithNotFoundHashesFlag, "readupdate", "", "Read hashes from file to download.  Replace entries in the file with just the hashes that were not found (for next time).")
	flag.BoolVar(&uploadToMWDBAndDeleteFlag, "uploaddeletemwdb", false, "Upload downloaded files to the Upload MWDB instance specified in the mlget.yml file.\nDelete the files after successful upload")
	flag.BoolVar(&uploadToAssemblyLineAndDeleteFlag, "uploaddeleteal", false, "Upload downloaded files to the Upload AssemblyLine instances specified in the mlget.yml file.\nDelete the files after successful upload")
	flag.BoolVar(&forceResubmission, "f", false, "Force resubmission to AssemblyLine when the files already exists on the AssemblyLine instance.")
	flag.StringSliceVar(&tagsFlag, "tag", []string{}, "Tag the sample when uploading to your own instance of MWDB.")
	flag.StringSliceVar(&commentsFlag, "comment", []string{}, "Add comment to the sample when uploading to your own instance of MWDB.")
	flag.BoolVar(&downloadOnlyFlag, "downloadonly", false, "Download from any source, including your personal instance of MWDB.\nWhen this flag is set; it will NOT update any output file with the hashes not found.\nAnd it will not upload to any of the UploadMWDB.")
	flag.BoolVar(&versionFlag, "version", false, "Print the version number")
	flag.BoolVar(&noValidationFlag, "novalidation", false, "Turn off post download hash check verification")
	flag.BoolVar(&precheckdir, "precheckdir", false, "Search current dir for files matching the hashes provided, if found don't redownload")
}

func main() {

	doNotValidatehash := []MalwareRepoType{ObjectiveSee}

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

	if versionFlag {
		fmt.Printf("Mlget version: %s\n", version)
		return
	}

	if helpFlag {
		usage()
		return
	}

	if AddConfigEntryFlag {
		AddToConfig(configFileName)
		return
	}

	if checkConfFlag {
		fmt.Printf("%+v", cfg)
		return
	}

	args := flag.Args()
	/*
		if webserver {
			runWebServer(ip, port)
		} else {*/
	downloadMalwareFromCLI(args, cfg, doNotValidatehash, precheckdir)
	//	}

}

func parseArgHashes(hashes []string, tags []string, comments []string) Hashes {
	parsedHashes := Hashes{}
	fmt.Printf("Hashes Passed Via the Command Line:\n")
	for _, h := range hashes {
		ht, err := hashType(h)
		if err != nil {
			fmt.Printf("\n Skipping %s because it's %s\n", h, err)
			continue
		}
		fmt.Printf("  - %s\n", h) // token in unicode-char
		hash := Hash{Hash: h, HashType: ht, Local: false}
		if len(tags) > 0 {
			hash.Tags = tags
		}
		if len(comments) > 0 {
			hash.Comments = comments
		}
		parsedHashes, _ = addHash(parsedHashes, hash)
	}
	fmt.Println("")
	return parsedHashes
}

func downloadMalwareFromCLI(args []string, cfg []RepositoryConfigEntry, doNotValidatehash []MalwareRepoType, precheckdir bool) {
	if apiFlag != "" {
		flaggedRepo := getMalwareRepoByFlagName(apiFlag)
		if flaggedRepo == NotSupported {
			fmt.Printf("Invalid or unsupported malware repo type: %s\nCheck the help for the values to pass to the --from parameter\n", apiFlag)
			return
		}
	}

	if apiFlag != "" && downloadOnlyFlag {
		fmt.Printf(("Can't use both the --from flag and the --downloadonly flag together"))
		return
	}

	hashes := parseArgHashes(args, tagsFlag, commentsFlag)
	var err error

	if inputFileFlag != "" {
		hshs, err := parseFileForHashEntries(inputFileFlag)
		if err != nil {
			fmt.Printf("Error reading from %s\n", inputFileFlag)
			fmt.Println(err)
		} else {
			for idx, hsh := range hshs {
				if len(hshs) > 100 {
					fmt.Printf("Adding Hash %d of %d\n", idx, len(hshs))
				}
				hashes, _ = addHash(hashes, hsh)
			}
		}
	}
	if readFromFileAndUpdateWithNotFoundHashesFlag != "" {
		hshs, err := parseFileForHashEntries(readFromFileAndUpdateWithNotFoundHashesFlag)
		if err != nil {
			fmt.Printf("Error reading from %s\n", readFromFileAndUpdateWithNotFoundHashesFlag)
			fmt.Println(err)
		} else {
			for idx, hsh := range hshs {
				if len(hshs) > 100 {
					fmt.Printf("Adding Hash %d of %d\n", idx, len(hshs))
				}
				hashes, _ = addHash(hashes, hsh)
			}
		}
	}

	var notFoundHashes Hashes

	if len(hashes.Hashes) == 0 {
		fmt.Println("No hashes found; displaying Help")
		usage()
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

	if doNotExtractFlag {
		doNotValidatehash = append(doNotValidatehash, VxShare, MalwareBazaar, HybridAnalysis, FileScanIo, Triage)
	}

	if precheckdir {
		files, err := os.ReadDir(".")
		if err != nil {
			fmt.Println(err)
		}

		filesHashing := 0
		ch := make(chan Hash, len(files)*3)
		var wg sync.WaitGroup

		go func() {
			wg.Wait()
			close(ch)
		}()

		for _, file := range files {
			if file.IsDir() {
				continue
			}
			filesHashing++
			wg.Add(1)

			name := file.Name()

			go func() {
				defer wg.Done()
				hashFileAndCheck(name, ch)
			}()
		}

		fmt.Println("\nFiles Matching Hashes Found Locally:")

		for i := range ch {
			if hashes.hashExists(i.Hash) {
				fmt.Printf("  - Found %s in current folder\n", i.Hash)
				fmt.Printf("      File Name: %s\n", i.LocalFile)
				hashes.updateLocalFile(i.Hash, i.LocalFile)

				h, _ := hashes.getByHash(i.Hash)

				if (uploadToMWDBFlag || uploadToMWDBAndDeleteFlag) && !downloadOnlyFlag {
					err := UploadSampleToMWDBs(cfg, h.LocalFile, h, uploadToMWDBAndDeleteFlag)
					if err != nil {
						fmt.Printf("      ! %s\n", err)
					}
				}
				if (uploadToAssemblyLineFlag || uploadToAssemblyLineAndDeleteFlag) && !downloadOnlyFlag {
					err := UploadSampleToAssemblyLine(cfg, h.LocalFile, h, uploadToAssemblyLineAndDeleteFlag, forceResubmission)
					if err != nil {
						fmt.Printf("      ! %s\n", err)
					}
				}
			}
		}
	}

	for idx, h := range hashes.Hashes {

		if h.Local {
			continue
		}

		fmt.Printf("\nLook up %s (%s) - (%d of %d)\n", h.Hash, h.HashType, idx+1, len(hashes.Hashes))

		if apiFlag != "" {
			flaggedRepo := getMalwareRepoByFlagName(apiFlag)

			fmt.Printf("Looking on %s\n", getMalwareRepoByFlagName(apiFlag))

			found, filename, checkedRepo := flaggedRepo.QueryAndDownload(cfg, h, doNotExtractFlag, osq)
			if !found {
				fmt.Println("    [!] Not Found")
				notFoundHashes, _ = addHash(notFoundHashes, h)
			} else if found {
				if !noValidationFlag {
					if slices.Contains(doNotValidatehash, checkedRepo) {
						if checkedRepo == ObjectiveSee {
							fmt.Printf("    [!] Not able to validate hash for repo %s\n", checkedRepo.String())
						} else {
							fmt.Printf("    [!] Not able to validate hash for repo %s when noextraction flag is set to %t\n", checkedRepo.String(), doNotExtractFlag)
						}
					} else {
						valid, calculatedHash := h.ValidateFile(filename)
						if !valid {
							fmt.Printf("    [!] Downloaded file hash %s\n        does not match searched for hash %s\n", calculatedHash, h.Hash)
							deleteInvalidFile(filename)
							notFoundHashes, _ = addHash(notFoundHashes, h)
							continue
						} else {
							fmt.Printf("    [+] Downloaded file %s validated as the requested hash\n", h.Hash)
						}
					}
				}
				if (uploadToMWDBFlag || uploadToMWDBAndDeleteFlag) && !downloadOnlyFlag {
					err := UploadSampleToMWDBs(cfg, filename, h, uploadToMWDBAndDeleteFlag)
					if err != nil {
						fmt.Printf("    ! %s", err)
					}
				}
				if (uploadToAssemblyLineFlag || uploadToAssemblyLineAndDeleteFlag) && !downloadOnlyFlag {
					err := UploadSampleToAssemblyLine(cfg, filename, h, uploadToAssemblyLineAndDeleteFlag, forceResubmission)
					if err != nil {
						fmt.Printf("    ! %s", err)
					}
				}
			}

		} else {
			fmt.Println("Querying all services")

			found, filename, _ := queryAndDownloadAll(cfg, h, doNotExtractFlag, !downloadOnlyFlag, osq, noValidationFlag, doNotValidatehash)
			if found {
				if (uploadToMWDBFlag || uploadToMWDBAndDeleteFlag) && !downloadOnlyFlag {
					err := UploadSampleToMWDBs(cfg, filename, h, uploadToMWDBAndDeleteFlag)
					if err != nil {
						fmt.Printf("    ! %s", err)
					}
				}
				if (uploadToAssemblyLineFlag || uploadToAssemblyLineAndDeleteFlag) && !downloadOnlyFlag {
					err := UploadSampleToAssemblyLine(cfg, filename, h, uploadToAssemblyLineAndDeleteFlag, forceResubmission)
					if err != nil {
						fmt.Printf("    ! %s", err)
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
			fmt.Printf("    %d: %s\n", i, s.Hash)
		}
	}
	if !downloadOnlyFlag {
		if readFromFileAndUpdateWithNotFoundHashesFlag != "" && !isValidUrl(readFromFileAndUpdateWithNotFoundHashesFlag) {
			err := writeUnfoundHashesToFile(readFromFileAndUpdateWithNotFoundHashesFlag, notFoundHashes)
			if err != nil {
				fmt.Println("Error writing not found hashes to file")
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
		} else if isValidUrl(readFromFileAndUpdateWithNotFoundHashesFlag) {
			fmt.Println("File specified is a URL - can't update file.  Please use --read and --output flags instead if you want to capture the hashes not found.")
		}
	}
}

func hashFileAndCheck(file string, c chan Hash) {

	f, err := os.Open(file)

	if err != nil {
		log.Fatal(err)
	}
	defer f.Close()

	hasherMD5 := crypto.MD5.New()
	if _, err := io.Copy(hasherMD5, f); err != nil {
		log.Fatal(err)
	}
	sumMD5 := hasherMD5.Sum(nil)

	c <- Hash{Hash: fmt.Sprintf("%x", sumMD5), HashType: md5, LocalFile: file}

	f.Seek(0, 0)
	hasherSHA1 := crypto.SHA1.New()
	if _, err := io.Copy(hasherSHA1, f); err != nil {
		log.Fatal(err)
	}
	sumSHA1 := hasherSHA1.Sum(nil)

	c <- Hash{Hash: fmt.Sprintf("%x", sumSHA1), HashType: sha1, LocalFile: file}

	f.Seek(0, 0)
	hasherSHA256 := crypto.SHA256.New()
	if _, err := io.Copy(hasherSHA256, f); err != nil {
		log.Fatal(err)
	}
	sumSHA256 := hasherSHA256.Sum(nil)

	c <- Hash{Hash: fmt.Sprintf("%x", sumSHA256), HashType: sha256, LocalFile: file}
}
