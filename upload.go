package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"mime/multipart"
	"net/http"
	"net/url"
	"os"
	"strings"
)

type CommentItemResponse struct {
	Author    string `json:"author"`
	Comment   string `json:"comment"`
	Id        int32  `json:"id"`
	Timestamp string `json:"timestamp"`
}

func SyncSampleAcrossUploadMWDBsIfExists(repos []RepositoryConfigEntry, hash Hash) bool {
	matchingConfigRepos := getConfigsByType(UploadMWDB, repos)
	synced := false
	for _, mcr := range matchingConfigRepos {
		if !doesSampleExistInMWDB(mcr.Host, mcr.Api, hash.Hash) {
			// If sample not found then skip the rest of this loop and check to see if the next UploadMWDB instance has the sample
			continue
		}
		// A sample was found, now download and upload to the remaining instances
		if len(matchingConfigRepos) > 1 {
			var osq ObjectiveSeeQuery
			downloaded, filename, _ := UploadMWDB.QueryAndDownload(matchingConfigRepos, hash, false, osq)
			if downloaded {
				UploadSampleToMWDBs(matchingConfigRepos, filename, hash, true)
			}
		}

		if len(hash.Tags) == 0 && len(hash.Comments) == 0 {
			fmt.Printf("  [!] Skipping %s\n", hash.Hash)
		} else {
			if len(hash.Tags) > 0 {
				// Add Tags
				AddTagsToSamplesAcrossMWDBs(matchingConfigRepos, hash)
			}
			if len(hash.Comments) > 0 {
				// Add Comments
				AddCommentsToSamplesAcrossMWDBs(matchingConfigRepos, hash)
			}
		}
		synced = true
	}
	return synced
}

func doesSampleExistInMWDB(uri string, api string, hash string) bool {
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

func UploadSampleToMWDBs(repos []RepositoryConfigEntry, filename string, hash Hash, deleteFromDisk bool) error {
	matchingConfigRepos := getConfigsByType(UploadMWDB, repos)
	for _, mcr := range matchingConfigRepos {
		if doesSampleExistInMWDB(mcr.Host, mcr.Api, hash.Hash) {
			continue
		}

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

		request, error := http.NewRequest("POST", mcr.Host+"/file", bodyBuf)
		if error != nil {
			fmt.Println(error)
			return error
		}

		request.Header.Set("Authorization", "Bearer "+mcr.Api)
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
			fmt.Printf("    [-] %s uploaded to MWDB (%s)\n", filename, mcr.Host)
			if deleteFromDisk {
				os.Remove(filename)
				fmt.Printf("    [-] %s deleted from disk\n", filename)
			}
		}

		err = addTagsToSampleInMWDB(hash, mcr.Host, mcr.Api)
		if err != nil {
			return err
		}

		err = addCommentsToSampleInMWDB(hash, mcr.Host, mcr.Api)
		if err != nil {
			return err
		}
	}
	return nil
}

func AddTagsToSamplesAcrossMWDBs(repos []RepositoryConfigEntry, hash Hash) {
	matchingConfigRepos := getConfigsByType(UploadMWDB, repos)
	for _, mcr := range matchingConfigRepos {
		if !doesSampleExistInMWDB(mcr.Host, mcr.Api, hash.Hash) {
			continue
		}
		err := addTagsToSampleInMWDB(hash, mcr.Host, mcr.Api)
		if err != nil {
			fmt.Printf("Error occurred while tagging %s on %s (%s)\n", hash.Hash, mcr.Type, mcr.Host)
		}
	}
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

func AddCommentsToSamplesAcrossMWDBs(repos []RepositoryConfigEntry, hash Hash) {
	matchingConfigRepos := getConfigsByType(UploadMWDB, repos)
	for _, mcr := range matchingConfigRepos {
		if !doesSampleExistInMWDB(mcr.Host, mcr.Api, hash.Hash) {
			continue
		}
		err := addCommentsToSampleInMWDB(hash, mcr.Host, mcr.Api)
		if err != nil {
			fmt.Printf("Error occurred while adding comments to %s on %s (%s)\n", hash.Hash, mcr.Type, mcr.Host)
		}
	}
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
