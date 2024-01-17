package main

import (
	"bytes"
	"compress/gzip"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strings"

	"github.com/yeka/zip"
)

type JoeSandboxQuery struct {
	Data []JoeSandboxQueryData `'json:"data"`
}

type JoeSandboxQueryData struct {
	Webid string `json:"webid"`
}

type InquestLabsQuery struct {
	Data    []InquestLabsQueryData `json:"data"`
	Success bool                   `json:"success"`
}

type InquestLabsQueryData struct {
	Sha256 string `json:"sha256"`
}

type HybridAnalysisQuery struct {
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

type AssemblyLineQuery struct {
	Error_message  string                     `json:"api_error_message"`
	Response       *AssemblyLineQueryResponse `json:"api_response"`
	Server_version string                     `json:"api_server_version"`
	Status_Code    int                        `json:"api_status_code"`
}

type AssemblyLineQueryResponse struct {
	AL *AssemblyLineQueryALResponse `json:"al"`
}

type AssemblyLineQueryALResponse struct {
	Error string                  `json:"error"`
	Items []AssemblyLineQueryItem `json:"items"`
}

type AssemblyLineQueryItem struct {
	Classification string                 `json:"classification"`
	Data           *AssemblyLineQueryData `json:"data"`
}

type AssemblyLineQueryData struct {
	Md5    string `json:"md5"`
	Sha1   string `json:"sha1"`
	Sha256 string `json:"sha256"`
}

type TriageQuery struct {
	Data []TriageQueryData `json:"data"`
}

type TriageQueryData struct {
	Id       string `json:"id"`
	Kind     string `json:"kind"`
	Filename string `json:"filename"`
}

type ObjectiveSeeQuery struct {
	Malware []ObjectiveSeeData `json:"malware"`
}

type ObjectiveSeeData struct {
	Name       string `json:"name"`
	Type       string `json:"type"`
	VirusTotal string `json:"virusTotal"`
	MoreInfo   string `json:"moreInfo"`
	Download   string `json:"download"`
	Sha256     string
}

type MalpediaData struct {
	Name      string
	FileBytes []byte
}

func loadObjectiveSeeJson(uri string) (ObjectiveSeeQuery, error) {

	fmt.Printf("Downloading Objective-See Malware json from: %s\n\n", uri)

	client := &http.Client{}
	response, error := client.Get(uri)
	if error != nil {
		fmt.Println(error)
		return ObjectiveSeeQuery{}, error
	}

	defer response.Body.Close()

	if response.StatusCode == http.StatusOK {
		byteValue, _ := io.ReadAll(response.Body)

		var data = ObjectiveSeeQuery{}
		error = json.Unmarshal(byteValue, &data)

		var unmarshalTypeError *json.UnmarshalTypeError
		if errors.As(error, &unmarshalTypeError) {
			fmt.Printf("    [!] Failed unmarshaling json.  Likely due to the format of the Objective-See json file changing\n")
			fmt.Printf("        %s\n", byteValue)

		} else if error != nil {
			fmt.Println(error)
			return ObjectiveSeeQuery{}, error
		}

		fmt.Printf("  Parsing VirusTotal Links for sha256 hashes\n")
		re := regexp.MustCompile("[A-Fa-f0-9]{64}")
		for k, item := range data.Malware {
			if len(item.VirusTotal) > 0 {
				matches := re.FindStringSubmatch(item.VirusTotal)
				if len(matches) == 1 {
					data.Malware[k].Sha256 = matches[0]
				}
			}
			if len(data.Malware[k].Sha256) == 0 {
				fmt.Printf("    [!] SHA256 not found for %s : %s\n        VirusTotal Link: %s\n", item.Name, item.Type, item.VirusTotal)
			}
		}

		return data, nil
	} else {
		return ObjectiveSeeQuery{}, fmt.Errorf("unable to download objective-see json file")
	}
}

func objectivesee(data ObjectiveSeeQuery, hash Hash, doNotExtract bool) (bool, string) {
	if hash.HashType != sha256 {
		fmt.Printf("    [!] Objective-See only supports SHA256\n        Skipping\n")
	}

	item, found := findHashInObjectiveSeeList(data.Malware, hash)

	if !found {
		return false, ""
	}

	if !doNotExtract {
		fmt.Printf("    [!] Extraction is not supported for Objective-See\n         Try again but with the --noextraction flag\n")
		return false, ""
	}

	client := &http.Client{}
	response, error := client.Get(item.Download)
	if error != nil {
		fmt.Println(error)
		return false, ""
	}

	defer response.Body.Close()

	if response.StatusCode != http.StatusOK {
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
		return false, ""
	}
}

func joesandbox(uri string, api string, hash Hash) (bool, string) {
	if api == "" {
		fmt.Println("    [!] !! Missing Key !!")
		return false, ""
	}

	fmt.Printf("    [-] Looking up sandbox ID for: %s\n", hash.Hash)

	query := uri + "/analysis/search"

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

		byteValue, error := io.ReadAll(response.Body)
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
	query := uri + "/analysis/download"

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
	query := uri + "/files/get/" + url.QueryEscape(hash.HashType.String()) + "/" + url.QueryEscape(hash.Hash) + "/"

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

	if hash.HashType != sha256 {
		fmt.Printf("    [-] Looking up sha256 hash for %s\n", hash.Hash)

		query := uri + "/dfi/search/hash/" + url.PathEscape(hash.HashType.String()) + "?hash=" + url.QueryEscape(hash.Hash)

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

			byteValue, _ := io.ReadAll(response.Body)

			var data = InquestLabsQuery{}
			error = json.Unmarshal(byteValue, &data)

			var unmarshalTypeError *json.UnmarshalTypeError
			if errors.As(error, &unmarshalTypeError) {
				fmt.Printf("    [!] Failed unmarshaling json.  This could be due to the API changing or\n        just no data inside the data array was returned - aka. sha256 hash was not found.\n")
				fmt.Printf("        %s\n", byteValue)

			} else if error != nil {
				fmt.Println(error)
				return false, ""
			}

			if !data.Success {
				return false, ""
			}

			if len(data.Data) == 0 {
				return false, ""
			}

			if data.Data[0].Sha256 == "" {
				return false, ""
			}
			hash.HashType = sha256
			hash.Hash = data.Data[0].Sha256
			fmt.Printf("    [-] Using hash %s\n", hash.Hash)

		} else if response.StatusCode == http.StatusForbidden {
			fmt.Printf("    [!] Not authorized.  Check the URL and APIKey in the config.\n")
			return false, ""
		}
	}

	if hash.HashType == sha256 {
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
	query := "/download/" + url.PathEscape(hash.HashType.String()) + "/" + url.PathEscape(hash.Hash)

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

	if hash.HashType != sha256 {
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
		byteValue, _ := io.ReadAll(response.Body)

		var data = HybridAnalysisQuery{}
		error = json.Unmarshal(byteValue, &data)

		if error != nil {
			fmt.Println(error)
			return false, ""
		}

		if data.Sha256 == "" {
			return false, ""
		}
		hash.Hash = data.Sha256
		hash.HashType = sha256
		fmt.Printf("    [-] Using hash %s\n", hash.Hash)

	}

	if hash.HashType == sha256 {
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
		fmt.Printf("    [!] Not authorized.  Check the URL and APIKey in the config.\nCould also be that the sample is not allowed to be downloaded.\n")
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

func triage(uri string, api string, hash Hash) (bool, string) {
	if api == "" {
		fmt.Println("    [!] !! Missing Key !!")
		return false, ""
	}

	// Look up hash to get Sample ID
	query := "query=" + url.QueryEscape(hash.HashType.String()) + ":" + url.QueryEscape(hash.Hash)
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

		byteValue, error := io.ReadAll(response.Body)
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
	// Triage will download an archive file that contians the hash in question sometimes versus the actual sample being requested
	hashMatch, _ := hash.ValidateFile(hash.Hash)
	if !hashMatch {
		files, err := extractPwdZip(hash.Hash, "", false, hash)
		if err != nil {
			fmt.Println(error)
			return false, ""
		}

		found := false

		fmt.Printf("      [-] The downloaded file appears to be a zip file in which the requested file should be located.\n")
		for _, f := range files {
			fmt.Printf("        [-] Checking file: %s\n", f.Name)
			hashMatch, _ = hash.ValidateFile(f.Name)
			if !hashMatch {
				err = os.Remove(f.Name)
				if err != nil {
					fmt.Println("        [!] Error when deleting file: ", f.Name)
					fmt.Println(err)
				}
			} else {
				fmt.Printf("        [+] %s is hash %s\n", f.Name, hash.Hash)
				err = os.Rename(f.Name, hash.Hash)
				if err != nil {
					fmt.Println("        [!] Error when renaming file: ", f.Name)
					fmt.Println(err)
				} else {
					found = true
				}
			}
		}
		if !found {
			fmt.Printf("        [!] Hash %s not found\n", hash.Hash)
			err = os.Remove(hash.Hash)
			if err != nil {
				fmt.Println("        [!] Error when deleting file: ", hash.Hash)
				fmt.Println(err)
			}
			return false, ""
		} else {
			fmt.Printf("      [+] Found %s\n", hash.Hash)
			return true, hash.Hash
		}
	} else {
		fmt.Printf("    [+] Downloaded %s\n", hash.Hash)
		return true, hash.Hash
	}
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
		fmt.Printf("    [+] Downloaded %s\n", hash.Hash)
		return true, hash.Hash
	} else if response.StatusCode == http.StatusForbidden {
		fmt.Printf("    [!] Not authorized.  Check the URL and APIKey in the config.\n")
		return false, ""
	} else {
		return false, ""
	}
}

func malwareBazaar(uri string, hash Hash, doNotExtract bool, password string) (bool, string) {
	if hash.HashType != sha256 {
		fmt.Printf("    [-] Looking up sha256 hash for %s\n", hash.Hash)

		query := "query=get_file&hash=" + hash.Hash
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

		if response.StatusCode == http.StatusForbidden {
			fmt.Printf("    [!] Not authorized.  Check the URL and APIKey in the config.\n")
			return false, ""
		}

		byteValue, _ := io.ReadAll(response.Body)

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
		hash.HashType = sha256
		fmt.Printf("    [-] Using hash %s\n", hash.Hash)

	}

	if hash.HashType == sha256 {
		return malwareBazaarDownload(uri, hash, doNotExtract, password)
	}
	return false, ""
}

func malwareBazaarDownload(uri string, hash Hash, doNotExtract bool, password string) (bool, string) {
	query := "query=get_file&sha256_hash=" + hash.Hash
	values, err := url.ParseQuery(query)
	if err != nil {
		fmt.Println(err)
		return false, ""
	}

	client := &http.Client{}

	response, err := client.PostForm(uri, values)
	if err != nil {
		fmt.Println(err)
		return false, ""
	}

	defer response.Body.Close()

	if response.Header["Content-Type"][0] == "application/json" {
		if response.StatusCode == http.StatusMethodNotAllowed {
			if !strings.HasSuffix(uri, "/") {
				fmt.Printf("    [!] Trying again with a trailing slash: %s/\n", uri)
				return malwareBazaarDownload(uri+"/", hash, doNotExtract, password)
			} else {
				fmt.Printf("    [!] Normally the response code: %s means that the provided URL %s needs a trailing slash (to avoid the redirect), but this already has a trailing slash.\nPlease file a bug report at https://github.com/xorhex/mlget/issues\n", response.Status, uri)
			}
		} else {
			fmt.Printf("    [!] %s\n", response.Status)
		}
		return false, ""
	}

	err = writeToFile(response.Body, hash.Hash+".zip")
	if err != nil {
		fmt.Println(err)
		return false, ""
	}

	fmt.Printf("    [+] Downloaded %s\n", hash.Hash+".zip")
	if doNotExtract {
		return true, hash.Hash + ".zip"
	} else {
		fmt.Println("    [-] Extracting...")
		files, err := extractPwdZip(hash.Hash+".zip", password, true, hash)
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

func filescanio(uri string, api string, hash Hash, doNotExtract bool, password string) (bool, string) {
	if api == "" {
		fmt.Println("    [!] !! Missing Key !!")
		return false, ""
	}
	return filescaniodownload(uri, api, hash, doNotExtract, password)
}

func filescaniodownload(uri string, api string, hash Hash, doNotExtract bool, password string) (bool, string) {
	query := "type=raw"
	_, error := url.ParseQuery(query)
	if error != nil {
		fmt.Println(error)
		return false, ""
	}

	request, error := http.NewRequest("GET", uri+"/files/"+url.PathEscape(hash.Hash)+"?"+query, nil)
	if error != nil {
		fmt.Println(error)
		return false, ""
	}

	request.Header.Set("X-Api-Key", api)

	client := &http.Client{}
	response, error := client.Do(request)
	if error != nil {
		fmt.Println(error)
		return false, ""
	}

	defer response.Body.Close()

	if response.StatusCode == 404 {
		return false, ""
	} else if response.StatusCode == 422 {
		fmt.Printf("    [!] Validation Error.\n")
		return false, ""
	} else if response.StatusCode == http.StatusForbidden {
		fmt.Printf("    [!] Not authorized.  Check the URL and APIKey in the config.\n")
		fmt.Printf("    [!] If you are sure this is correct, then test downloading a sample you've access to in their platform. It should work.\n")
		fmt.Printf("    [!] Not sure why it does not just return a 404 instead; when the creds are correct but the file is not available.\n")
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
		files, err := extractPwdZip(hash.Hash+".zip", password, true, hash)
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

func vxshare(uri string, api string, hash Hash, doNotExtract bool, password string) (bool, string) {
	if api == "" {
		fmt.Println("    [!] !! Missing Key !!")
		return false, ""
	}
	return vxsharedownload(uri, api, hash, doNotExtract, password)
}

func vxsharedownload(uri string, api string, hash Hash, doNotExtract bool, password string) (bool, string) {
	query := "apikey=" + url.QueryEscape(api) + "&hash=" + url.QueryEscape(hash.Hash)
	_, error := url.ParseQuery(query)
	if error != nil {
		fmt.Println(error)
		return false, ""
	}

	client := &http.Client{}
	response, error := client.Get(uri + "/download?" + query)
	if error != nil {
		fmt.Println(error)
		return false, ""
	}

	defer response.Body.Close()

	if response.StatusCode == 404 {
		return false, ""
	} else if response.StatusCode == 204 {
		fmt.Printf("    [!] Request rate limit exceeded. You are making more requests than are allowed or have exceeded your quota.\n")
		return false, ""
	} else if response.StatusCode == http.StatusForbidden {
		fmt.Printf("    [!] Not authorized.  Check the URL and APIKey in the config.\n")
		return false, ""
	}

	error = writeToFile(response.Body, hash.Hash+".zip")
	if error != nil {
		fmt.Println(error)
		return false, ""
	}

	fmt.Printf("    [+] Downloaded %s\n", hash.Hash)
	if doNotExtract {
		return true, hash.Hash + ".zip"
	} else {
		fmt.Println("    [-] Extracting...")
		files, err := extractPwdZip(hash.Hash+".zip", password, true, hash)
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

func unpacme(uri string, api string, hash Hash) (bool, string) {
	if api == "" {
		fmt.Println("    [!] !! Missing Key !!")
		return false, ""
	}

	if hash.HashType != sha256 {
		fmt.Printf("    [!] UnpacMe only supports SHA256\n        Skipping\n")
		return false, ""
	}

	return unpacmeDownload(uri, api, hash)
}

func unpacmeDownload(uri string, api string, hash Hash) (bool, string) {
	request, error := http.NewRequest("GET", uri+"/private/download/"+url.PathEscape(hash.Hash), nil)
	if error != nil {
		fmt.Println(error)
		return false, ""
	}

	request.Header.Set("Authorization", "Key "+api)

	client := &http.Client{}
	response, error := client.Do(request)
	if error != nil {
		fmt.Println(error)
		return false, ""
	}

	defer response.Body.Close()

	if response.StatusCode == 404 {
		return false, ""
	} else if response.StatusCode == http.StatusForbidden {
		fmt.Printf("    [!] Not authorized.  Check the URL and APIKey in the config.\n")
		return false, ""
	} else if response.StatusCode == http.StatusUnauthorized {
		fmt.Printf("    [!] Not authorized.  Check the URL and APIKey in the config.\n")
		return false, ""
	}

	error = writeToFile(response.Body, hash.Hash)
	if error != nil {
		fmt.Println(error)
		return false, ""
	}
	fmt.Printf("    [+] Downloaded %s\n", hash.Hash)
	return true, hash.Hash
}

func urlscanio(uri string, api string, hash Hash) (bool, string) {
	if api == "" {
		fmt.Println("    [!] !! Missing Key !!")
		return false, ""
	}

	if hash.HashType != sha256 {
		fmt.Printf("    [!] URLScanIO only supports SHA256\n        Skipping\n")
	}

	return urlscanioDownload(uri, api, hash)
}

func urlscanioDownload(uri string, api string, hash Hash) (bool, string) {
	//downloads/<sha256>"
	request, error := http.NewRequest("GET", uri+"/"+url.PathEscape(hash.Hash)+"/", nil)
	if error != nil {
		fmt.Println(error)
		return false, ""
	}

	request.Header.Set("API-Key", api)

	client := &http.Client{}
	response, error := client.Do(request)
	if error != nil {
		fmt.Println(error)
		return false, ""
	}

	defer response.Body.Close()

	if response.StatusCode == 404 {
		return false, ""
	} else if response.StatusCode == http.StatusForbidden {
		fmt.Printf("    [!] Not authorized.  Check the URL and APIKey in the config.\n")
		return false, ""
	}

	error = writeToFile(response.Body, hash.Hash)
	if error != nil {
		fmt.Println(error)
		return false, ""
	}
	fmt.Printf("    [+] Downloaded %s\n", hash.Hash)
	return true, hash.Hash
}

func malpedia(uri string, api string, hash Hash) (bool, string) {
	if api == "" {
		fmt.Println("    [!] !! Missing Key !!")
		return false, ""
	}

	if hash.HashType == sha1 {
		fmt.Printf("    [!] Malpedia only supports MD5 and SHA256\n        Skipping\n")
	}

	return malpediaDownload(uri, api, hash)

}

func malpediaDownload(uri string, api string, hash Hash) (bool, string) {
	///get/sample/<md5>/raw
	// Malpedia returns a json file of the file and all of the related files (base64 encoded)
	// No way to determine which file is which, so hashing each file found to identify the correct file
	request, error := http.NewRequest("GET", uri+"/get/sample/"+url.PathEscape(hash.Hash)+"/raw", nil)
	if error != nil {
		fmt.Println(error)
		return false, ""
	}

	request.Header.Set("Authorization", "apitoken "+api)

	client := &http.Client{}
	response, error := client.Do(request)
	if error != nil {
		fmt.Println(error)
		return false, ""
	}

	defer response.Body.Close()

	if response.StatusCode == 404 {
		return false, ""
	} else if response.StatusCode == http.StatusForbidden {
		fmt.Printf("    [!] Not authorized.  Check the URL and APIKey in the config.\n")
		return false, ""
	}

	byteValue, _ := io.ReadAll(response.Body)
	jsonParseSuccesful, mpData := parseMalpediaJson(byteValue)
	if jsonParseSuccesful {
		for _, item := range mpData {
			match, _ := hash.Validate(item.FileBytes)
			if match {
				error = writeBytesToFile(item.FileBytes, hash.Hash)
				if error != nil {
					fmt.Println(error)
					return false, ""
				}
				fmt.Printf("    [+] Downloaded %s\n", hash.Hash)
				return true, hash.Hash
			}
		}
	}
	return false, ""
}

func parseMalpediaJson(byteValue []byte) (bool, []MalpediaData) {
	// Code copied and modified fromm https://gist.github.com/mjohnsullivan/24647cae50928a34b5cc
	// Unmarshal using a generic interface
	var f interface{}
	err := json.Unmarshal(byteValue, &f)
	if err != nil {
		fmt.Println("Error parsing JSON: ", err)
		return false, nil
	}

	// JSON object parses into a map with string keys
	itemsMap := f.(map[string]interface{})
	var malpediaJsonItems []MalpediaData

	for key := range itemsMap {
		var item MalpediaData
		item.Name = key
		rawDecodedValue, err := base64.StdEncoding.DecodeString(itemsMap[key].(string))
		if err != nil {
			fmt.Println("Error base64 decoding the json value: ", err)
			return false, nil
		}
		item.FileBytes = rawDecodedValue
		malpediaJsonItems = append(malpediaJsonItems, item)
	}
	return true, malpediaJsonItems
}

func assemblyline(uri string, user string, api string, ignoretlserrors bool, hash Hash) (bool, string) {
	if api == "" {
		fmt.Println("    [!] !! Missing Key !!")
		return false, ""
	}
	if user == "" {
		fmt.Println("    [!] !! Missing User !!")
		return false, ""
	}

	if hash.HashType != sha256 {
		fmt.Printf("    [-] Looking up sha256 hash for %s\n", hash.Hash)

		request, error := http.NewRequest("GET", uri+"/hash_search/"+url.PathEscape(hash.Hash)+"/", nil)
		if error != nil {
			fmt.Println(error)
			return false, ""
		}

		request.Header.Set("Content-Type", "application/json; charset=UTF-8")
		request.Header.Set("x-user", user)
		request.Header.Set("x-apikey", api)

		tr := &http.Transport{}
		if ignoretlserrors {
			fmt.Printf("    [!] Ignoring Certificate Errors.\n")
			tr.TLSClientConfig = &tls.Config{InsecureSkipVerify: true}
		}

		client := &http.Client{Transport: tr}
		response, error := client.Do(request)
		if error != nil {
			fmt.Println(error)
			return false, ""
		}
		defer response.Body.Close()

		if response.StatusCode == http.StatusForbidden || response.StatusCode == http.StatusUnauthorized {
			fmt.Printf("    [!] Not authorized.  Check the URL, User, and APIKey in the config.\n")
			return false, ""
		}

		byteValue, _ := io.ReadAll(response.Body)

		var data = AssemblyLineQuery{}
		error = json.Unmarshal(byteValue, &data)

		if error != nil {
			fmt.Println(error)
			return false, ""
		}

		if data.Response.AL == nil {
			return false, ""
		}
		hash.Hash = data.Response.AL.Items[0].Data.Sha256
		hash.HashType = sha256
		fmt.Printf("    [-] Using hash %s\n", hash.Hash)
	}

	return assemblylineDownload(uri, user, api, ignoretlserrors, hash)

}

func assemblylineDownload(uri string, user string, api string, ignoretlserrors bool, hash Hash) (bool, string) {
	request, error := http.NewRequest("GET", uri+"/file/download/"+url.PathEscape(hash.Hash)+"/?encoding=raw", nil)
	if error != nil {
		fmt.Println(error)
		return false, ""
	}

	request.Header.Set("Content-Type", "application/json; charset=UTF-8")
	request.Header.Set("x-user", user)
	request.Header.Set("x-apikey", api)

	tr := &http.Transport{}
	if ignoretlserrors {
		tr.TLSClientConfig = &tls.Config{InsecureSkipVerify: true}
	}

	client := &http.Client{Transport: tr}
	response, error := client.Do(request)
	if error != nil {
		fmt.Println(error)
		return false, ""
	}

	defer response.Body.Close()

	if response.StatusCode == http.StatusNotFound {
		return false, ""
	} else if response.StatusCode == http.StatusForbidden {
		fmt.Printf("    [!] Not authorized.  Check the URL, User, and APIKey in the config.\n")
		return false, ""
	} else if response.StatusCode == http.StatusUnauthorized {
		fmt.Printf("    [!] Not authorized.  Check the URL, User, and APIKey in the config.\n")
		return false, ""
	}

	error = writeToFile(response.Body, hash.Hash)
	if error != nil {
		fmt.Println(error)
		return false, ""
	}
	fmt.Printf("    [+] Downloaded %s\n", hash.Hash)
	return true, hash.Hash
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

func extractPwdZip(file string, password string, renameFileAsHash bool, hash Hash) ([]*zip.File, error) {

	r, err := zip.OpenReader(file)
	if err != nil {
		log.Fatal(err)
	}
	defer r.Close()

	files := r.File

	for _, f := range r.File {
		if f.IsEncrypted() {
			f.SetPassword(password)
		}

		r, err := f.Open()
		if err != nil {
			log.Fatal(err)
		}

		var name string

		if !renameFileAsHash {
			name = f.Name
		} else {
			name = hash.Hash
		}

		out, error := os.Create(name)
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

func findHashInObjectiveSeeList(list []ObjectiveSeeData, hash Hash) (ObjectiveSeeData, bool) {
	for _, item := range list {
		if item.Sha256 == hash.Hash {
			return item, true
		}
	}
	return ObjectiveSeeData{}, false
}

func writeBytesToFile(bytes []byte, filename string) error {
	// Create the file
	out, err := os.Create(filename)
	if err != nil {
		return err
	}
	defer out.Close()

	_, err = out.Write(bytes)
	return err
}
