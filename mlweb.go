package main

import (
	"fmt"
	"log"
	"net/http"
	"strings"
	"text/template"
)

type Page struct {
	hashes   []string
	tags     []string
	comments []string
}

func indexHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method == "POST" {
		values := strings.Split(r.PostFormValue("hashes"), "\r\n")
		tags := strings.Split(r.PostFormValue("tags"), "\r\n")
		comments := strings.Split(r.PostFormValue("comments"), "\r\n")
		go processMalwareDownloadRequest(values, tags, comments)
	}
	t, _ := template.ParseFiles("./web/templates/index.html")
	t.Execute(w, nil)
}

func processMalwareDownloadRequest(values []string, tags []string, comments []string) {
	hashes := parseArgHashes(values, tags, comments)
	downloadMalwareFromWebServer(hashes)
}

func runWebServer(bind string, port int) {

	http.HandleFunc("/styles/style.css", func(response http.ResponseWriter, request *http.Request) {
		http.ServeFile(response, request, "./web/styles/style.css")
	})

	http.HandleFunc("/scripts/script.js", func(response http.ResponseWriter, request *http.Request) {
		http.ServeFile(response, request, "./web/scripts/script.js")
	})

	http.HandleFunc("/", indexHandler)

	//http.HandleFunc("/download", postDataHandler)

	log.Fatal(http.ListenAndServe(fmt.Sprint(bind, ":", port), nil))
}
