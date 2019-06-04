package main

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
	"time"
)

var tgClient = &http.Client{Timeout: 10 * time.Second}

func main() {
	os.Setenv("HTTP_PROXY", "http://127.0.0.1:10086")
	os.Setenv("HTTPS_PROXY", "http://127.0.0.1:10086")
	var API_TOKEN string

	fmt.Println("Please input telegram bot API token:")
	fmt.Scanf("%s", &API_TOKEN)
	API_URL := "https://api.telegram.org/bot" + API_TOKEN + "/"
	fmt.Printf("API URL:%s\n", API_URL)

	resp, err := http.Get(API_URL + "getUpdates")
	if err != nil {
		fmt.Println(err)
	}
	defer resp.Body.Close()
	body, _ := ioutil.ReadAll(resp.Body)
	var obj interface{}
	json.Unmarshal([]byte(string(body)), &obj)
	fmt.Println(obj.(map[string]interface{})["ok"])
}
