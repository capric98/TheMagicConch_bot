package main

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
	"time"
)

var SettingsPack map[string]string
var API_URL = ""

func SaveSettings() {
	json_file, _ := json.MarshalIndent(SettingsPack, "", "  ")
	ioutil.WriteFile("Settings.json", json_file, 0600)
}

func BotValidation() bool {
	resp, err := http.Get(API_URL + "getMe")
	if err != nil {
		fmt.Println(err)
	}
	defer resp.Body.Close()
	body, _ := ioutil.ReadAll(resp.Body)
	var obj interface{}
	json.Unmarshal([]byte(string(body)), &obj)
	return obj.(map[string]interface{})["ok"].(bool)
}

func NeedReply(uid, cid, text string) (bool, string) {
	return false, ""
}

// func Reply() {
// }

func UpdateMessages() string {
	resp, err := http.Get(API_URL + "getUpdates?offset=" + SettingsPack["Last_update_id"])
	if err != nil {
		fmt.Println(err)
		return SettingsPack["Last_update_id"]
	}
	defer resp.Body.Close()
	//body, _ := ioutil.ReadAll(resp.Body)

	var obj interface{}
	Decoder := json.NewDecoder(resp.Body)
	Decoder.UseNumber()
	Decoder.Decode(&obj)
	result := obj.(map[string]interface{})["result"]
	var max_update_id int
	for _, val := range result.([]interface{}) {
		message_block := val.(map[string]interface{})
		//fmt.Println(message_block)
		if current_update_id, _ := message_block["update_id"].(json.Number).Int64(); int(current_update_id) > max_update_id {
			max_update_id = int(current_update_id)
		}
		message_block = message_block["message"].(map[string]interface{})
		mtext := message_block["text"].(string)
		mfromid := message_block["from"].(map[string]interface{})["id"].(json.Number).String()
		mchatid := message_block["chat"].(map[string]interface{})["id"].(json.Number).String()
		// fmt.Println("In chat " + mchatid + " " + mfromid + " says \"" + mtext + "\"")
		if flag, rtext := NeedReply(mfromid, mchatid, mtext); flag {
			//Reply(mfromid, mchatid, rtext)
			print(rtext)
		}
	}
	//return strconv.Itoa(max_update_id + 1)
	return "0"
	//fmt.Println(time.Now().Unix())
	// return a new Last_update_id
}

func SleepMode() string {
	return SettingsPack["Last_update_id"]
	// return a Last_update_id
}

func StartBot() {
	var NewUpdateID string
	for {
		for IdleTimes := 0; IdleTimes < 3; {
			NewUpdateID = UpdateMessages()
			if NewUpdateID == SettingsPack["Last_update_id"] {
				IdleTimes += 1
			} else {
				IdleTimes = 0
				SaveSettings()
			}
			time.Sleep(1 * time.Second)
		}
		// Idle 3 times, run sleep mode
		SettingsPack["Last_update_id"] = SleepMode()
		SaveSettings()
	}
}

func main() {
	os.Setenv("HTTP_PROXY", "http://127.0.0.1:10086")
	os.Setenv("HTTPS_PROXY", "http://127.0.0.1:10086")
	var API_TOKEN, Last_update_id string

	if _, err := os.Stat("Settings.json"); err == nil {
		fmt.Println("Settings.json exists!")
		json_file, _ := ioutil.ReadFile("Settings.json")
		json.Unmarshal([]byte(json_file), &SettingsPack)
		fmt.Println("Token: " + SettingsPack["Token"])
		fmt.Println("Last id: " + SettingsPack["Last_update_id"])

		API_TOKEN = SettingsPack["Token"]
		Last_update_id = SettingsPack["Last_update_id"]
	} else if os.IsNotExist(err) {
		fmt.Println("Please input telegram bot API token:")
		Last_update_id = "0"
		fmt.Scanf("%s", &API_TOKEN)
	}

	API_URL = "https://api.telegram.org/bot" + API_TOKEN + "/"
	if BotValidation() {
		SettingsPack["Token"] = API_TOKEN
		SettingsPack["Last_update_id"] = Last_update_id
		SaveSettings()
		StartBot()
	} else {
		fmt.Println("The given API Token is not valid, please check it!")
	}
}
