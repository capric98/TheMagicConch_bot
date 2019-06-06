package main

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"
)

var SettingsPack map[string]string
var API_URL = ""
var Last_update_id = "0"

type MessageType struct {
	chatid, mid, fromid, text string
	update_id                 int
	is_reply                  bool
	reply_to_username         string
}

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

func JsonParse(Decoder *json.Decoder) ([]MessageType, int) {
	var obj interface{}
	Decoder.UseNumber()
	Decoder.Decode(&obj)
	result := obj.(map[string]interface{})["result"]

	length := len(result.([]interface{}))
	Messages := make([]MessageType, 0, length)

	for _, val := range result.([]interface{}) {
		message_block := val.(map[string]interface{})
		update_id, _ := message_block["update_id"].(json.Number).Int64()
		if message_block["message"] != nil {
			message_block = message_block["message"].(map[string]interface{})
		} else if message_block["forward_message"] != nil {
			message_block = message_block["forward_message"].(map[string]interface{})
		} else if message_block["edited_message"] != nil {
			message_block = message_block["edited_message"].(map[string]interface{})
		} else {
			fmt.Println(message_block)
			message_block = nil
		}

		if message_block["text"] == nil {
			length -= 1
			continue
		}

		var is_reply bool
		var reply_to_username string
		mtext := message_block["text"].(string)
		mid := message_block["message_id"].(json.Number).String()
		mfromid := message_block["from"].(map[string]interface{})["id"].(json.Number).String()
		mchatid := message_block["chat"].(map[string]interface{})["id"].(json.Number).String()

		if message_block["reply_to_message"] != nil {
			is_reply = true
			reply_to_username = message_block["reply_to_message"].(map[string]interface{})["from"].(map[string]interface{})["username"].(string)
		} else {
			is_reply = false
			reply_to_username = ""
		}

		Messages = append(Messages, MessageType{mchatid, mid, mfromid, mtext, int(update_id), is_reply, reply_to_username})
	}

	return Messages, length
}

func isNeedReply(uid, text string) (bool, string) {
	if strings.Contains(text, "为什么") {
		return true, ""
	} else {
		return false, ""
	}

}

func Reply(chid, mid, text string) {
	funcURL := API_URL + "sendmessage?chat_id=" + chid + "&text=" + text
	if mid != "notreply" {
		funcURL = funcURL + "&reply_to_message_id=" + mid
	}
	//fmt.Println(funcURL)
	http.Get(funcURL)
}

func UpdateMessages() string {
	resp, err := http.Get(API_URL + "getUpdates?offset=" + Last_update_id)
	if err != nil {
		fmt.Println(err)
		return Last_update_id
	}
	defer resp.Body.Close()

	Messages, messagelen := JsonParse(json.NewDecoder(resp.Body))
	var max_update_id = 0

	for i := 0; i < messagelen; i++ {
		m := Messages[i]
		if m.update_id > max_update_id {
			max_update_id = m.update_id
		}
		if Messages[i].is_reply || strings.Contains(m.text, "@TheMagicConch_bot ") {
			Reply(m.chatid, "notreply", "不知道！")
		} else if flag, _ := isNeedReply(m.fromid, m.text); flag {
			Reply(m.chatid, m.mid, "不如问问神奇海螺")
		}
	}
	if max_update_id != 0 {
		return strconv.Itoa(max_update_id + 1)
	} else {
		return Last_update_id
	}
	//return "0"
	//fmt.Println(time.Now().Unix())
	// return a new Last_update_id
}

func SleepMode() string {
	return Last_update_id
	// return a Last_update_id
}

func StartBot() {
	var NewUpdateID string
	for {
		for IdleTimes := 0; IdleTimes < 3; {
			NewUpdateID = UpdateMessages()
			if NewUpdateID == Last_update_id {
				IdleTimes += 1
			} else {
				IdleTimes = 0
				Last_update_id = NewUpdateID
			}
			time.Sleep(1 * time.Second)
		}
		// Idle 3 times, run sleep mode
		Last_update_id = SleepMode()
	}
}

func main() {
	os.Setenv("HTTP_PROXY", "http://127.0.0.1:10086")
	os.Setenv("HTTPS_PROXY", "http://127.0.0.1:10086")
	var API_TOKEN string

	if _, err := os.Stat("Settings.json"); err == nil {
		fmt.Println("Settings.json exists!")
		json_file, _ := ioutil.ReadFile("Settings.json")
		json.Unmarshal([]byte(json_file), &SettingsPack)
		fmt.Println("Token: " + SettingsPack["Token"])

		API_TOKEN = SettingsPack["Token"]
	} else if os.IsNotExist(err) {
		fmt.Println("Please input telegram bot API token:")
		Last_update_id = "0"
		fmt.Scanf("%s", &API_TOKEN)
	}

	API_URL = "https://api.telegram.org/bot" + API_TOKEN + "/"
	if BotValidation() {
		SettingsPack["Token"] = API_TOKEN
		SaveSettings()
		StartBot()
	} else {
		fmt.Println("The given API Token is not valid, please check it!")
	}
}
