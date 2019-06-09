package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"math"
	"math/rand"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"time"
)

type MessageType struct {
	chatid, mid, fromid, text string
	date                      int64
	update_id                 int
	is_reply                  bool
	reply_to_username         string
}
type MLogType struct {
	TimeStamp int64
	next      *MLogType
}

var SettingsPack map[string]string
var API_URL, RPC_Token, Last_update_id, p, SleepTime = "", "", "0", 0.5, 30
var QLogTimeout int64
var QLog = make(map[string](*MLogType))
var tgServer = http.Client{
	Timeout: time.Duration(5 * time.Second),
}
var letters = []rune("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ")

func SaveSettings() {
	json_file, _ := json.MarshalIndent(SettingsPack, "", "  ")
	ioutil.WriteFile("Settings.json", json_file, 0600)
}

func randSeq(n int) string {
	b := make([]rune, n)
	for i := range b {
		b[i] = letters[rand.Intn(len(letters))]
	}
	return string(b)
}

func BotValidation() bool {
	resp, err := tgServer.Get(API_URL + "getMe")
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
	var result []interface{}
	if obj.(map[string]interface{})["result"] != nil {
		result = obj.(map[string]interface{})["result"].([]interface{})
	} else {
		result = make([]interface{}, 0, 1)
		result = append(result, obj)
	}

	length := len(result)
	Messages := make([]MessageType, 0, length)

	for _, val := range result {
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
		mdate, _ := message_block["date"].(json.Number).Int64()
		mid := message_block["message_id"].(json.Number).String()
		mfromid := message_block["from"].(map[string]interface{})["id"].(json.Number).String()
		mchatid := message_block["chat"].(map[string]interface{})["id"].(json.Number).String()

		if message_block["reply_to_message"] != nil {
			is_reply = true
			if message_block["reply_to_message"].(map[string]interface{})["from"].(map[string]interface{})["is_bot"].(bool) == true {
				reply_to_username = message_block["reply_to_message"].(map[string]interface{})["from"].(map[string]interface{})["username"].(string)
			} else {
				reply_to_username = ""
			}

		} else {
			is_reply = false
			reply_to_username = ""
		}

		Messages = append(Messages, MessageType{mchatid, mid, mfromid, mtext, mdate, int(update_id), is_reply, reply_to_username})
	}

	return Messages, length
}

func isQuestion(uid, text string) (bool, string) {
	if strings.Contains(text, "为什么") || strings.Contains(text, "为啥") || strings.Contains(text, "怎么回事") {
		return true, ""
	} else {
		if strings.Contains(text, "不知道") && strings.Contains(text, "只") {
			return false, "谁说的！"
		}
		if strings.Contains(text, "海螺") && strings.Contains(text, "傻") {
			return false, "你才是！"
		}
	}
	return false, ""
}

func MaintainQLog(uid string, mdate int64) bool {
	count := 1.0
	TimeStamp := time.Now().Unix()
	queue := QLog[uid]
	var last *MLogType
	for queue != nil {
		if TimeStamp-queue.TimeStamp > QLogTimeout {
			if last == nil {
				QLog[uid] = queue.next
				queue = queue.next
			} else {
				last.next = queue.next
				queue = queue.next
			}
		} else {
			count += 1
			last = queue
			queue = queue.next
		}
	}
	if QLog[uid] == nil {
		QLog[uid] = &MLogType{mdate, nil}
	} else {
		last.next = new(MLogType)
		last.next.TimeStamp = mdate
		last.next.next = nil
	}

	fmt.Println("user " + uid + " counts: " + strconv.Itoa(int(count)))
	random_x := rand.Float64()
	fmt.Println(random_x, " vs ", 1-math.Pow((1-p), count))

	if random_x < 1-math.Pow((1-p), count) {
		QLog[uid] = QLog[uid].next // count - 1
		return true
	} else {
		return false
	}
}

func Reply(chid, mid, text string) {
	funcURL := API_URL + "sendmessage?chat_id=" + chid + "&text=" + text
	tgServer.Get(API_URL + "sendChatAction?chat_id=" + chid + "&action=typing")
	if mid != "notreply" {
		funcURL = funcURL + "&reply_to_message_id=" + mid
	}
	time.Sleep(1 * time.Second) // +1s
	tgServer.Get(funcURL)
}

func UpdateMessages(jsonbody *json.Decoder) string {
	Messages, messagelen := JsonParse(jsonbody)
	var max_update_id = 0

	for i := 0; i < messagelen; i++ {
		m := Messages[i]
		fmt.Println("UID="+m.fromid+" says \""+m.text+"\" at time:", m.date)
		fmt.Println("Last_update_id=" + Last_update_id + " VS Update_id=" + strconv.Itoa(m.update_id))
		if m.update_id > max_update_id {
			max_update_id = m.update_id
		}
		if flag, rtext := isQuestion(m.fromid, m.text); flag {
			if (m.is_reply && m.reply_to_username == "TheMagicConch_bot") || strings.Contains(m.text, "@TheMagicConch_bot") {
				go Reply(m.chatid, "notreply", "不知道！")
			} else if MaintainQLog(m.fromid, m.date) {
				go Reply(m.chatid, m.mid, "不如问问神奇海螺")
			}
		} else {
			if (m.is_reply && m.reply_to_username == "TheMagicConch_bot") || strings.Contains(m.text, "@TheMagicConch_bot") {
				go Reply(m.chatid, "notreply", "不懂啊。。")
			} else if rtext != "" {
				go Reply(m.chatid, "notreply", rtext)
			}
		}
	}
	if max_update_id != 0 {
		return strconv.Itoa(max_update_id + 1)
	} else {
		return Last_update_id
	}
}

func makebotHandler(Done chan bool) func(http.ResponseWriter, *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/"+RPC_Token {
			http.Error(w, "Bad request.", http.StatusBadRequest)
			return
		}

		switch r.Method {
		case "POST":
			Last_update_id = UpdateMessages(json.NewDecoder(r.Body))
			Done <- true
		default:
			http.Error(w, "Only support POST method.", http.StatusBadRequest)
		}
	}
}

func SleepMode(WakeUpChan chan bool) {
	RPC_Token = randSeq(16)
	tgServer.Get(API_URL + "setWebhook?url=" + SettingsPack["RPC-URL"] + RPC_Token)
	fmt.Println("Sleeping...")
	select {
	case <-WakeUpChan:
		fmt.Println("Back to normal update via wakeup.")
		break
	case <-time.After(time.Duration(SleepTime) * time.Second):
		fmt.Println("Sleep over ", SleepTime, "s.")
		break
	}
	tgServer.Get(API_URL + "deleteWebhook")
}

func StartBot() {
	var NewUpdateID string
	WakeUpChan := make(chan bool)
	botHandler := makebotHandler(WakeUpChan)
	mux := http.NewServeMux()
	mux.HandleFunc("/", botHandler)
	// cfg := &tls.Config{
	// 	MinVersion:               tls.VersionTLS12,
	// 	CurvePreferences:         []tls.CurveID{tls.CurveP521, tls.CurveP384, tls.CurveP256},
	// 	PreferServerCipherSuites: true,
	// 	CipherSuites: []uint16{
	// 		tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
	// 		tls.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
	// 		tls.TLS_RSA_WITH_AES_256_GCM_SHA384,
	// 		tls.TLS_RSA_WITH_AES_256_CBC_SHA,
	// 	},
	// }
	srv := &http.Server{
		Addr:    "127.0.0.1:88",
		Handler: mux,
		//TLSConfig:    cfg,
		//TLSNextProto: make(map[string]func(*http.Server, *tls.Conn, http.Handler), 0),
	}
	//log.Fatal(srv.ListenAndServeTLS("tls.crt", "tls.key"))

	//fmt.Println("Start RPC!")
	go srv.ListenAndServe()
	defer srv.Shutdown(context.Background())

	for {
		for IdleTimes := 0; IdleTimes < 3; {
			resp, err := tgServer.Get(API_URL + "getUpdates?offset=" + Last_update_id)
			if err != nil {
				fmt.Println("Fail to get response from telegram server.")
			} else {
				NewUpdateID = UpdateMessages(json.NewDecoder(resp.Body))
				if NewUpdateID == Last_update_id {
					IdleTimes += 1
				} else {
					IdleTimes = 0
					Last_update_id = NewUpdateID
				}
			}
			defer resp.Body.Close()
			//fmt.Println("Normal work.")
			//time.Sleep(1 * time.Second)
		}
		// Idle 3 times, run sleep mode
		SleepMode(WakeUpChan)
	}
}

func main() {
	var API_TOKEN string

	if _, err := os.Stat("Settings.json"); err == nil {
		fmt.Println("Settings.json exists!")
		json_file, _ := ioutil.ReadFile("Settings.json")
		json.Unmarshal([]byte(json_file), &SettingsPack)
		fmt.Println("Token: " + SettingsPack["Token"])

		API_TOKEN = SettingsPack["Token"]
		if SettingsPack["ProxyPort"] != "" {
			os.Setenv("HTTP_PROXY", "http://127.0.0.1:"+SettingsPack["ProxyPort"])
			os.Setenv("HTTPS_PROXY", "http://127.0.0.1:"+SettingsPack["ProxyPort"])
		}
	} else if os.IsNotExist(err) {
		fmt.Println("Please input telegram bot API token:")
		Last_update_id = "0"
		fmt.Scanf("%s", &API_TOKEN)
		SettingsPack = make(map[string]string, 10)
		SettingsPack["Token"] = API_TOKEN
		SettingsPack["Possibility"] = "0.5"
		SettingsPack["QLogTimeout"] = "600"
		SettingsPack["RPC-URL"] = "https://sample.com/bot/"
		SettingsPack["SleepTime"] = "30"
		SettingsPack["ProxyPort"] = ""
		SaveSettings()
	}

	API_URL = "https://api.telegram.org/bot" + API_TOKEN + "/"
	if BotValidation() {
		//SaveSettings()
		SleepTime, _ = strconv.Atoi(SettingsPack["SleepTime"])
		p, _ = strconv.ParseFloat(SettingsPack["Possibility"], 64)
		QLogTimeout, _ = strconv.ParseInt(SettingsPack["QLogTimeout"], 10, 64)

		tgServer.Get(API_URL + "deleteWebhook")
		qsignal := make(chan error, 2)
		go func() {
			c := make(chan os.Signal)
			signal.Notify(c, os.Interrupt)
			qsignal <- fmt.Errorf("%s", <-c)
		}() // Receive system signal.
		go StartBot()

		<-qsignal
		fmt.Println("Normally stop.")
		tgServer.Get(API_URL + "deleteWebhook")
		SaveSettings()
	} else {
		fmt.Println("The given API Token is not valid, please check it!")
	}
}
