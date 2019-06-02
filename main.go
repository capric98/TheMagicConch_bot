package main

import (
	"bufio"
	"fmt"
	"os"
)

func main() {
	os.Setenv("HTTP_PROXY", "http://127.0.0.1:10086")
	os.Setenv("HTTPS_PROXY", "http://127.0.0.1:10086")
	reader := bufio.NewReader(os.Stdin)
	fmt.Println("Please input telegram bot API token:")
	API_TOKEN, _ := reader.ReadString('\n')

	fmt.Printf("API Token:%s", API_TOKEN)
	reader.ReadString('\n')
}
