package cnnfirebase

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/url"
	"time"

	"cloud.google.com/go/firestore"
	firebase "firebase.google.com/go"

	"google.golang.org/api/iterator"
	"google.golang.org/api/option"
)

var opt = option.WithCredentialsFile("./nothing.json")
var app, err = firebase.NewApp(context.Background(), nil, opt)
var client, _ = app.Firestore(context.Background())

type Log4j struct {
	Domain string
	Time   time.Time
	Result string
}

func InsertData(test *Log4j) {
	if err != nil {
		return
	}
	u, _ := url.Parse(test.Domain)

	client.Collection("log4j-fuzzing").Doc(u.Host).Set(context.Background(), test)
	if err != nil {
		log.Fatal(err)
	}
}

func GetData() [][]byte {
	var data [][]byte = make([][]byte, 2)
	iter := client.Collection("log4j-fuzzing").OrderBy("Time", firestore.Desc).Limit(2).Documents(context.Background())
	i := 0
	for {
		doc, err := iter.Next()
		if err == iterator.Done {
			break
		}
		if err != nil {
			return nil
		}
		d, _ := json.Marshal(doc.Data())
		//fmt.Println(string(d))
		data[i] = d
		i++
	}
	return data
}

func DeleteData() {
	fmt.Println("This's deletedata function")
	// _, err := client.Collection("log4j-fuzzing").Doc("DC").Delete(context.Background())
	// if err != nil {
	//     // Handle any errors in an appropriate way, such as returning them.
	//     log.Printf("An error has occurred: %s", err)
	// }
}

func EditData() {
	fmt.Println("This's editdata function")
}
