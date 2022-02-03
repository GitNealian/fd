package main

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"flag"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
	"strings"
)

func sign(token string, privateKey *rsa.PrivateKey) (string, error) {
	sum := sha256.Sum256([]byte(token))
	signed, err := rsa.SignPKCS1v15(rand.Reader, privateKey, crypto.SHA256, sum[:])
	if err != nil {
		return "", err
	}
	return base64.RawStdEncoding.EncodeToString(signed), nil
}

func main() {
	client := flag.String("client", "client.txt", "path of client configure file")
	server := flag.String("server", "39.106.53.74:7749", "server address")
	flag.Parse()
	fileData, err := ioutil.ReadFile(*client)
	if err != nil {
		println(err.Error())
		return
	}
	tokens := strings.Split(string(fileData), " ")
	if len(tokens) != 2 {
		println("invalid client configure file")
		return
	}

	clientId := tokens[0]
	privateKey := fmt.Sprintf("-----BEGIN RSA PRIVATE KEY-----\n%s\n-----END RSA PRIVATE KEY-----\n", tokens[1])

	block, _ := pem.Decode([]byte(privateKey))
	if block == nil {
		println("error decode private key")
		return
	}
	priv, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		println(err.Error())
		return
	}
	resp, err := http.Get(fmt.Sprintf("http://%s/ding?clientId=%s", *server, clientId))
	if err != nil {
		println(err.Error())
		return
	}
	defer resp.Body.Close()
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		println(err.Error())
		return
	}
	if resp.StatusCode == http.StatusOK {
		data := map[string]string{}
		err = json.Unmarshal(body, &data)
		if err != nil {
			println(err.Error())
			return
		}
		if token, ok := data["token"]; ok {
			signedString, err := sign(token, priv)
			if err != nil {
				println(err.Error())
				return
			}
			resp, err := http.Get(fmt.Sprintf("http://%s/dong?clientId=%s&sig=%s", *server, clientId, url.QueryEscape(signedString)))
			if err != nil {
				println(err.Error())
				return
			}
			defer resp.Body.Close()
			body, err := ioutil.ReadAll(resp.Body)
			if err != nil {
				println(err.Error())
				return
			}
			if resp.StatusCode == http.StatusOK {
				println("success")
				return
			} else {
				fmt.Printf("%s\n", body)
			}
		}
	} else {
		fmt.Printf("%s\n", body)
	}
}
