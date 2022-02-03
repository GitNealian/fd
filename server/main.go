package main

import (
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"io/ioutil"
	"os/exec"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/gofrs/uuid"
)

// [clientId]ip
var CLIENTS map[string]string = map[string]string{}

// [clientId]key
var CLIENTS_KEY map[string]*rsa.PublicKey = map[string]*rsa.PublicKey{}

// [clientId]token
var CLIENTS_TOKEN map[string]string = map[string]string{}

func loadPublicKeys(path string) error {
	data, err := ioutil.ReadFile(path)
	if err != nil {
		return err
	}
	lines := string(data)
	for _, line := range strings.Split(lines, "\n") {
		if len(line) == 0 {
			continue
		}
		tokens := strings.Split(line, " ")
		if len(tokens) != 2 {
			continue
		}
		clientId := tokens[0]
		key := fmt.Sprintf("-----BEGIN RSA PUBLIC KEY-----\n%s\n-----END RSA PUBLIC KEY-----\n", tokens[1])
		block, _ := pem.Decode([]byte(key))
		if block == nil {
			return errors.New("public key error")
		}
		pubInterface, err := x509.ParsePKCS1PublicKey(block.Bytes)
		if err != nil {
			return err
		}
		CLIENTS_KEY[clientId] = pubInterface
	}
	fmt.Printf("%v\n", CLIENTS_KEY)
	return nil
}

func validate(clientId, tokenEncrypted string) (bool, error) {
	token, ok1 := CLIENTS_TOKEN[clientId]
	key, ok2 := CLIENTS_KEY[clientId]
	if !ok1 || !ok2 {
		return false, errors.New("client not exists")
	}

	sum := sha256.Sum256([]byte(token))
	sig, err := base64.RawStdEncoding.DecodeString(tokenEncrypted)
	if err != nil {
		return false, err
	}
	err = rsa.VerifyPKCS1v15(key, crypto.SHA256, sum[:], sig)
	return err == nil, err
}

func addRule(clientId, ip string) error {
	// remove old ip rule
	if ip_old, ok := CLIENTS[clientId]; ok {
		err := exec.Command("firewall-cmd", fmt.Sprintf(`--permanent --remove-rich-rule="rule family="ipv4" source address="%s" accept"`, ip_old)).Run()
		if err != nil {
			return err
		}
	}
	CLIENTS[clientId] = ip
	// add new ip rule
	err := exec.Command("firewall-cmd", fmt.Sprintf(`--permanent --add-rich-rule="rule family="ipv4" source address="%s" accept"`, ip)).Run()
	if err != nil {
		return err
	}
	// reload firewall-cmd
	err = exec.Command("firewall-cmd", "--reload").Run()
	if err != nil {
		return err
	}
	return nil
}

func addRuleFake(clientId, ip string) error {
	// remove old ip rule
	if ip_old, ok := CLIENTS[clientId]; ok {
		fmt.Printf("firewall-cmd --permanent --remove-rich-rule=\"rule family=\"ipv4\" source address=\"%s\" accept\"\n", ip_old)
	}
	CLIENTS[clientId] = ip
	// add new ip rule
	fmt.Printf("firewall-cmd --permanent --add-rich-rule=\"rule family=\"ipv4\" source address=\"%s\" accept\"\n", ip)

	// reload firewall-cmd
	fmt.Print("firewall-cmd --reload\n")
	return nil
}

func main() {
	clients := flag.String("clients", "clients.txt", "path of clients configure file")
	flag.Parse()
	err := loadPublicKeys(*clients)
	if err != nil {
		fmt.Printf("error load clients: %s\n", err.Error())
		return
	}

	r := gin.Default()
	// get token
	r.GET("/ding", func(c *gin.Context) {
		clientId := c.Query("clientId")
		if _, ok := CLIENTS_KEY[clientId]; !ok {
			c.JSON(500, gin.H{
				"msg": "client not exists",
			})
		}
		token, err := uuid.NewV4()
		if err != nil {
			c.JSON(500, gin.H{
				"msg": fmt.Sprintf("%s", err),
			})
			return
		}
		CLIENTS_TOKEN[clientId] = token.String()
		c.JSON(200, gin.H{
			"token": token,
		})
	})

	// upload ip
	r.GET("/dong", func(c *gin.Context) {
		sig := c.Query("sig")
		clientId := c.Query("clientId")
		if len(sig) == 0 || len(clientId) == 0 {
			c.JSON(403, gin.H{})
			return
		}
		ok, err := validate(clientId, sig)
		if err == nil && ok {
			addRule(clientId, c.ClientIP())
			c.JSON(200, gin.H{
				"message": "success",
			})
			return
		}
		fmt.Printf("%v\n", err)
		c.JSON(403, gin.H{
			"msg": "invalid parameters",
		})
	})
	r.Run(":7749")
}
