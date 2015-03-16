package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/md5"
	"crypto/sha1"
	"encoding/base64"
	"fmt"
	"io/ioutil"
	"os"

	"golang.org/x/crypto/pbkdf2"
	"gopkg.in/yaml.v2"
)

type Installation struct {
	Data string `yaml:":data"`
	Salt string `yaml:":salt"`
	Iv   string `yaml:":iv"`
	Md5  string `yaml:":md5"`
}

func main() {
	text, err := decrypt()
	if err != nil {
		fmt.Println(err)
	}
	fmt.Println(text)
}

func decrypt() (text string, err error) {
	file, err := os.Open("installation.yml")
	if err != nil {
		return
	}
	data, err := ioutil.ReadAll(file)
	if err != nil {
		return
	}
	ins := Installation{}
	err = yaml.Unmarshal(data, &ins)
	if err != nil {
		return
	}
	key := pbkdf2.Key([]byte("welcome"), []byte(ins.Salt), 4096, 32, sha1.New)
	block, err := aes.NewCipher(key)
	if err != nil {
		fmt.Println("error")
		return
	}
	ivData, err := base64.StdEncoding.DecodeString(ins.Iv)
	if err != nil {
		return
	}
	encryptedData, err := base64.StdEncoding.DecodeString(ins.Data)
	if err != nil {
		return
	}
	var decryptData []byte = []byte(encryptedData)
	mode := cipher.NewCBCDecrypter(block, ivData)

	mode.CryptBlocks(decryptData, []byte(encryptedData))
	unpadData := PKCS5UnPadding(decryptData)
	fmt.Printf("%x", md5.Sum(unpadData))
	return (string(unpadData)), nil
}

func PKCS5UnPadding(src []byte) []byte {
	length := len(src)
	unpadding := int(src[length-1])
	return src[:(length - unpadding)]
}
