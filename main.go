package main

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/md5"
	"crypto/rand"
	"crypto/sha1"
	"encoding/base64"
	"encoding/hex"
	"flag"
	"fmt"
	"io/ioutil"
	"os"

	"github.com/datianshi/yaml"
	"golang.org/x/crypto/pbkdf2"
)

type Installation struct {
	Data string `yaml:":data,binary"`
	Salt string `yaml:":salt"`
	Iv   string `yaml:":iv,binary"`
	Md5  string `yaml:":md5"`
}

func main() {
	enc := flag.Bool("e", false, "encrypt")
	dec := flag.Bool("d", false, "decrypt")
	flag.Parse()
	if *enc {
		err := encrypt()
		if err != nil {
			fmt.Println(err)
		}
	}
	if *dec {
		text, err := decrypt()
		if err != nil {
			fmt.Println(err)
		}
		fmt.Println(text)
	}
}

func decrypt() (text string, err error) {
	file, err := os.Open("encrypted.yml")
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

func encrypt() (err error) {
	file, err := os.Open("installation.yml")
	if err != nil {
		return
	}
	data, err := ioutil.ReadAll(file)
	if err != nil {
		return
	}
	sum := md5.Sum(data)
	salt := generateSalt()
	key := pbkdf2.Key([]byte("welcome"), []byte(salt), 4096, 32, sha1.New)
	block, err := aes.NewCipher(key)
	if err != nil {
		return
	}
	ivData := generateIV(block.BlockSize())
	mode := cipher.NewCBCEncrypter(block, ivData)
	paddedData := PKCS5Padding(data, block.BlockSize())
	mode.CryptBlocks(paddedData, paddedData)
	ins := Installation{
		Data: string(paddedData),
		Iv:   string(ivData),
		Salt: salt,
		Md5:  hex.EncodeToString(sum[:]),
	}
	result, err := yaml.Marshal(&ins)
	if err != nil {
		return
	}
	fmt.Printf(string(result))
	return
}
func generateIV(size int) []byte {
	b := make([]byte, size)
	rand.Read(b)
	return b
}
func generateSalt() string {
	c := 10
	b := make([]byte, c)
	rand.Read(b)
	return hex.EncodeToString(b)
}

func PKCS5UnPadding(src []byte) []byte {
	length := len(src)
	unpadding := int(src[length-1])
	return src[:(length - unpadding)]
}
func PKCS5Padding(src []byte, blockSize int) []byte {
	padding := blockSize - len(src)%blockSize
	padtext := bytes.Repeat([]byte{byte(padding)}, padding)
	return append(src, padtext...)
}
