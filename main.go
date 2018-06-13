package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/md5"
	"crypto/sha256"
	"encoding/base64"
	"log"

	"golang.org/x/crypto/pbkdf2"
)

func main() {
	// 1.8
	str, err := decrypt18("W9gqsW+Z+tcE61WDFbuCPvdzJIHgv5cILkTJzZWAtBhga5hfnI9Q5YNt6MZSzSI1", "153ce768", "W_XislJAhmKDiMQT7oHybm63_yyd9HLG")
	if err != nil {
		log.Fatal(err)
	}
	log.Printf("Foundation 1.8 autoscale password :%s", str)
	// 2.1
	str, err = decrypt("igNofYRgGrq8i9su+5mNYTrc+YIDw3NUIgIuPkRBhkx3Z9Y+EJKXDAu++WXaK7+r", "359f7a8c88fe1aea", "zP2vzTyH_wvwH-NlhSFTn2vB88QQT3Mf")
	if err != nil {
		log.Fatal(err)
	}
	log.Printf("Foundation 2.1 credhub password :%s", str)
}

var openSSLSaltHeader string = "Salted_"

type OpenSSLCreds struct {
	key []byte
	iv  []byte
}

func decrypt18(data, salt, encryptKey string) (string, error) {
	creds, err := extractOpenSSLCreds([]byte(encryptKey), []byte(salt))
	if err != nil {
		return "", err
	}
	block, err := aes.NewCipher(creds.key)
	if err != nil {
		return "", err
	}
	if err != nil {
		return "", err
	}
	encryptedData, err := base64.StdEncoding.DecodeString(data)
	if err != nil {
		return "", err
	}
	decryptData := encryptedData
	mode := cipher.NewCBCDecrypter(block, creds.iv)

	mode.CryptBlocks(decryptData, encryptedData)
	if err != nil {
		log.Print(err)
	}
	return (string(decryptData)), nil
}

func decrypt(data, salt, encryptKey string) (string, error) {
	key := pbkdf2.Key([]byte(encryptKey), []byte(salt), 2048, 16, sha256.New)
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}
	if err != nil {
		return "", err
	}
	encryptedData, err := base64.StdEncoding.DecodeString(data)
	if err != nil {
		return "", err
	}
	var decryptData = encryptedData
	mode := cipher.NewCBCDecrypter(block, []byte(salt))

	mode.CryptBlocks(decryptData, encryptedData)
	return (string(decryptData)), nil
}

func extractOpenSSLCreds(password, salt []byte) (OpenSSLCreds, error) {
	prev := []byte{}
	m0 := hash(prev, password, salt)
	for i := 1; i < 2048; i++ {
		m0 = md5sum(m0)
	}
	m1 := hash(m0, password, salt)
	for i := 1; i < 2048; i++ {
		m1 = md5sum(m1)
	}

	return OpenSSLCreds{key: m0, iv: m1}, nil
}

func hash(prev, password, salt []byte) []byte {
	a := make([]byte, len(prev)+len(password)+len(salt))
	copy(a, prev)
	copy(a[len(prev):], password)
	copy(a[len(prev)+len(password):], salt)
	return md5sum(a)
}

func md5sum(data []byte) []byte {
	h := md5.New()
	h.Write(data)
	return h.Sum(nil)
}
