package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"io"
)

// For use  of the AES we have to generate the AES key which is symmetric key like
// both eceyption and decryption key are same that is AES key and this AES key can be encrypted by
// public key and decrypted by private key

// This contains the 14 rounds of the encryption
func checkError(e error) {
	if e != nil {
		fmt.Println(e.Error())
		return
	}
}

func encryptAESKey(aesKey []byte, publicKey rsa.PublicKey) []byte {
	encryptedKey, err := rsa.EncryptOAEP(sha256.New(), rand.Reader, &publicKey, aesKey, nil)
	checkError(err)
	return encryptedKey
}

func decryptAESKey(encryptedKey []byte, privateKey rsa.PrivateKey) []byte {
	aesKey, err := rsa.DecryptOAEP(sha256.New(), rand.Reader, &privateKey, encryptedKey, nil)
	checkError(err)
	return aesKey
}

func encryptSecreteMessage(secretMessage []byte, aesKey []byte) []byte {
	// lable := []byte("encrypt")
	// uptoRange := rand.Reader
	// cipherText, err := rsa.EncryptOAEP(sha256.New(), uptoRange, &publicKey, []byte(secretMessage), lable)
	// checkError(err)
	// return base64.StdEncoding.EncodeToString(cipherText)

	// This block provides methods to encrypt and decrypt data in blocks of a fixed size (16 bytes for AES).
	//  in easy language in creates the cipher block which is used for the ecryption and decrypting data
	block, err := aes.NewCipher(aesKey)
	checkError(err)
	fmt.Println("block :", block)

	// aes.BlockSize is add because of we have to consider the IV and the secret message in the cipherText
	cipherText := make([]byte, aes.BlockSize+len(secretMessage))

	fmt.Println("lenght of the cipherText : ", len(cipherText))
	// get the initialization vector
	iv := cipherText[:aes.BlockSize]
	fmt.Println("Initialization Vector before adding the random number : ", iv)

	_, err = io.ReadFull(rand.Reader, iv)
	fmt.Println("Initialization Vector before adding the random number : ", iv)

	checkError(err)
	// stream cipher is a cryptographic algorithm that encrypts one byte of plaintext at a time.
	stream := cipher.NewCFBEncrypter(block, iv)
	// the above stream generate the key stream and use to XOR the each byte of the secret message
	fmt.Println("stream : ", stream)
	stream.XORKeyStream(cipherText[aes.BlockSize:], secretMessage)
	return cipherText
}

func decryptSecreteMessage(cipherText []byte, aesKey []byte) []byte {
	// decryptMessage, err := base64.StdEncoding.DecodeString(cipherText)
	// checkError(err)
	// lable := []byte("encrypt")
	// uptoRange := rand.Reader
	// plainText, err := rsa.DecryptOAEP(sha256.New(), uptoRange, &privateKey, decryptMessage, lable)
	// checkError(err)
	// return string(plainText)

	block, err := aes.NewCipher(aesKey)
	checkError(err)
	fmt.Println("Block : ", block)

	if len(cipherText) < aes.BlockSize {
		panic("Ciphertext is too short")
	}

	iv := cipherText[:aes.BlockSize]
	cipherText = cipherText[aes.BlockSize:]
	stream := cipher.NewCFBDecrypter(block, iv)
	stream.XORKeyStream(cipherText, cipherText)
	return cipherText

}

func main() {

	// 1 byte = 8 bits
	// aes.BlockSize = 16 bytes = 16 * 8 = 128 bits and this is constants

	/*
		The purpose of the IV is to provide randomness to the encryption process,
		so that if the same plaintext is encrypted multiple times with the same key,
		the resulting ciphertext will be different each time. This helps to hide patterns
		in the data, making the encryption more secure.
	*/

	/*
		Cipher Feedback (CFB) mode is a mode of operation for block cipher encryption algorithms
		that allows them to be used in a manner similar to a stream cipher.
		CFB mode processes small increments of plaintext into ciphertext,
		instead of processing an entire block at a time.
		This is done by encrypting the previous ciphertext block and
		then applying a bitwise XOR operation to a part of the result
		and a part of the plaintext.

		Here's a simplified explanation of how CFB mode works:

		1. The encryption algorithm is applied to an initialization vector (IV).
		2. A segment of the output (the same length as the plaintext segment) is XORed with the plaintext to produce the ciphertext.
		3. The IV is shifted left by the same length as the plaintext segment, discarding the leftmost bits.
		4. The ciphertext is appended to the right side of the IV.
		5. Steps 1-4 are repeated until all plaintext is encrypted.
	*/

	secretMessage := []byte(`-----BEGIN RSA PRIVATE KEY-----
	MIIEowIBAAKCAQEAt7arlt5MBvdM3B98K84JkpSg8KGbRXi9FtPTFzH8mYK1vdZ0
	kkMyOzNVIQU8V2wUu4zGvC1qXoeBSZDvZavzZHSNtO3rQMp8uoNVKs/DD7ZprCkB
	AjfWEmtP1qhbZBiLMHaufpSREyXV6FcZukvudent4vPl2ie8gDQqbXH0EBloROEG
	2U3pzARLkBtBmgqpuq1jpmhSZ9teysJzEQUU95M2e93qkLFLDehPdasg+XFd9nUV
	RigYPPyRx0BfecWG0En8ePcv3lZt3tkrQeGC/hekfmNjrk/vbK8D0c3aZRYeRSrI
	g8ba5Fx8a0ZS5+su6KCtjgtWh3QMyuUhLLQ2fQIDAQABAoIBAGyxALgT8Ts12R1q
	61YnYnZ8xPNZSbpCgu0ciglxI5fXQ5t7ZCCc7P0lk7ojlN3MLkAAPBxdak9fMFjM
	DTdEEo5efvCKyuLcagsXZK4dmbSUIdUftV8QlfDz2JqRpPCFrOQRc4+kami/u9zo
	m2ojPoQ40OuzjUwSsm3Pb0KtZs6WmO5LKqweJJEuGJMmJ54op+BLBkOqFhJIQzeE
	KBdPetiBScFFFz4VlnVKuOYEoBDrFZSiIvtNJ92ZgeEvh4JIV61yIQAAabnlhvQu
	V7BRv6Vypm0Gnc8s0++slsrE19e02gl5DjJSC5XSgkOI+YikWtXkpaO5jB/ESokS
	eAMzeqkCgYEA04SbtdiIxJjzc/BU8zDmiY4zmYhTZLwD5pPwyyXhicSYowpGb25F
	QPu3OHC7N6j4uEmFYGZyAQJlIwKGGlh+XQJkEzggrEn3nq+LFhGb+fJ3ulB9oHXB
	/cCo/58U8vXkwD3QoxhBERiB75WIDJwj8QXC0RfU0TZzySyk+bHyD3MCgYEA3lkq
	6e6AqTzs4y7otnY9B5ErRUKd7d3szGwQhrZPQBc8G/oVWFUOgbaYkveXH0xbZTmi
	cr+R8RNPxip8tHyW8k5lAPESc7f5p89qvOW8EwpDO0xNFYOeftPAx+w85PmB+9zW
	wudXetv9QGfbyxXTE53BrBPDj7nsS+2at+AYRk8CgYA9bM0rSe6t6R0KFkkVNqY8
	XCdv9r8BCfi4BU5wMFgHAiixcFJ0GbnS3UagBVzZFSDlo7QwApAo6uEkAZ+gFwLb
	T85wJmSWpARc+O2TQxngxCEw4h8Zchkb788kLLaQuAfuLAVi17BNnqhdQzd3MgDe
	BaZFwn3zI7UMPwLJ4HtDMQKBgQCcJXKFpgCk2SxivuaefJqPXdtNYGMYUOmjBaD1
	ecJd9/M2koG67sCpR1oOm+F9EVp90+PJQc9zxWQYfm3lMjmvIG6+Io4axfCFcJw8
	2/kgRezBD+xyV2RPHNYdkEGTa8Vk4snPRjehCCzptgYcsM7yz67a8WY84QyYpdwp
	lS528QKBgH69DPkflIF30+2FNaYA4BwMqHoHP6UAiLD2B7ZWS8eqCCNCdpwmFZBx
	CFYRJY4Ec9ILvWCYGuF6yVp53Sk0k6/MRSL1+9rYvhUqNywDwSjxslz1N9ENW4zm
	QvJRzj1ree7m7kyNl+a8H7G/vUvU2t8tXt3Q26FTuaDg2vzzxfPm
	-----END RSA PRIVATE KEY-----`)

	// Generate the RSA private key
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	checkError(err)
	publicKey := privateKey.PublicKey

	// This is used to generate the 256 bit AES key
	aesKey := make([]byte, 32)
	n, err := io.ReadFull(rand.Reader, aesKey)
	checkError(err)
	fmt.Println("n : ", n)

	fmt.Println("AES key : ", aesKey)
	encryptedAESKey := encryptAESKey(aesKey, publicKey)
	fmt.Println("encrypted AES key : ", base64.StdEncoding.EncodeToString(encryptedAESKey))

	decryptedAESKey := decryptAESKey(encryptedAESKey, *privateKey)
	fmt.Println("decrypted AES key : ", decryptedAESKey)

	encryptMessage := encryptSecreteMessage(secretMessage, decryptedAESKey)
	decryptMessage := decryptSecreteMessage(encryptMessage, decryptedAESKey)
	fmt.Println("encrypted message : ", base64.StdEncoding.EncodeToString(encryptMessage))
	fmt.Println("decrypted message : ", string(decryptMessage))

}
