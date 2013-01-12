package crypt

import (
	// "crypto/aes"
	"crypto/cipher"
	"fmt"
	"log"
)

func AESEncryptBytes(block cipher.Block, data []byte) (cipher []byte, err error) {
	blockSize := block.BlockSize()

	length := len(data)

	cipherBytes := make([]byte, length)
	numBlocks := length / blockSize
	// Add one more if there were bytes left over
	if length % blockSize != 0 {
		numBlocks++
	}

	// Encrypt
	for i := 0; i < length; i += blockSize {
		block.Encrypt(cipherBytes[i:i+blockSize], data[i:i+blockSize])
	}

	return cipherBytes, nil
}

func AESDecryptBytes(block cipher.Block, cipherBytes []byte) (plain []byte, err error) {
	defer func() {
		if e := recover(); e != nil {
			log.Printf("Panic from AESDecryptBytes: %v", e)
			plain = nil
			err = fmt.Errorf("%v", e)
		}
	}()

	blockSize := block.BlockSize()
	plain = make([]byte, len(cipherBytes))
	for i := 0; i < len(cipherBytes); i += blockSize {
		block.Decrypt(plain[i:i+blockSize], cipherBytes[i:i+blockSize])
	}
	return plain, nil
}
