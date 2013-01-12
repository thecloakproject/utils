// Steve Phillips / elimisteve
// 2013.01.12

package crypt

import (
	"bytes"
	"code.google.com/p/go.crypto/openpgp"
	"code.google.com/p/go.crypto/openpgp/armor"
	"fmt"
	"github.com/elimisteve/fun"
	"io"
	"io/ioutil"
	"log"
	"os"
)

// GPG vars
var (
	GPG_DIR = os.Getenv("HOME") + "/.gnupg/"
	// TODO: Document how and make it easy to set these variables from
	// the caller
	DEBUG = false
	// TODO: Make it possible to support multiple keyrings in a
	// thread-safe way
	PUBLIC_KEYRING_FILENAME  = GPG_DIR + "pubring.gpg"
	PRIVATE_KEYRING_FILENAME = GPG_DIR + "secring.gpg"

	// TODO: Make updates to these thread-safe
	pubkeys  = map[string]*openpgp.Entity{}
	privkeys = map[string]*openpgp.Entity{}
)

// EncryptMessage creates ciphertext based upon `message`, sent from
// `sender` to `recipient`, then writes it to `dst`
func EncryptMessage(mw io.Writer, sender, recipient, msg string) error {
	defer func() {
		if err := recover(); err != nil {
			log.Println("Error in encryptMessage:", err)
			log.Fatalf("(That probably meant that you don't have %s's key)\n",
				recipient)
		}
	}()
	// Grab relevant keys
	myPrivateKey, err := GetEntityFrom(sender, PRIVATE_KEYRING_FILENAME)
	if err != nil {
		return fmt.Errorf("Error getting private key for %s from %s: %v",
			sender, PRIVATE_KEYRING_FILENAME, err)
	}
	theirPublicKey, err := GetEntityFrom(recipient, PUBLIC_KEYRING_FILENAME)
	if err != nil {
		return fmt.Errorf("Error getting public key for %s from %s: %v",
			recipient, PRIVATE_KEYRING_FILENAME, err)
	}

	// Produce new writer to... write encrypted messages to?
	w, err := armor.Encode(mw, "PGP MESSAGE", nil)
	fun.MaybeFatalAt("Encode", err)
	defer w.Close()

	// Encrypt message from ME to recipient
	plaintext, err := openpgp.Encrypt(w, []*openpgp.Entity{theirPublicKey},
		myPrivateKey, nil, nil)
	fun.MaybeFatalAt("Encrypt", err)
	defer plaintext.Close()

	// Write message to `plaintext` WriteCloser
	fmt.Fprintf(plaintext, msg)

	return nil
}

// DecryptMessage is largely from
// http://chiselapp.com/user/loser/repository/auricular/artifact/e14b57f441816f449105d201e7fb429f76907c65
func DecryptMessage(recipient, cipher string) (string, error) {
	// if DEBUG { log.Printf("Within decryptMessage: cipher == %v\n", cipher) }
	r := bytes.NewBufferString(cipher)
	// r := strings.NewReader(cipher)
	block, err := armor.Decode(r)
	if err != nil {
		return "", fmt.Errorf("Error decrypting message: %v", err)
	}

	if DEBUG {
		log.Printf("Getting entity from private keyring\n")
	}
	myPrivateKey, err := GetEntityFrom(recipient, PRIVATE_KEYRING_FILENAME)
	if err != nil {
		return "", fmt.Errorf("Error getting private key for %s: %v",
			recipient, err)
	}
	entities := openpgp.EntityList([]*openpgp.Entity{myPrivateKey})
	if DEBUG {
		log.Printf("Got entities\n")
	}
	details, err := openpgp.ReadMessage(block.Body, entities, nil, nil)
	if err != nil {
		return "", fmt.Errorf("Error reading message block body: %v", err)
	}

	// Read the message body
	if DEBUG {
		log.Printf("Reading raw message body\n")
	}
	raw, err := ioutil.ReadAll(details.UnverifiedBody)
	if err != nil {
		return "", fmt.Errorf("Error reading decrypted message body: %v", err)
	}

	return string(raw), nil
}

// GetKeyByEmail is from http://www.imperialviolet.org/2011/06/12/goopenpgp.html
func GetKeyByEmail(keyring openpgp.EntityList, email string) *openpgp.Entity {
	for _, entity := range keyring {
		for _, ident := range entity.Identities {
			if ident.UserId.Email == email {
				if DEBUG {
					log.Printf("Found entity for %s: %+v\n", email, entity)
				}
				return entity
			}
		}
	}
	return nil
}

// GetEntityFrom returns (OpenPGP) Entity values for the specified
// user's private or public key (from secring.gpg or pubring.gpg,
// respectively)
func GetEntityFrom(email, sourceFile string) (*openpgp.Entity, error) {
	// Default case: sourceFile == PUBLIC_KEYRING_FILENAME
	keyType := "public"
	keyMap := pubkeys

	if sourceFile == PRIVATE_KEYRING_FILENAME {
		keyType = "private"
		keyMap = privkeys
	}

	if key, ok := pubkeys[email]; ok {
		if DEBUG {
			log.Printf("Grabbed cached pubkey for %s\n", email)
		}
		return key, nil
	}
	ringFile, err := os.Open(sourceFile)
	if err != nil {
		return nil, fmt.Errorf("Error opening %s key file %s: %v",
			keyType, sourceFile, err)
	}
	defer ringFile.Close()

	ring, err := openpgp.ReadKeyRing(ringFile)
	if err != nil {
		return nil, fmt.Errorf("Error reading %s key file %s: %v",
			keyType, sourceFile, err)
	}
	if DEBUG {
		log.Printf("Grabbed %s key for %s off disk\n", keyType, email)
	}

	key := GetKeyByEmail(ring, email)
	// TODO: Is adding to this map this thread safe? Doesn't look
	// like it. Should it be?
	keyMap[email] = key
	return key, nil

	if sourceFile != PUBLIC_KEYRING_FILENAME && sourceFile != PRIVATE_KEYRING_FILENAME {
		panic("GetEntityFrom: Asking for neither private nor public key???")
	}

	return nil, fmt.Errorf("This should never happen!!!\n")
}
