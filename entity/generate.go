package entity

import (
	"crypto/rand"
	"crypto/rsa"
	"openabyss/utils"
	"os"
	"path/filepath"
	"time"

	"golang.org/x/crypto/openpgp"
	"golang.org/x/crypto/openpgp/armor"
	"golang.org/x/crypto/openpgp/packet"
)

func GenerateKeys(dir string, keyname string, bits int) Entity {
	sk, err := rsa.GenerateKey(rand.Reader, bits)
	utils.HandleErr(err, "error generating Private key")

	privKeyFile, err := os.Create(filepath.Join(dir, keyname))
	utils.HandleErr(err, "couldn't create private key file")
	defer privKeyFile.Close()
	pubKeyFile, err := os.Create(filepath.Join(dir, keyname+".pub"))
	utils.HandleErr(err, "couldn't create public key file")
	defer pubKeyFile.Close()

	w, err := armor.Encode(privKeyFile, openpgp.PrivateKeyType, make(map[string]string))
	utils.HandleErr(err, "error creating private key armor")

	gpgSkKey := packet.NewRSAPrivateKey(time.Now(), sk)
	gpgSkKey.Serialize(w)
	w.Close()

	w, err = armor.Encode(pubKeyFile, openpgp.PublicKeyType, make(map[string]string))
	utils.HandleErr(err, "error creating public key armor")

	gpgPbKey := packet.NewRSAPublicKey(time.Now(), &sk.PublicKey)
	gpgPbKey.Serialize(w)
	w.Close()

	return Entity{
		privateKey: gpgSkKey,
		publicKey:  gpgPbKey,
	}
}
