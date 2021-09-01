package entity

import (
	"crypto/rand"
	"crypto/rsa"
	"openabyss/utils"
	"time"

	"golang.org/x/crypto/openpgp/packet"
)

func GenerateKeys(dir string, keyname string, bits int) Entity {
	// Generate & Create RSA Keys
	sk, err := rsa.GenerateKey(rand.Reader, bits)
	utils.HandleErr(err, "error generating Private key")

	gpgSkKey := packet.NewRSAPrivateKey(time.Now(), sk)
	gpgPbKey := packet.NewRSAPublicKey(time.Now(), &sk.PublicKey)

	// Export keys to file
	err = utils.ExportKeys(gpgPbKey, gpgSkKey, dir, keyname)
	utils.HandleErr(err, "could no export keys to file")

	return Entity{
		PrivateKey: gpgSkKey,
		PublicKey:  gpgPbKey,
	}
}
