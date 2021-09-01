package entity

import "golang.org/x/crypto/openpgp/packet"

type Entity struct {
	publicKey  *packet.PublicKey
	privateKey *packet.PrivateKey
}
