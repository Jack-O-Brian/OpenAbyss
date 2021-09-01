package entity

import "golang.org/x/crypto/openpgp/packet"

type Entity struct {
	PublicKey  *packet.PublicKey
	PrivateKey *packet.PrivateKey
}
