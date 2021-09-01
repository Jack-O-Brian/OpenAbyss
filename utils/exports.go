package utils

import (
	"bytes"
	"os"

	"golang.org/x/crypto/openpgp"
	"golang.org/x/crypto/openpgp/packet"
)

// Exports the public/private key to a file given
//  the filename and entity to export
func ExportKeys(entity *openpgp.Entity, filename string) error {
	// Serialize the Key into Bytes
	dataBytes := bytes.NewBufferString("")
	if err := entity.PrivateKey.Serialize(dataBytes); err != nil {
		return err
	}

	// Output key to a file
	file, err := os.Create(filename)
	if err != nil {
		return err
	}
	defer file.Close()

	// Convert to ASCII
	if err := openpgp.ArmoredDetachSign(file, entity, bytes.NewBuffer([]byte("")), &packet.Config{}); err != nil {
		os.Remove(filename)
		return nil
	}

	return nil
}
