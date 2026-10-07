package ctv

import "encoding/pem"

func pemBlock(raw []byte) *pem.Block {
	block, _ := pem.Decode(raw)
	return block
}
