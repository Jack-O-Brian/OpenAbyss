package main

import (
	"fmt"
	"openabyss/entity"
)

func main() {
	e1 := entity.GenerateKeys("keys", "key1", 2048)
	fmt.Println(e1.PrivateKey.KeyId)
}
