package main

import (
	"fmt"
	"openabyss/entity"
	"os"
)

func main() {
	os.Mkdir("keys", 0777)
	e1 := entity.GenerateKeys("keys", "key1", 2048)

	fmt.Println(e1)
}
