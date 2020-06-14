package main

import (
	"github.com/SimonSchneider/traefik-jwt-decode/config"
)

func main() {
	c, _ := config.NewConfig().RunServer()
	panic(<-c)
}
