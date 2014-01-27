package main

import (
	"github.com/oov/socks5"
	"log"
)

func main() {
	srv := socks5.New()
	srv.AuthNoAuthenticationRequiredCallback = func(c *socks5.Conn) error {
		return socks5.ErrAuthenticationFailed
	}
	srv.AuthUsernamePasswordCallback = func(c *socks5.Conn, username, password []byte) error {
		user := string(username)
		log.Printf("Welcome %v!", user)
		c.Data = user
		return nil
	}
	srv.HandleCloseFunc(func(c *socks5.Conn) {
		if user, ok := c.Data.(string); ok {
			log.Printf("Goodbye %v!", user)
		}
	})

	srv.ListenAndServe(":12345")
}
