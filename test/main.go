package main

import (
	"github.com/oov/socks5"
	"log"
)

func main() {
	users := make(map[*socks5.Conn]string)

	srv := socks5.New()
	srv.AuthNoAuthenticationRequiredCallback = func(c *socks5.Conn) error {
		return socks5.ErrAuthenticationFailed
	}
	srv.AuthUsernamePasswordCallback = func(c *socks5.Conn, username, password []byte) error {
		user := string(username)
		users[c] = user
		log.Printf("Welcome %v!", user)
		return nil
	}
	srv.HandleCloseFunc(func(c *socks5.Conn) {
		if user, ok := users[c]; ok {
			log.Printf("Goodbye %v!", user)
		}
		delete(users, c)
	})

	srv.ListenAndServe(":12345")
}
