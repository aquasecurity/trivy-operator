package client

type Authorization struct {
	Basic *UsernameAndPassword
}

type UsernameAndPassword struct {
	Username string
	Password string
}
