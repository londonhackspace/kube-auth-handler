package main

type cacheconfig struct {
	Username    string `json:"username"`
	Token       string `json:"token"`
	TokenExpiry int64  `json:"token_expiry"`
}
