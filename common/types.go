package common

type LoginRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

type LoginResponse struct {
	Success bool `json:"success"`

	Token       string `json:"token"`
	TokenExpiry int64  `json:"token_expiry"`
}
