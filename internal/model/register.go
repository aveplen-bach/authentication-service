package model

type RegisterRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
	Photo    string `json:"photo"`
}
