package auth

import (
	"bufio"
	"crypto/md5"
	"encoding/hex"
	"fmt"
	"os"
	"strings"

	"golang.org/x/crypto/bcrypt"
)

func GenerateAPIKey(email string) string {
	hash, err := bcrypt.GenerateFromPassword([]byte(email), bcrypt.DefaultCost)
	if err != nil {
		panic(err)
	}

	hasher := md5.New()
	hasher.Write(hash)
	return "hactar+" + hex.EncodeToString(hasher.Sum(nil))
}

/*
LoadAPIKeys reads a file containing API keys and returns a map of API keys to users.
The file should have one line per API key, with the following format:
email role api_key
where role is either "admin" or "user".
*/
func LoadAPIKeys(filepath string) (map[string]*User, error) {
	f, err := os.Open(filepath)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	apiKeys := make(map[string]*User)
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := scanner.Text()
		parts := strings.Split(line, " ")
		if len(parts) != 3 {
			return nil, fmt.Errorf("invalid line: %v", line)
		}

		email := parts[0]
		role := parts[1]
		apiKey := parts[2]

		var r Role
		switch role {
		case "admin":
			r = Admin
		case "user":
			r = RegularUser
		default:
			return nil, fmt.Errorf("invalid role: %v", role)
		}

		apiKeys[apiKey] = &User{
			Email: email,
			Role:  r,
		}
	}

	return apiKeys, nil
}

func AddAPIKey(filepath string, u User) (string, error) {
	f, err := os.OpenFile(filepath, os.O_APPEND|os.O_WRONLY, 0644)
	if err != nil {
		return "", err
	}
	defer f.Close()

	apiKey := GenerateAPIKey(u.Email)
	_, err = f.WriteString(fmt.Sprintf("%v %v %v\n", u.Email, u.Role, apiKey))
	if err != nil {
		return "", err
	}
	return apiKey, nil
}
