package site

import (
	"crypto/rand"
	"encoding/base64"
	"log"
	"mochi/database"
	"net/http"
	"sort"
)

type AdminCookieName string

const AuthenticatedUserCookieName = AdminCookieName("authenticated_user")
const AuthenticatedUserTokenCookieName = AdminCookieName("authenticated_user_token")

func sortMapByValue(m map[string]int) []struct {
	Key   string
	Value int
} {
	var sorted []struct {
		Key   string
		Value int
	}
	for k, v := range m {
		sorted = append(sorted, struct {
			Key   string
			Value int
		}{k, v})
	}
	sort.Slice(sorted, func(i, j int) bool {
		return sorted[i].Value > sorted[j].Value
	})
	return sorted
}

func GetSignedInUserOrNil(r *http.Request) *database.User {
	user, _ := r.Context().Value(AuthenticatedUserCookieName).(*database.User)
	return user
}

func GetSignedInUserOrFail(r *http.Request) *database.User {
	user := GetSignedInUserOrNil(r)
	if user == nil {
		log.Fatalf("Expected user to be signed in but it wasn't")
	}

	return user
}

func generateAuthToken() (string, error) {
	const tokenLength = 32
	tokenBytes := make([]byte, tokenLength)
	_, err := rand.Read(tokenBytes)
	if err != nil {
		return "", err
	}
	token := base64.URLEncoding.EncodeToString(tokenBytes)
	return token, nil
}

func stringWithValueOrNil(s string) *string {
	if s == "" {
		return nil
	}
	return &s
}
