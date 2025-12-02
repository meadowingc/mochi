package site

import (
	"crypto/rand"
	"encoding/base64"
	"log"
	"mochi/user_database"
	"net/http"
	"sort"
	"strings"
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

func GetSignedInUserOrNil(r *http.Request) *user_database.User {
	user, _ := r.Context().Value(AuthenticatedUserCookieName).(*user_database.User)
	return user
}

func GetSignedInUserOrFail(r *http.Request) *user_database.User {
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

func clearUserSession(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{
		Name:   string(AuthenticatedUserTokenCookieName),
		Value:  "",
		Path:   "/",
		MaxAge: -1,
	})
}

func setUserSession(w http.ResponseWriter, username string, authToken string) {
	cookieValue := authToken + "///" + username
	http.SetCookie(w, &http.Cookie{
		Name:   string(AuthenticatedUserTokenCookieName),
		Value:  cookieValue,
		Path:   "/",
		MaxAge: 60 * 60 * 24 * 365 * 10, // 10 years
	})
}

func stringWithValueOrNil(s string) *string {
	if s == "" {
		return nil
	}

	strSlice := strings.TrimSpace(s)

	return &strSlice
}

func countryCodeToFlagEmoji(countryCode string) string {
	var flagEmoji strings.Builder
	for _, char := range countryCode {
		flagEmoji.WriteRune(rune(char) + 0x1F1A5)
	}
	return flagEmoji.String()
}
