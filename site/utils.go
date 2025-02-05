package site

import (
	"crypto/rand"
	"encoding/base64"
	"log"
	"mochi/database"
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
		MaxAge: 60 * 60 * 24 * 7, // 1 week
	})
}

// func encryptAuthToken(plaintextValue string) (string, error) {
// 	encrypted, err := encrypt([]byte(plaintextValue))
// 	if err != nil {
// 		return "", err
// 	}

// 	return base64.StdEncoding.EncodeToString(encrypted), nil
// }

// func decryptAuthToken(encryptedToken string) (string, error) {
// 	ciphertext, err := base64.StdEncoding.DecodeString(encryptedToken)
// 	if err != nil {
// 		return "", err
// 	}

// 	decrypted, err := decrypt(ciphertext)
// 	if err != nil {
// 		return "", err
// 	}

// 	return string(decrypted), nil
// }

// func encrypt(plaintext []byte) ([]byte, error) {
// 	key := []byte(os.Getenv("COOKIE_SECRET"))
// 	if len(key) != 32 {
// 		return nil, fmt.Errorf(
// 			"invalid key length: must be 32 bytes. Got: %d", len(key),
// 		)
// 	}

// 	block, err := aes.NewCipher(key)
// 	if err != nil {
// 		return nil, err
// 	}

// 	ciphertext := make([]byte, aes.BlockSize+len(plaintext))
// 	iv := ciphertext[:aes.BlockSize]
// 	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
// 		return nil, err
// 	}

// 	stream := cipher.NewCFBEncrypter(block, iv)
// 	stream.XORKeyStream(ciphertext[aes.BlockSize:], plaintext)

// 	return ciphertext, nil
// }

// func decrypt(ciphertext []byte) ([]byte, error) {
// 	key := []byte(os.Getenv("COOKIE_SECRET"))
// 	if len(key) != 32 {
// 		return nil, fmt.Errorf(
// 			"invalid key length: must be 32 bytes. Got: %d", len(key),
// 		)
// 	}

// 	block, err := aes.NewCipher(key)
// 	if err != nil {
// 		return nil, err
// 	}

// 	if len(ciphertext) < aes.BlockSize {
// 		return nil, errors.New("ciphertext too short")
// 	}

// 	iv := ciphertext[:aes.BlockSize]
// 	ciphertext = ciphertext[aes.BlockSize:]

// 	stream := cipher.NewCFBDecrypter(block, iv)
// 	stream.XORKeyStream(ciphertext, ciphertext)

// 	return ciphertext, nil
// }

func stringWithValueOrNil(s string) *string {
	if s == "" {
		return nil
	}

	strSlice := strings.TrimSpace(s)

	return &strSlice
}
