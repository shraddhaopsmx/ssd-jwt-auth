// This will become a separate package (mostyly) will be used for all service-to-service authentication
// and moving other attributes around such as groups, orgID,etc.
// Specifications: https://docs.google.com/document/d/1uuKitg7G0m6GzXM0BYzbsyEogZeUhthy7LSUTgnRtuQ/edit#heading=h.imy018wzvh86
package ssdjwtauth

import (
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
)

var hmacSecret string = "test"
var SSDTokenTypeUser string = "user/v1"
var SSDTokenTypeService string = "service-account/v1"
var SSDTokenTypeInternal string = "internal-account/v1"

// Initialize JWT creation. This might include certs/secrets, admin groups and more
func InitJWTSecret(secret string, admingrps []string, sessionTmout uint) {
	hmacSecret = secret
	adminGroups = admingrps
	sessionTimeout = time.Duration(sessionTmout * 1000) // Session time out in sec
	// TODO: Go-routine to clean-up the revoked list once the token has expired
}

// Create a new JWT and return a base64 encoded string
// That is ready for use
func GetUserJWT(user *SsdUserToken) (bool, string, error) {
	sut := SsdUserToken{"user/v1", user.Uid, "NoAPIAvailableYET", user.Groups, false}
	// Not using MAPs, that might be slower than a direct search as we don't expect a long list of Admin-groups
	// This might be a challenge where one of our customers has 1500+ groups per user
	found := false
	for _, element := range user.Groups { // With 3 admin groups, 1500 user groups, we have 4500 iterations!!
		for _, usergrp := range adminGroups {
			if element == usergrp {
				found = true
				break
			}
		}
	}
	sut.IsAdmin = found // Set the IsAdmin flag
	claims := jwt.MapClaims{
		"sub":          user.Uid,
		"aud":          "ssd.opsmx.io",
		"nbf":          time.Now().Unix(),
		"exp":          time.Now().Add(time.Second * sessionTimeout).Unix(), // JWT expiration time
		"jti":          uuid.New(),
		"ssd.opsmx.io": sut,
	}
	return getSignedTokenStr(&claims)
}

func getSignedTokenStr(claims *jwt.MapClaims) (bool, string, error) {
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)

	// Sign and get the complete encoded token as a string using the secret
	tokenString, err := token.SignedString([]byte(hmacSecret))
	if err != nil {
		return false, "", err
	}
	return true, tokenString, nil
}

// token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
// // Sign and get the complete encoded token as a string using the secret
// tokenString, err := token.SignedString([]byte(hmacSecret))
// if err != nil {
// 	return false, "", err
// }
// return true, tokenString, nil
