// Utilities for JWT functions
package ssdjwtauth

import "github.com/golang-jwt/jwt/v5"

// Given user groups and admin groups, return true if user is an Admin
func IsUserAnAdmin(userGroups, adminGroups []string) bool {
	found := false
	for _, element := range userGroups { // With 3 admin groups, 1500 user groups, we have 4500 iterations!!
		for _, usergrp := range adminGroups {
			if element == usergrp {
				found = true
				break
			}
		}
	}
	return found
}

// Create a signed Token and return the token
func getSignedTokenStr(claims *jwt.MapClaims) (string, error) {
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)

	// Sign and get the complete encoded token as a string using the secret
	tokenString, err := token.SignedString([]byte(hmacSecret))
	if err != nil {
		return "", err
	}
	return tokenString, nil
}
