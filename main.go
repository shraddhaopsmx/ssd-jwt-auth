// This package (mostyly) is be used for all service-to-service authentication
// and moving other attributes around such as groups, orgID,etc.
// Specifications: https://docs.google.com/document/d/1uuKitg7G0m6GzXM0BYzbsyEogZeUhthy7LSUTgnRtuQ/edit#heading=h.imy018wzvh86
// We have jwt-create.go - create various types of JWTs, auth.go - methods other services can call
package main

import (
	"log"

	"github.com/ksrinimba/ssd-jwt-auth/ssdjwtauth"
)

// Token strings for testing, not using the generated ones
var uTokenStr string = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJhdWQiOiJzc2Qub3BzbXguaW8iLCJleHAiOjE3MDY5MjMwMDEsImp0aSI6ImM2MDliODg1LTRlODAtNGZlNy1iMWU1LTAyYzA0N2FlMDQ5ZCIsIm5iZiI6MTcwNjkxOTEwMSwic3NkLm9wc214LmlvIjp7InR5cGUiOiJ1c2VyL3YxIiwidWlkIjoia3NyaW5pbWJhIiwib3JnSWQiOiJOb0FQSUF2YWlsYWJsZVlFVCIsImdyb3VwcyI6WyJkZXYiLCJxYSJdLCJpc0FkbWluIjpmYWxzZX0sInN1YiI6ImtzcmluaW1iYSJ9.VOrp6QFpLb4o1yQjDR-sdwpfRxE3n_ewJbXae4NHVuE"
var sTokenStr string = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJhdWQiOiJzc2Qub3BzbXguaW8iLCJleHAiOjE3MDk1MTE0MDEsImp0aSI6IjU1MThhNzlhLWNlMjktNDRlNy1hZDYwLTVmYTdmYzk0MjczYSIsIm5iZiI6MTcwNjkxOTEwMSwic3NkLm9wc214LmlvIjp7InR5cGUiOiJzZXJ2aWNlLWFjY291bnQvdjEiLCJzZXJ2aWNlIjoiamVua2lucyIsImluc3RJZCI6IjQ1Njc4OSIsIm9yZ0lkIjoiTm9BUElBdmFpbGFibGVZRVQifX0.K9pyH47EhBIHtK2bgSIGejLhu2VU3knox6At1YXQw6M"

// This had 30 sec expiry, so MUST be expired
var iTokenStr string = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJhdWQiOiJzc2Qub3BzbXguaW8iLCJleHAiOjE3MDY5MTk0MzEsImp0aSI6ImQ1ZGEzMmUyLTYwNDAtNGI3Zi05ZTJiLWY1ZjFmNTU0ODk0MCIsIm5iZiI6MTcwNjkxOTEwMSwic3NkLm9wc214LmlvIjp7InR5cGUiOiJpbnRlcm5hbC1hY2NvdW50L3YxIiwic2VydmljZSI6InNzZC1vcGEiLCJpc0FkbWluIjp0cnVlfX0.rHq48WFCVC-4Hox2K3BK1IUslb2xmeVGGcCIjOf0vHo"
var wrongIssuerTokenStr string = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJhdWQiOiJNdXN0QmVXcm9uZyIsImV4cCI6MTcwNjkyMzI2MiwianRpIjoiNjIyN2M3MTEtYTYzNS00OWY2LTg2N2QtOWIwMjlkYzE5ZTEzIiwibmJmIjoxNzA2OTE5MzYyLCJzc2Qub3BzbXguaW8iOnsidHlwZSI6InVzZXIvdjEiLCJ1aWQiOiJrc3JpbmltYmEiLCJvcmdJZCI6Ik5vQVBJQXZhaWxhYmxlWUVUIiwiZ3JvdXBzIjpbImRldiIsInFhIl0sImlzQWRtaW4iOmZhbHNlfSwic3ViIjoia3NyaW5pbWJhIn0.d540kceVPeqo4r4J5DlotWm4pcb5lIGZ-tYH8X1nI-c"

func main() { // TODO: change to a demo/test method
	log.Println("use jwt.io, debugger to see the token, epochconverter.com to check the expiry")
	// Initialize: userID, adminGroups, UI session expiry, serviceAccount expiry, internal Token expiry time
	// TODO: Replace HMAC with cert+key
	ssdjwtauth.InitJWTSecret("myHmacSecret", []string{"admin", "bigboss"}, 3600, 3600*24*30, 30)
	create3TypeOfTokens()
	// Now to Decode and get info
	// Failure test-cases: create tokens with wrong issuer??
}

func create3TypeOfTokens() {
	// Create tokens of each type - user
	utokenStr, err := ssdjwtauth.GetUserJWT("ksrinimba", []string{"dev", "qa"}, 0)
	if err != nil {
		log.Printf("User Token Creation Error:%v", err)
	} else {
		// take the token strings and decode and print contents
		log.Printf("User Token Created: %s", utokenStr)
	}

	// Create tokens of each type - Service
	stokenStr, err := ssdjwtauth.GetServiceJWT("jenkins", "456789", "NoAPIAvailableYET")
	if err != nil {
		log.Printf("Service Token Creation Error:%v", err)
	} else {
		// take the token strings and decode and print contents
		log.Printf("Service Token Created: %s", stokenStr)
	}

	// Create tokens of each type - Internal
	itokenStr, err := ssdjwtauth.GetInternalJWT("ssd-opa", true)
	if err != nil {
		log.Printf("Internal Token Creation Error:%v", err)
	} else {
		// take the token strings and decode and print contents
		log.Printf("Internal Token Created: %s", itokenStr)
	}
}
