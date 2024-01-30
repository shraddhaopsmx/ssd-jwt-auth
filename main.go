// This package (mostyly) is be used for all service-to-service authentication
// and moving other attributes around such as groups, orgID,etc.
// Specifications: https://docs.google.com/document/d/1uuKitg7G0m6GzXM0BYzbsyEogZeUhthy7LSUTgnRtuQ/edit#heading=h.imy018wzvh86
// We have jwt-create.go - create various types of JWTs, auth.go - methods other services can call
package main

func main() { // TODO: change to a demo/test method
	// Initialize
	// Create tokens of each type
	// take the token strings and decode and print contents
	// Failure test-cases: create tokens with wrong issuer??
	// Create short-lived tokens so they expire (sleep for a few sec)
}
