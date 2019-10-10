package main

/*

This is an oauth2 authorization server. All databases interactions are hard coded as
map objects here for simplicity.

This server will grant authorization codes to a client and grant
tokens to client applications.

*/

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"time"

	"github.com/satori/go.uuid"
)

type Client struct {
	ClientID     string    `json:"cliend_id"`
	ClientSecret string    `json:"client_secret"`
	CreatedAt    time.Time `json:"created_at"`
	Name         string
	Scope        string
	UserID       string
	RedirectURI  string
}

type Token struct {
	UserID string
	//RefreshToken string    //unique=true,
	RefreshToken *RefreshToken
	AccessToken  string    //uuid.v4
	ExpiresIn    time.Time //60*3 - 3 minutes
	TokenType    string    //default=bearer
	Consumed     bool      //default=false
	CreatedAt    time.Time //time stamp of creation

}

type RefreshToken struct {
	UserID    string    `json:"user_id"`
	Token     string    `json:"token"`
	CreatedAt time.Time `json:"created_at"`
	Consumed  bool      `json:"consumed"`
}

type Oauth2Request struct {
	ClientID     string `json:"client_id"`
	ResponseType string `json:"response_type"`
	RedirectURI  string `json:"redirect_uri"`
	User         string `json:"user"`
}

type AuthCode struct {
	Code        string //default=uuid.v4()
	CreateAt    string //Date.Now(), expires '10m'
	Consumed    bool
	ClientID    string
	UserID      string
	RedirectURI string
}

type Oauth2Response struct {
	AccessToken *AuthCode
	State       string
}

type TokenResponse struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	ExpiresIn    string `json:"expires_in"`
	TokenType    string `json:"token_type"`
}

type TokenRequest struct {
	GrantType   string `json:"grant_type"`
	AuthCode    string `json:"auth_code"`
	RedirectURI string `json:"redirect_uri"`
	ClientID    string `json:"client_id"`
}

// various maps representing databases

// Mapping clientId to client Objects
var ClientMap map[string]*Client

// Mapping authCode to authCode Objects
var AuthCodeMap map[string]*AuthCode

// Mapping token to
var TokenMap map[string]*Token

func main() {
	//main
	fmt.Println("oauth2 authorization server starting up")

	//make the maps
	ClientMap = make(map[string]*Client)
	AuthCodeMap = make(map[string]*AuthCode)
	TokenMap = make(map[string]*Token)

	ClientMap["test1"] = &Client{RedirectURI: "/testuri1"}
	ClientMap["test2"] = &Client{RedirectURI: "/testuri2"}

	serverType := os.Args[1]

	if serverType == "authorization" || serverType == "authz" {
		StartAuthorizationServer()
	} else if serverType == "resource" {
		//start resource server
	}

}

func StartClientApplication() {
	// client application will:
	// 1: Request an Auth code from the authz server. It will have to
	//		autheicate itself as a valid client application registered
	//		with this authz server.
	// 2: After successfull AuthCode request, it will then request an access token from
	//		the authz server.
	// 3: After successfull AccessToken request, it will request the resource from the
	// 		resource server via the access token.
}

func StartResourceServer() {
	// this server will listen for resource requests
	// when it receives a request it will decode an
	// access token and after it has it will query the
	// authz server for its access token to validate
	// the token is good for the service.
}

func StartAuthorizationServer() {
	http.HandleFunc("/authorize", authorize)
	http.HandleFunc("/token", token)
	http.ListenAndServe(":8080", nil)
}

//helper functions for generating specific fields
func GenerateRefreshToken(userId string) *RefreshToken {
	var token = &RefreshToken{
		UserID:    userId,
		Token:     uuid.NewV4().String(),
		CreatedAt: time.Now(),
		Consumed:  false,
	}

	return token

}

func GenerateAccessToken(authCode *AuthCode, refreshToken *RefreshToken) *Token {
	var token = &Token{
		UserID:       authCode.UserID,
		RefreshToken: refreshToken,
		AccessToken:  uuid.NewV4().String(),
		ExpiresIn:    time.Now().Add(time.Millisecond * 10800), //3 minute timeout before consumption
		TokenType:    "Access",
		Consumed:     false,
		CreatedAt:    time.Now(),
	}

	return token
}

func LogRequest(req interface{}) {
	if prettyJSON, err := json.MarshalIndent(req, "", "   "); err != nil {
		fmt.Println("Could not decode JSON because " + err.Error())
	} else {
		fmt.Println("Recieved request: " + string(prettyJSON))
	}
}

// authorizeResource
//
// This function will check the request is authorized for the specified resource.
// Request handler should send in there args and this function will return true
// or false for success. Response codes have already been writen to the tcp stream.
//
func authorizeResource(w http.ResponseWriter, r *http.Request) bool {

	//Get authorization header from the http request
	//For now, this will use BasicAuth.
	//This is a helper in go that will use the Authenticate header
	//from the form Authenticate: 'username passsword' however
	//oauth2 will read it in the form: Authenticate: 'bearer accessToken'
	tokenType, accessToken, status := r.BasicAuth()

	// validate headers where set on input
	if tokenType == "" || accessToken == "" || status == false {
		fmt.Printf("Could not get auth header from the request ")

		// Standard reponse header indicating authentication is required.
		// Bearer indicates we are looking for a bearer token with an access token aswell.

		// TODO - write header may write the response, right back
		// but so may http.Error ... need to test these error handlers.
		w.Header().Set("WWW-Authenticate", "Bearer")
		w.WriteHeader(401)

		http.Error(w, "No access token was provided", 401)

		return false
	}

	// unclear what to do here.
	// I think this access token has been distributed to bo the resource owner
	// and the client and the resource owner TRUSTS the service provider so it will
	// accept access token.
	//
	// As per the docs, the accessToken should be consumed and marked as such. In order
	// to access again, a refresh token needs to be issued to be exchanged for a new accessToken
	// to be used here.

	// -- based on the docs only ---
	//
	// find the accessToken. After it is found, invalidate every other accessToken for this user.
	// i.e. one login per resource granted otherwise we get session hijacking

	var userID = ""
	for _, v := range TokenMap {
		if v.AccessToken == accessToken {
			userID = v.UserID

			// found the token and user id
			break
		}
	}

	// make sure we found the accessToken in the DB
	if userID == "" {
		fmt.Println("accessToken not found. Access will not be granted")

		http.Error(w, "No access token was provided", 401)
		return false
	}

	// invalidate all other accessTokens for this user
	for _, v := range TokenMap {
		if v.UserID == userID {
			v.Consumed = true
		}
	}

	// okay, authz passed, grant access.

	//TODO give access
	return true

}

// consumeToken
//
// This function validate and consume an access token for a specific resource
//
func validateAndConsumeAccessToken(t *Token) bool {

	// search for the access token on the map
	lt := TokenMap[t.AccessToken]

	if lt == nil {
		fmt.Println("The access token " + t.AccessToken + " does not exist in local map")
		return false
	}

	// validate the token
	if lt.Consumed == true {
		fmt.Println("The access token " + t.AccessToken + " was previously consumed")
		return false
	} else {
		lt.Consumed = true
	}

	// validate the token
	if t.CreatedAt != lt.CreatedAt ||
		t.ExpiresIn != lt.ExpiresIn ||
		t.UserID != lt.UserID {
		fmt.Println("Access token validation failed " + t.AccessToken)
		return false
	}

	return true

}

// endpoints are defined below they are as followed:
//
// /authorize 	- authorizes access for the resources - takes in client credentials to verify
// /token 		- validates a user via credentials and issues a token that is used to authorize

// This function provide a valid client with an authorization code.
// This code is sent to the client application and the client application
// will hit the token endpoint to get a token to use for the resource.
func authorize(w http.ResponseWriter, r *http.Request) {
	//oauth2 proto
	//read the request for the token code
	fmt.Println("Authorize Endpoint Starting")

	decoder := json.NewDecoder(r.Body)
	var req Oauth2Request

	if err := decoder.Decode(&req); err != nil {
		fmt.Println("Error decoding JSON request because " + err.Error())
		return
	}

	LogRequest(req)

	// make sure all the fields have been supplied
	if req.ClientID == "" ||
		req.RedirectURI == "" ||
		req.ResponseType == "" {
		fmt.Println("Not all required fields have been supplied")
		return
	}

	//Verify, for the client ID, the proper RedirectURI is specified
	localClient := ClientMap[req.ClientID]

	if localClient == nil {
		fmt.Println("Unknown specified client ID (" + req.ClientID + ")")
		return
	}

	//make sure the URI matches. If not, security alert
	if localClient.RedirectURI != req.RedirectURI {
		fmt.Println("Redirect URI does not match!")
		return
	}

	//at this point, we believe the client is who they say they are
	//issue an access token
	token := &AuthCode{
		Code:        uuid.NewV4().String(),
		CreateAt:    time.Now().String(),
		Consumed:    false,
		ClientID:    req.ClientID,
		UserID:      req.User,
		RedirectURI: req.RedirectURI,
	}

	resp := &Oauth2Response{
		AccessToken: token,
		State:       "undef",
	}

	enc := json.NewEncoder(w)

	if err := enc.Encode(resp); err != nil {
		fmt.Println("Could not write response because " + err.Error())
	}

	fmt.Println("Authorize Endpoint Ending")

}

func user(w http.ResponseWriter, r *http.Request) {

}

//
// Token Request Handler
//
// This function handler will take a valid authorization code and issue a token
// that the client service will accept for resource.
//
func token(w http.ResponseWriter, r *http.Request) {
	// This handler will generate the token the client
	// will use in order to authorize access to the resource

	fmt.Println("Token Endpoint Starting")
	decoder := json.NewDecoder(r.Body)
	var req TokenRequest

	if err := decoder.Decode(&req); err != nil {
		fmt.Println("Error decoding JSON request because " + err.Error())
		return
	}

	LogRequest(req)

	if req.AuthCode == "" ||
		req.ClientID == "" ||
		req.GrantType == "" ||
		req.RedirectURI == "" {
		fmt.Println("Invalid request. A required field is not provied")
		return
	}

	if req.GrantType == "authorization_code" {
		//In this case, we need to match the authorization code
		//supplied in the request to one that was authorized in
		//the authorization table.

		code := AuthCodeMap[req.AuthCode]

		// Validate the authCode
		if code == nil {
			// no authCode was ever issued with this Id
			fmt.Println("There is no authCode object for id " + req.AuthCode)
			return
		} else if code.Consumed == true {
			// this auth code was already used
			fmt.Println("This authCode (" + req.AuthCode + ") was already consumed")
			return
		}

		// authCode provided in tokenRequest checks out
		code.Consumed = true

		// Now, validate the redirect URI. This is important because
		// if it does not match then there is likely some cross site
		// activies happening here, and thats bad, ummm kay?
		if code.RedirectURI != req.RedirectURI {
			// someone is trying to reflect and steal the token!
			fmt.Println("XS Error - RedirectURI of request (" + req.RedirectURI + ") != URI of authCode (" + code.RedirectURI + ")")
			return
		}

		//Validate the clientId.
		var clientId = ClientMap[req.ClientID]

		// Validate the client
		if clientId == nil {
			// client specified in this request does not exist
			fmt.Println("Client specified in request (" + req.ClientID + ") does not exist")
		}

		// At this point, the code as been validated and a token
		// can be issued for graning access to the resource
		var refreshToken = GenerateRefreshToken(code.UserID)

		var accessToken = GenerateAccessToken(code, refreshToken)

		// save the token to the token table
		TokenMap[accessToken.AccessToken] = accessToken

		// send the response back to the requester
		var response = &TokenResponse{
			AccessToken:  accessToken.AccessToken,
			RefreshToken: refreshToken.Token,
			ExpiresIn:    accessToken.ExpiresIn.String(),
			TokenType:    accessToken.TokenType,
		}

		enc := json.NewEncoder(w)

		if err := enc.Encode(response); err != nil {
			fmt.Println("Could not encode token response because " + err.Error())
		}
	} else {
		fmt.Println("grant type not currently supported (" + req.GrantType + ")")
	}
	fmt.Println("Token Endpoint Complete")
}
