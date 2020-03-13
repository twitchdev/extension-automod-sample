/**
 *    Copyright 2019 Amazon.com, Inc. or its affiliates
 *
 *    Licensed under the Apache License, Version 2.0 (the "License");
 *    you may not use this file except in compliance with the License.
 *    You may obtain a copy of the License at
 *
 *        http://www.apache.org/licenses/LICENSE-2.0
 *
 *    Unless required by applicable law or agreed to in writing, software
 *    distributed under the License is distributed on an "AS IS" BASIS,
 *    WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *    See the License for the specific language governing permissions and
 *    limitations under the License.
 */

package main

import (
	"context"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"log"
	"math/rand"
	"net/http"
	"os"
	"strings"
	"time"

	"git-aws.internal.justin.tv/vpolouch/extension-automod/ebs/config"
	"git-aws.internal.justin.tv/vpolouch/extension-automod/ebs/dynamodb"
	"git-aws.internal.justin.tv/vpolouch/extension-automod/ebs/helix"

	jwt "github.com/dgrijalva/jwt-go"

	"github.com/gorilla/handlers"
	"github.com/gorilla/mux"
	"github.com/gorilla/sessions"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/twitch"
)

var (
	clientID            = os.Getenv("CLIENT_ID")
	apiSecret           = os.Getenv("API_SECRET")
	extensionSecret     = os.Getenv("EXTENSION_SECRET")
	sessionSecret       = os.Getenv("SESSION_SECRET")
	authHeaderName      = "Authorization"
	authHeaderPrefix    = "Bearer "
	authSessionName     = "automodder-session"
	authHeaderPrefixLen = len(authHeaderPrefix)
	minLegalTokenLength = authHeaderPrefixLen + 5
	parser              = jwt.Parser{ValidMethods: []string{"HS256"}}
)

type contextKeyType string

type loginHandler struct {
	config       *config.Config
	sessionStore *sessions.CookieStore
}
type authCallbackHandler struct {
	config          *config.Config
	dynamoDBService *dynamodb.DynamoDBService
	helixService    *helix.HelixService
	sessionStore    *sessions.CookieStore
}

type autoModCheckHandler struct {
	dynamoDBService *dynamodb.DynamoDBService
	helixService    *helix.HelixService
}

type userHandler struct{}

func main() {
	rand.Seed(time.Now().UTC().UnixNano())

	config := &config.Config{
		ExtensionSecret: extensionSecret,
		OAuth2: &oauth2.Config{
			ClientID:     clientID,
			ClientSecret: apiSecret,
			Scopes:       []string{"moderation:read"},
			Endpoint:     twitch.Endpoint,
			RedirectURL:  "http://localhost:8080/auth/redirect",
		},
	}

	dynamoDBService := dynamodb.NewDynamoDBService()
	helixService := helix.NewHelixService(config, dynamoDBService)
	sessionStore := sessions.NewCookieStore([]byte(sessionSecret))

	r := mux.NewRouter()
	s := r.PathPrefix("/auth").Subrouter()
	s.Handle("/login", &loginHandler{config: config, sessionStore: sessionStore}).Methods("GET")
	s.Handle("/redirect", &authCallbackHandler{config: config, dynamoDBService: dynamoDBService, helixService: helixService, sessionStore: sessionStore}).Methods("GET")

	s = r.PathPrefix("/api").Subrouter()
	s.Handle("/automod", &autoModCheckHandler{dynamoDBService: dynamoDBService, helixService: helixService}).Methods("POST")
	s.Handle("/user", &userHandler{}).Methods("GET")
	s.Use(verifyJWT)

	// Serve frontend assets
	r.PathPrefix("/").Handler(http.FileServer(http.Dir("../client/")))

	fmt.Println("Started running on http://localhost:8080/")
	fmt.Println(http.ListenAndServe(":8080", handlers.CORS(handlers.AllowedHeaders([]string{authHeaderName}))(r)))
}

func (h *loginHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	session, err := h.sessionStore.Get(r, authSessionName)
	if err != nil {
		log.Println("Could not read the session, generated a new one")
		err = nil
	}

	var b [255]byte
	state := hex.EncodeToString(b[:])
	session.Values["state"] = state

	if err = session.Save(r, w); err != nil {
		log.Println("Could not save the session")
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	// For example purposes, we're passing force_verify to always prompt the broadcaster for authorization during extension configuration
	http.Redirect(w, r, h.config.OAuth2.AuthCodeURL(state, oauth2.SetAuthURLParam("force_verify", "true")), http.StatusTemporaryRedirect)
}

func (h *authCallbackHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	session, err := h.sessionStore.Get(r, authSessionName)
	if err != nil {
		log.Println("Could not read session, generated a new one")
		err = nil
	}

	switch stateChallenge, state := session.Values["state"].(string), r.FormValue("state"); {
	case state == "", len(stateChallenge) < 1:
		err = errors.New("Missing state challenge")
	case state != stateChallenge:
		err = fmt.Errorf("Invalid oauth state, expected '%s', got '%s'", state, stateChallenge)
	}

	if err != nil {
		log.Println(err.Error())
		http.Error(w, "Couldn't verify your confirmation, please try again.", http.StatusBadRequest)
		return
	}

	token, err := h.config.OAuth2.Exchange(context.Background(), r.FormValue("code"))
	if err != nil {
		log.Println(err.Error())
		http.Error(w, "Couldn't verify your confirmation, please try again.", http.StatusInternalServerError)
		return
	}

	// Once the broadcaster has authenticated, we retrieve their TUID to we use it as our key in the database
	userID, err := h.helixService.GetUserID(token.AccessToken)
	if err != nil {
		log.Println(err.Error())
		http.Error(w, "Couldn't retrieve your confirmation, please try again.", http.StatusInternalServerError)
		return
	}

	err = h.dynamoDBService.PutUser(&dynamodb.User{
		UserID:       userID,
		AccessToken:  token.AccessToken,
		RefreshToken: token.RefreshToken,
		Expiry:       token.Expiry,
		TokenType:    token.TokenType,
	})
	if err != nil {
		log.Println(err.Error())
		http.Error(w, "Couldn't store your information, please try again.", http.StatusInternalServerError)
		return
	}

	http.Redirect(w, r, "/auth_popup.html", http.StatusTemporaryRedirect)
	return
}

func (h *autoModCheckHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	b, err := ioutil.ReadAll(r.Body)
	defer r.Body.Close()
	if err != nil {
		log.Println(err.Error())
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	var body struct {
		Message string `json:"message"`
	}

	err = json.Unmarshal(b, &body)
	if err != nil {
		log.Println(err.Error())
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	claims := getClaims(r)
	// A missing user ID indicates that they viewer has not shared their identity in the extension
	if claims.UserID == "" {
		log.Println("UserID is missing in the request context")
		http.Error(w, http.StatusText(http.StatusForbidden), http.StatusForbidden)
		return
	}

	result, err := h.helixService.GetEnforcementStatus(claims.ChannelID, claims.UserID, body.Message)
	if err != nil {
		log.Println(err.Error())
		http.Error(w, "Couldn't validate message against AutoMod, please try again.", http.StatusInternalServerError)
		return
	}

	resp := struct {
		IsPermitted bool `json:"is_permitted"`
	}{
		IsPermitted: result,
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(resp)
}

func (h *userHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	claims := getClaims(r)

	resp := struct {
		OpaqueUserID string `json:"opaque_user_id"`
		UserID       string `json:"user_id,omitempty"`
		Role         string `json:"role"`
	}{
		OpaqueUserID: claims.OpaqueUserID,
		UserID:       claims.UserID,
		Role:         claims.Role,
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(resp)
}

func verifyJWT(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var token string

		tokens, ok := r.Header[authHeaderName]
		if !ok {
			log.Println("Missing authorization header")
			http.Error(w, http.StatusText(http.StatusUnauthorized), http.StatusUnauthorized)
			return
		}

		if len(tokens) != 1 {
			log.Println("Multiple authorization headers found")
			http.Error(w, "Multiple authorization headers found; only one header should be sent", http.StatusUnauthorized)
			return
		}

		token = tokens[0]
		if !strings.HasPrefix(token, authHeaderPrefix) || len(token) < minLegalTokenLength {
			log.Println("Malformed authorization header")
			http.Error(w, "Malformed authorization header", http.StatusUnauthorized)
			return
		}
		token = strings.TrimPrefix(token, authHeaderPrefix)

		parsedToken, err := parser.ParseWithClaims(token, &jwtClaims{}, getKey)
		if err != nil {
			log.Println(err)
			http.Error(w, "Could not parse authorization header", http.StatusInternalServerError)
			return
		}

		if claims, ok := parsedToken.Claims.(*jwtClaims); ok && parsedToken.Valid {
			next.ServeHTTP(w, setClaims(r, claims))
		} else {
			log.Println("Could not parse JWT claims")
			http.Error(w, http.StatusText(http.StatusUnauthorized), http.StatusUnauthorized)
			return
		}
	})
}

func getKey(*jwt.Token) (interface{}, error) {
	secret, err := base64.StdEncoding.DecodeString(extensionSecret)
	if err != nil {
		log.Fatalf("Could not parse extension secret: %v", err)
	}

	return secret, nil
}
