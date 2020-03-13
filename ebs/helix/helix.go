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

package helix

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"log"
	"math/rand"
	"net/http"
	"strconv"
	"time"

	"git-aws.internal.justin.tv/vpolouch/extension-automod/ebs/config"
	"git-aws.internal.justin.tv/vpolouch/extension-automod/ebs/dynamodb"
	"golang.org/x/oauth2"
)

// HelixService provides methods to call the Twitch API
type HelixService struct {
	config *config.Config
	db     *dynamodb.DynamoDBService
	client *http.Client
}

// NewHelixService creates a new HelixService based on tbe extension configuration
func NewHelixService(config *config.Config, db *dynamodb.DynamoDBService) *HelixService {
	return &HelixService{
		config: config,
		db:     db,
		client: &http.Client{
			Timeout: time.Second * 10,
		},
	}
}

type manyMessages struct {
	Messages []message `json:"data"`
}

type message struct {
	MessageID   string `json:"msg_id"`
	MessageText string `json:"msg_text,omitempty"`
	UserID      string `json:"user_id,omitempty"`
	IsPermitted bool   `json:"is_permitted,omitempty"`
}

type manyUsers struct {
	Users []user `json:"data"`
}

type user struct {
	UserID          string `json:"id"`
	Login           string `json:"login"`
	DisplayName     string `json:"display_name"`
	Type            string `json:"type"`
	BroadcasterType string `json:"broadcaster_type"`
	Description     string `json:"description"`
	ProfileImageURL string `json:"profile_image_url"`
	OfflineImageURL string `json:"offline_image_url"`
	ViewCount       int    `json:"view_count"`
}

// GetUserID returns a user
func (s *HelixService) GetUserID(accessToken string) (string, error) {
	req, err := http.NewRequest("GET", "https://api.twitch.tv/helix/users", nil)
	if err != nil {
		log.Println(err.Error())
		return "", err
	}

	req.Header.Set("Client-Id", s.config.OAuth2.ClientID)
	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", accessToken))

	res, err := s.client.Do(req)
	if res != nil {
		defer res.Body.Close()
	}
	if err != nil {
		log.Println(err.Error())
		return "", err
	}

	bodyBytes, err := ioutil.ReadAll(res.Body)
	if err != nil {
		log.Println(err.Error())
		return "", err
	}

	var u manyUsers
	err = json.Unmarshal(bodyBytes, &u)
	if err != nil {
		return "", err
	}

	if len(u.Users) > 1 {
		log.Println("multiple users found for the same id")
		return "", errors.New("multiple users found for the same id")
	}

	return u.Users[0].UserID, nil
}

// GetEnforcementStatus checks if a text string passes AutoMod settings
func (s *HelixService) GetEnforcementStatus(broadcaster_id, userID, messageText string) (bool, error) {
	m := manyMessages{
		[]message{
			{
				MessageID:   random(1, 1000),
				MessageText: messageText,
				UserID:      userID,
			},
		},
	}

	b := new(bytes.Buffer)
	json.NewEncoder(b).Encode(m)

	req, err := http.NewRequest("POST", fmt.Sprintf("https://api.twitch.tv/helix/moderation/enforcements/status?broadcaster_id=%s", broadcaster_id), b)
	if err != nil {
		log.Println(err.Error())
		return false, err
	}

	req.Header.Set("Client-Id", s.config.OAuth2.ClientID)
	req.Header.Set("Content-Type", "application/json")

	accessToken, err := s.getAccessToken(broadcaster_id)
	if err != nil {
		return false, err
	}

	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", accessToken))

	res, err := s.client.Do(req)
	if res != nil {
		defer res.Body.Close()
	}
	if err != nil {
		log.Println(err.Error())
		return false, err
	}

	bodyBytes, err := ioutil.ReadAll(res.Body)
	if err != nil {
		log.Println(err.Error())
		return false, err
	}

	err = json.Unmarshal(bodyBytes, &m)
	if err != nil {
		log.Println(err.Error())
		return false, err
	}

	return m.Messages[0].IsPermitted, nil
}

func random(min int, max int) string {
	return strconv.Itoa(rand.Intn(max-min) + min)
}

// getAccessToken returns the broadcaster's stored API access token, and refreshes it if it's expired
func (s *HelixService) getAccessToken(userID string) (string, error) {
	var accessToken string

	user, err := s.db.GetUser(userID)
	if err != nil {
		log.Println(err.Error())
		return "", err
	}

	token := &oauth2.Token{
		AccessToken:  user.AccessToken,
		RefreshToken: user.RefreshToken,
		Expiry:       user.Expiry,
		TokenType:    user.TokenType,
	}

	accessToken = user.AccessToken

	// Refresh the token
	if token.Expiry.Sub(time.Now()).Minutes() < 5 {
		tokenSource := s.config.OAuth2.TokenSource(oauth2.NoContext, token)
		newToken, err := tokenSource.Token()
		if err != nil {
			log.Println(err.Error())
			return "", err
		}

		if newToken.AccessToken != token.AccessToken {
			err = s.db.PutUser(&dynamodb.User{
				UserID:       userID,
				AccessToken:  newToken.AccessToken,
				RefreshToken: newToken.RefreshToken,
				Expiry:       newToken.Expiry,
				TokenType:    newToken.TokenType,
			})
			if err != nil {
				log.Println(err.Error())
				return "", err
			}

			s.client = oauth2.NewClient(oauth2.NoContext, tokenSource)

			accessToken = newToken.AccessToken
		}
	}

	return accessToken, nil
}
