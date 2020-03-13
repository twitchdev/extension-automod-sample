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
	"net/http"

	jwt "github.com/dgrijalva/jwt-go"
)

const jwtClaimsKey contextKeyType = "jwtClaims"

type jwtClaims struct {
	ChannelID    string         `json:"channel_id"`
	IsUnlinked   bool           `json:"is_unlinked"`
	OpaqueUserID string         `json:"opaque_user_id"`
	UserID       string         `json:"user_id"`
	Role         string         `json:"role"`
	Permissions  jwtPermissions `json:"pubsub_perms"`
	jwt.StandardClaims
}

type jwtPermissions struct {
	Send   []string `json:"send,omitempty"`
	Listen []string `json:"listen,omitempty"`
}

func setClaims(r *http.Request, claims *jwtClaims) *http.Request {
	ctx := context.WithValue(r.Context(), jwtClaimsKey, claims)
	return r.WithContext(ctx)
}

func getClaims(r *http.Request) *jwtClaims {
	if claims, ok := r.Context().Value(jwtClaimsKey).(*jwtClaims); ok {
		return claims
	}
	return &jwtClaims{} // empty default
}
