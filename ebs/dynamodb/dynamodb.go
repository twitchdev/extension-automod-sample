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

package dynamodb

import (
	"fmt"
	"time"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/dynamodb"
	"github.com/aws/aws-sdk-go/service/dynamodb/dynamodbattribute"
)

const (
	tableName = "automodder-users"
)

// DynamoDBService provides methods to use DynamoDB via the AWS SDK
type DynamoDBService struct {
	*dynamodb.DynamoDB
}

// User represents the broadcaster and their API credentials in DynamoDB
type User struct {
	UserID       string
	AccessToken  string
	RefreshToken string
	Expiry       time.Time
	TokenType    string
}

// NewDynamoDBService creates a new DynamoDBService by loading AWS credentials
// from ~/.aws/credentials and AWS region from ~/.aws/config
func NewDynamoDBService() *DynamoDBService {
	s := session.Must(session.NewSessionWithOptions(session.Options{
		SharedConfigState: session.SharedConfigEnable,
	}))

	return &DynamoDBService{dynamodb.New(s)}
}

// GetUser returns a user from DynamoDB
func (db *DynamoDBService) GetUser(userID string) (*User, error) {
	result, err := db.GetItem(&dynamodb.GetItemInput{
		TableName: aws.String(tableName),
		Key: map[string]*dynamodb.AttributeValue{
			"UserID": {
				S: aws.String(userID),
			},
		},
	})

	if err != nil {
		return nil, err
	}

	user := User{}

	err = dynamodbattribute.UnmarshalMap(result.Item, &user)
	if err != nil {
		return nil, err
	}

	if user.UserID == "" {
		return nil, fmt.Errorf("user %s not found in the database", userID)
	}

	return &user, nil
}

// PutUser creates and updates a new user in DynamoDB
func (db *DynamoDBService) PutUser(user *User) error {
	item, err := dynamodbattribute.MarshalMap(user)
	if err != nil {
		return err
	}

	_, err = db.PutItem(&dynamodb.PutItemInput{
		TableName: aws.String(tableName),
		Item:      item,
	})

	if err != nil {
		return err
	}

	return nil
}
