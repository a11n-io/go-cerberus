package go_cerberus

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"time"
)

type User struct {
	Id          string `json:"id"`
	DisplayName string `json:"displayName"`
	UserName    string `json:"userName"`
}

type Role struct {
	Id       string `json:"id"`
	RoleName string `json:"roleName"`
}

type Resource struct {
	Id string `json:"id"`
}

type errorResponse struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

type successResponse struct {
	Code int         `json:"code"`
	Data interface{} `json:"data"`
}

type resourceData struct {
	ResourceId     string `json:"resourceId"`
	ResourceTypeId string `json:"resourceTypeId"`
}

type userData struct {
	UserId      string `json:"userId"`
	UserName    string `json:"userName"`
	DisplayName string `json:"displayName"`
}

type roleData struct {
	RoleId   string `json:"roleId"`
	RoleName string `json:"roleName"`
}

type Client interface {
	GetToken(ctx context.Context) (string, error)
	CreateResource(ctx context.Context, jwtToken, accountId, resourceId, resourceTypeId string) (Resource, error)
	CreateUser(ctx context.Context, jwtToken, accountId, userId, userName, displayName string) (User, error)
	CreateRole(ctx context.Context, jwtToken, accountId, roleId, roleName string) (Role, error)
	AssignRole(ctx context.Context, jwtToken, accountId, roleId, userId string) error
}

type client struct {
	baseURL    string
	apiKey     string
	apiSecret  string
	HTTPClient *http.Client
}

func NewClient(baseUrl, apiKey, apiSecret string) Client {
	return &client{
		baseURL:   baseUrl,
		apiKey:    apiKey,
		apiSecret: apiSecret,
		HTTPClient: &http.Client{
			Timeout: time.Minute,
		},
	}
}

func (c *client) GetToken(ctx context.Context) (string, error) {

	req, err := http.NewRequest("GET", fmt.Sprintf("%s/auth/token", c.baseURL), nil)
	if err != nil {
		return "", err
	}

	req = req.WithContext(ctx)

	req.SetBasicAuth(c.apiKey, c.apiSecret)

	var token string
	if err := c.sendRequest(req, &token); err != nil {
		return "", err
	}

	return token, nil
}

func (c *client) CreateResource(ctx context.Context, jwtToken, accountId, resourceId, resourceTypeId string) (Resource, error) {

	body := &resourceData{
		ResourceId:     resourceId,
		ResourceTypeId: resourceTypeId,
	}

	payloadBuf := new(bytes.Buffer)
	err := json.NewEncoder(payloadBuf).Encode(body)
	if err != nil {
		return Resource{}, err
	}
	req, err := http.NewRequest(
		"POST",
		fmt.Sprintf("%s/accounts/%s/resources", c.baseURL, accountId),
		payloadBuf)
	if err != nil {
		return Resource{}, err
	}

	req = req.WithContext(ctx)

	req.Header.Set("CerberusAuthorization", "Bearer "+jwtToken)

	var resource Resource
	if err := c.sendRequest(req, &resource); err != nil {
		return Resource{}, err
	}

	return resource, nil
}

func (c *client) CreateUser(ctx context.Context, jwtToken, accountId, userId, userName, displayName string) (User, error) {

	body := &userData{
		UserId:      userId,
		UserName:    userName,
		DisplayName: displayName,
	}

	payloadBuf := new(bytes.Buffer)
	err := json.NewEncoder(payloadBuf).Encode(body)
	if err != nil {
		return User{}, err
	}
	req, err := http.NewRequest(
		"POST",
		fmt.Sprintf("%s/accounts/%s/users", c.baseURL, accountId),
		payloadBuf)
	if err != nil {
		return User{}, err
	}

	req = req.WithContext(ctx)

	req.Header.Set("CerberusAuthorization", "Bearer "+jwtToken)

	var user User
	if err := c.sendRequest(req, &user); err != nil {
		return User{}, err
	}

	return user, nil
}

func (c *client) CreateRole(ctx context.Context, jwtToken, accountId, roleId, roleName string) (Role, error) {

	body := &roleData{
		RoleId:   roleId,
		RoleName: roleName,
	}

	payloadBuf := new(bytes.Buffer)
	err := json.NewEncoder(payloadBuf).Encode(body)
	if err != nil {
		return Role{}, err
	}
	req, err := http.NewRequest(
		"POST",
		fmt.Sprintf("%s/accounts/%s/roles", c.baseURL, accountId),
		payloadBuf)
	if err != nil {
		return Role{}, err
	}

	req = req.WithContext(ctx)

	req.Header.Set("CerberusAuthorization", "Bearer "+jwtToken)

	var role Role
	if err := c.sendRequest(req, &role); err != nil {
		return Role{}, err
	}

	return role, nil
}

func (c *client) AssignRole(ctx context.Context, jwtToken, accountId, roleId, userId string) error {

	req, err := http.NewRequest(
		"POST",
		fmt.Sprintf("%s/accounts/%s/roles/%s/users/%s", c.baseURL, accountId, roleId, userId), nil)
	if err != nil {
		return err
	}

	req = req.WithContext(ctx)

	req.Header.Set("CerberusAuthorization", "Bearer "+jwtToken)

	if err := c.sendRequest(req, nil); err != nil {
		return err
	}

	return nil
}

func (c *client) sendRequest(req *http.Request, v interface{}) error {

	req.Header.Set("Content-Type", "application/json; charset=utf-8")
	req.Header.Set("Accept", "application/json; charset=utf-8")

	res, err := c.HTTPClient.Do(req)
	if err != nil {
		return err
	}

	defer res.Body.Close()

	if res.StatusCode < http.StatusOK || res.StatusCode >= http.StatusBadRequest {
		var errRes errorResponse
		if err = json.NewDecoder(res.Body).Decode(&errRes); err == nil {
			return errors.New(errRes.Message)
		}

		return fmt.Errorf("unknown error, status code: %d", res.StatusCode)
	}

	if v != nil {
		fullResponse := successResponse{
			Data: v,
		}
		if err = json.NewDecoder(res.Body).Decode(&fullResponse); err != nil {
			return err
		}
	}

	return nil
}
