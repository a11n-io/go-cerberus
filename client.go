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

type Account struct {
	Id string `json:"id"`
}

type Resource struct {
	Id       string `json:"id"`
	ParentId string `json:"parentId"`
}

type errorResponse struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

type successResponse struct {
	Code int         `json:"code"`
	Data interface{} `json:"data"`
}

type accountData struct {
	AccountId string `json:"accountId"`
}

type resourceData struct {
	ResourceId       string `json:"resourceId"`
	ParentId         string `json:"parentId"`
	ResourceTypeId   string `json:"resourceTypeId"`
	ResourceTypeName string `json:"resourceTypeName"`
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

type permissionData struct {
	PermitteeId string   `json:"permitteeId"`
	ResourceId  string   `json:"resourceId"`
	PolicyIds   []string `json:"policyIds"`
	PolicyNames []string `json:"policyNames"`
}

type Client interface {
	GetToken(ctx context.Context) (string, error)
	HasAccess(ctx context.Context, accountId, userId, resourceId, action string) (bool, error)
	CreateAccount(ctx context.Context, accountId string) (Account, error)
	CreateResource(ctx context.Context, accountId, resourceId, parentId, resourceType string) (Resource, error)
	CreateUser(ctx context.Context, accountId, userId, userName, displayName string) (User, error)
	CreateRole(ctx context.Context, accountId, roleId, roleName string) (Role, error)
	AssignRole(ctx context.Context, accountId, roleId, userId string) error
	CreatePermission(ctx context.Context, accountId, permitteeId, resourceId string, policies []string) error
	GetUsersForAccount(ctx context.Context, accountId string) ([]User, error)
	GetRolesForAccount(ctx context.Context, accountId string) ([]Role, error)
	GetUsersForRole(ctx context.Context, accountId, roleId string) ([]User, error)
	GetRolesForUser(ctx context.Context, accountId, userId string) ([]Role, error)
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

func (c *client) HasAccess(ctx context.Context, accountId, userId, resourceId, action string) (bool, error) {

	jwtToken := ctx.Value("cerberusToken")
	if jwtToken == nil {
		return false, fmt.Errorf("no token")
	}

	req, err := http.NewRequest(
		"GET",
		fmt.Sprintf("%s/api/accounts/%s/access/permitteeid/%s/resourceid/%s/actionname/%s", c.baseURL, accountId, userId, resourceId, action), nil)
	if err != nil {
		return false, err
	}

	req = req.WithContext(ctx)

	req.Header.Set("Authorization", "Bearer "+jwtToken.(string))

	if err := c.sendRequest(req, nil); err != nil {
		return false, err
	}

	return true, nil
}

func (c *client) CreateAccount(ctx context.Context, accountId string) (Account, error) {

	jwtToken := ctx.Value("cerberusToken")
	if jwtToken == nil {
		return Account{}, fmt.Errorf("no token")
	}

	body := &accountData{
		AccountId: accountId,
	}

	payloadBuf := new(bytes.Buffer)
	err := json.NewEncoder(payloadBuf).Encode(body)
	if err != nil {
		return Account{}, err
	}
	req, err := http.NewRequest(
		"POST",
		fmt.Sprintf("%s/api/accounts", c.baseURL),
		payloadBuf)
	if err != nil {
		return Account{}, err
	}

	req = req.WithContext(ctx)

	req.Header.Set("Authorization", "Bearer "+jwtToken.(string))

	var account Account
	if err := c.sendRequest(req, &account); err != nil {
		return Account{}, err
	}

	return account, nil
}

func (c *client) CreateResource(ctx context.Context, accountId, resourceId, parentId, resourceType string) (Resource, error) {

	jwtToken := ctx.Value("cerberusToken")
	if jwtToken == nil {
		return Resource{}, fmt.Errorf("no token")
	}

	body := &resourceData{
		ResourceId:       resourceId,
		ParentId:         parentId,
		ResourceTypeName: resourceType,
	}

	payloadBuf := new(bytes.Buffer)
	err := json.NewEncoder(payloadBuf).Encode(body)
	if err != nil {
		return Resource{}, err
	}
	req, err := http.NewRequest(
		"POST",
		fmt.Sprintf("%s/api/accounts/%s/resources", c.baseURL, accountId),
		payloadBuf)
	if err != nil {
		return Resource{}, err
	}

	req = req.WithContext(ctx)

	req.Header.Set("Authorization", "Bearer "+jwtToken.(string))

	var resource Resource
	if err := c.sendRequest(req, &resource); err != nil {
		return Resource{}, err
	}

	return resource, nil
}

func (c *client) CreateUser(ctx context.Context, accountId, userId, userName, displayName string) (User, error) {

	jwtToken := ctx.Value("cerberusToken")
	if jwtToken == nil {
		return User{}, fmt.Errorf("no token")
	}

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
		fmt.Sprintf("%s/api/accounts/%s/users", c.baseURL, accountId),
		payloadBuf)
	if err != nil {
		return User{}, err
	}

	req = req.WithContext(ctx)

	req.Header.Set("Authorization", "Bearer "+jwtToken.(string))

	var user User
	if err := c.sendRequest(req, &user); err != nil {
		return User{}, err
	}

	return user, nil
}

func (c *client) CreateRole(ctx context.Context, accountId, roleId, roleName string) (Role, error) {

	jwtToken := ctx.Value("cerberusToken")
	if jwtToken == nil {
		return Role{}, fmt.Errorf("no token")
	}

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
		fmt.Sprintf("%s/api/accounts/%s/roles", c.baseURL, accountId),
		payloadBuf)
	if err != nil {
		return Role{}, err
	}

	req = req.WithContext(ctx)

	req.Header.Set("Authorization", "Bearer "+jwtToken.(string))

	var role Role
	if err := c.sendRequest(req, &role); err != nil {
		return Role{}, err
	}

	return role, nil
}

func (c *client) AssignRole(ctx context.Context, accountId, roleId, userId string) error {

	jwtToken := ctx.Value("cerberusToken")
	if jwtToken == nil {
		return fmt.Errorf("no token")
	}

	req, err := http.NewRequest(
		"POST",
		fmt.Sprintf("%s/api/accounts/%s/roles/%s/users/%s", c.baseURL, accountId, roleId, userId), nil)
	if err != nil {
		return err
	}

	req = req.WithContext(ctx)

	req.Header.Set("Authorization", "Bearer "+jwtToken.(string))

	if err := c.sendRequest(req, nil); err != nil {
		return err
	}

	return nil
}

func (c *client) CreatePermission(ctx context.Context, accountId, permitteeId, resourceId string, policies []string) error {

	jwtToken := ctx.Value("cerberusToken")
	if jwtToken == nil {
		return fmt.Errorf("no token")
	}

	body := &permissionData{
		PermitteeId: permitteeId,
		ResourceId:  resourceId,
		PolicyNames: policies,
	}

	payloadBuf := new(bytes.Buffer)
	err := json.NewEncoder(payloadBuf).Encode(body)
	if err != nil {
		return err
	}
	req, err := http.NewRequest(
		"POST",
		fmt.Sprintf("%s/api/accounts/%s/permissions", c.baseURL, accountId),
		payloadBuf)
	if err != nil {
		return err
	}

	req = req.WithContext(ctx)

	req.Header.Set("Authorization", "Bearer "+jwtToken.(string))

	if err := c.sendRequest(req, nil); err != nil {
		return err
	}

	return nil
}

func (c *client) GetUsersForAccount(ctx context.Context, accountId string) ([]User, error) {
	jwtToken := ctx.Value("cerberusToken")
	if jwtToken == nil {
		return []User{}, fmt.Errorf("no token")
	}
	req, err := http.NewRequest(
		"GET",
		fmt.Sprintf("%s/api/accounts/%s/users", c.baseURL, accountId),
		nil)
	if err != nil {
		return []User{}, err
	}

	req = req.WithContext(ctx)

	req.Header.Set("Authorization", "Bearer "+jwtToken.(string))

	var users []User
	if err := c.sendRequest(req, &users); err != nil {
		return []User{}, err
	}

	return users, nil
}

func (c *client) GetRolesForAccount(ctx context.Context, accountId string) ([]Role, error) {
	jwtToken := ctx.Value("cerberusToken")
	if jwtToken == nil {
		return []Role{}, fmt.Errorf("no token")
	}
	req, err := http.NewRequest(
		"GET",
		fmt.Sprintf("%s/api/accounts/%s/roles", c.baseURL, accountId),
		nil)
	if err != nil {
		return []Role{}, err
	}

	req = req.WithContext(ctx)

	req.Header.Set("Authorization", "Bearer "+jwtToken.(string))

	var roles []Role
	if err := c.sendRequest(req, &roles); err != nil {
		return []Role{}, err
	}

	return roles, nil
}

func (c *client) GetUsersForRole(ctx context.Context, accountId, roleId string) ([]User, error) {
	jwtToken := ctx.Value("cerberusToken")
	if jwtToken == nil {
		return []User{}, fmt.Errorf("no token")
	}
	req, err := http.NewRequest(
		"GET",
		fmt.Sprintf("%s/api/accounts/%s/users/roles/%s", c.baseURL, accountId, roleId),
		nil)
	if err != nil {
		return []User{}, err
	}

	req = req.WithContext(ctx)

	req.Header.Set("Authorization", "Bearer "+jwtToken.(string))

	var users []User
	if err := c.sendRequest(req, &users); err != nil {
		return []User{}, err
	}

	return users, nil
}

func (c *client) GetRolesForUser(ctx context.Context, accountId, userId string) ([]Role, error) {
	jwtToken := ctx.Value("cerberusToken")
	if jwtToken == nil {
		return []Role{}, fmt.Errorf("no token")
	}
	req, err := http.NewRequest(
		"GET",
		fmt.Sprintf("%s/api/accounts/%s/roles/users/%s", c.baseURL, accountId, userId),
		nil)
	if err != nil {
		return []Role{}, err
	}

	req = req.WithContext(ctx)

	req.Header.Set("Authorization", "Bearer "+jwtToken.(string))

	var roles []Role
	if err := c.sendRequest(req, &roles); err != nil {
		return []Role{}, err
	}

	return roles, nil
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
