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

type scriptData struct {
	Script string `json:"script"`
}

type Client interface {
	GetToken(ctx context.Context) (string, error)
	GetUserToken(ctx context.Context, accountId, userId string) (string, error)
	HasAccess(ctx context.Context, resourceId, action string) (bool, error)
	UserHasAccess(ctx context.Context, userId, resourceId, action string) (bool, error)
	CreateAccount(ctx context.Context, accountId string) (Account, error)
	CreateResource(ctx context.Context, resourceId, parentId, resourceType string) (Resource, error)
	CreateUser(ctx context.Context, userId, userName, displayName string) (User, error)
	CreateRole(ctx context.Context, roleId, roleName string) (Role, error)
	AssignRole(ctx context.Context, roleId, userId string) error
	UnassignRole(ctx context.Context, roleId, userId string) error
	CreatePermission(ctx context.Context, permitteeId, resourceId string, policies []string) error
	GetUsers(ctx context.Context) ([]User, error)
	GetRoles(ctx context.Context) ([]Role, error)
	GetUsersForRole(ctx context.Context, roleId string) ([]User, error)
	GetRolesForUser(ctx context.Context, userId string) ([]Role, error)
	RunScript(ctx context.Context, script string) error
	Ping(ctx context.Context) error
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

	req, err := http.NewRequest("GET", fmt.Sprintf(
		"%s/auth/token", c.baseURL), nil)
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

func (c *client) GetUserToken(ctx context.Context, accountId, userId string) (string, error) {

	req, err := http.NewRequest("GET", fmt.Sprintf(
		"%s/auth/token/accounts/%s/users/%s",
		c.baseURL, accountId, userId), nil)
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

func (c *client) HasAccess(ctx context.Context, resourceId, action string) (bool, error) {

	jwtToken := ctx.Value("cerberusToken")
	if jwtToken == nil {
		return false, fmt.Errorf("no token")
	}

	req, err := http.NewRequest(
		"GET",
		fmt.Sprintf("%s/api/access/resourceid/%s/actionname/%s", c.baseURL, resourceId, action), nil)
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

func (c *client) UserHasAccess(ctx context.Context, userId, resourceId, action string) (bool, error) {

	jwtToken := ctx.Value("cerberusToken")
	if jwtToken == nil {
		return false, fmt.Errorf("no token")
	}

	req, err := http.NewRequest(
		"GET",
		fmt.Sprintf("%s/api/access/permitteeid/%s/resourceid/%s/actionname/%s", c.baseURL, userId, resourceId, action), nil)
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

func (c *client) CreateResource(ctx context.Context, resourceId, parentId, resourceType string) (Resource, error) {

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
		fmt.Sprintf("%s/api/resources", c.baseURL),
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

func (c *client) CreateUser(ctx context.Context, userId, userName, displayName string) (User, error) {

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
		fmt.Sprintf("%s/api/users", c.baseURL),
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

func (c *client) CreateRole(ctx context.Context, roleId, roleName string) (Role, error) {

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
		fmt.Sprintf("%s/api/roles", c.baseURL),
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

func (c *client) AssignRole(ctx context.Context, roleId, userId string) error {

	jwtToken := ctx.Value("cerberusToken")
	if jwtToken == nil {
		return fmt.Errorf("no token")
	}

	req, err := http.NewRequest(
		"POST",
		fmt.Sprintf("%s/api/roles/%s/users/%s", c.baseURL, roleId, userId), nil)
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

func (c *client) UnassignRole(ctx context.Context, roleId, userId string) error {

	jwtToken := ctx.Value("cerberusToken")
	if jwtToken == nil {
		return fmt.Errorf("no token")
	}

	req, err := http.NewRequest(
		"DELETE",
		fmt.Sprintf("%s/api/roles/%s/users/%s", c.baseURL, roleId, userId), nil)
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

func (c *client) CreatePermission(ctx context.Context, permitteeId, resourceId string, policies []string) error {

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
		fmt.Sprintf("%s/api/permissions", c.baseURL),
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

func (c *client) GetUsers(ctx context.Context) ([]User, error) {
	jwtToken := ctx.Value("cerberusToken")
	if jwtToken == nil {
		return []User{}, fmt.Errorf("no token")
	}
	req, err := http.NewRequest(
		"GET",
		fmt.Sprintf("%s/api/users", c.baseURL),
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

func (c *client) GetRoles(ctx context.Context) ([]Role, error) {
	jwtToken := ctx.Value("cerberusToken")
	if jwtToken == nil {
		return []Role{}, fmt.Errorf("no token")
	}
	req, err := http.NewRequest(
		"GET",
		fmt.Sprintf("%s/api/roles", c.baseURL),
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

func (c *client) GetUsersForRole(ctx context.Context, roleId string) ([]User, error) {
	jwtToken := ctx.Value("cerberusToken")
	if jwtToken == nil {
		return []User{}, fmt.Errorf("no token")
	}
	req, err := http.NewRequest(
		"GET",
		fmt.Sprintf("%s/api/users/roles/%s", c.baseURL, roleId),
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

func (c *client) GetRolesForUser(ctx context.Context, userId string) ([]Role, error) {
	jwtToken := ctx.Value("cerberusToken")
	if jwtToken == nil {
		return []Role{}, fmt.Errorf("no token")
	}
	req, err := http.NewRequest(
		"GET",
		fmt.Sprintf("%s/api/roles/users/%s", c.baseURL, userId),
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

func (c *client) RunScript(ctx context.Context, script string) error {
	jwtToken := ctx.Value("cerberusToken")
	if jwtToken == nil {
		return fmt.Errorf("no token")
	}

	body := &scriptData{
		Script: script,
	}

	payloadBuf := new(bytes.Buffer)
	err := json.NewEncoder(payloadBuf).Encode(body)
	if err != nil {
		return err
	}

	req, err := http.NewRequest(
		"POST",
		fmt.Sprintf("%s/api/script", c.baseURL),
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

func (c *client) Ping(ctx context.Context) error {

	req, err := http.NewRequest(
		"GET",
		fmt.Sprintf("%s/ping", c.baseURL),
		nil)
	if err != nil {
		return err
	}

	req = req.WithContext(ctx)

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
