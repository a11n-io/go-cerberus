// Package go_cerberus provides functions for interacting with the a11n.io cerberus backend,
// whether hosted on our cloud servers, or on-premises in your own data-center.
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

// A User contains information identifying a cerberus user
// specific to an Account on an App.
type User struct {
	Id          string `json:"id"`
	DisplayName string `json:"displayName"`
	UserName    string `json:"userName"`
}

// A Role contains information identifying a cerberus role
// specific to an Account on an App.
type Role struct {
	Id   string `json:"id"`
	Name string `json:"name"`
}

// An Account contains information identifying a cerberus account
// specific to an App.
type Account struct {
	Id string `json:"id"`
}

// A Resource contains information identifying a cerberus resource.
// A Resource is anything your clients want to have access-controlled
// specific to an App.
type Resource struct {
	Id       string `json:"id"`
	ParentId string `json:"parentId"`
}

// A MigrationVersion specifies the version and state of a migration
// of static rules on an app.
type MigrationVersion struct {
	Version int  `json:"version"`
	Dirty   bool `json:"dirty"`
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
	RoleId string `json:"roleId"`
	Name   string `json:"name"`
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

// Commands

type Command struct {
	CreateAccount    *createAccountCmd    `json:"createAccount,omitempty"`
	CreateResource   *createResourceCmd   `json:"createResource,omitempty"`
	CreateUser       *createUserCmd       `json:"createUser,omitempty"`
	CreateRole       *createRoleCmd       `json:"createRole,omitempty"`
	AssignRole       *assignRoleCmd       `json:"assignRole,omitempty"`
	UnassignRole     *unassignRoleCmd     `json:"unassignRole,omitempty"`
	CreatePermission *createPermissionCmd `json:"createPermission,omitempty"`
}

type createAccountCmd struct {
	AccountId string `json:"accountId"`
}
type createResourceCmd struct {
	ResourceId   string `json:"resourceId"`
	ParentId     string `json:"parentId"`
	ResourceType string `json:"resourceType"`
}
type createUserCmd struct {
	UserId      string `json:"userId"`
	UserName    string `json:"userName"`
	DisplayName string `json:"displayName"`
}
type createRoleCmd struct {
	RoleId string `json:"roleId"`
	Name   string `json:"roleName"`
}
type assignRoleCmd struct {
	RoleId string `json:"roleId"`
	UserId string `json:"userId"`
}
type unassignRoleCmd struct {
	RoleId string `json:"roleId"`
	UserId string `json:"userId"`
}
type createPermissionCmd struct {
	PermitteeId string   `json:"permitteeId"`
	ResourceId  string   `json:"resourceId"`
	Policies    []string `json:"policies"`
}

// A CerberusClient has the ability to communicate to the cerberus backend
// using an ApiKey and ApiSecret, which represents a specific App
type CerberusClient interface {
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
	GetMigrationVersion(ctx context.Context) (MigrationVersion, error)
	SetMigrationVersion(ctx context.Context, version MigrationVersion) error
	Ping(ctx context.Context) error

	Execute(ctx context.Context, command ...Command) error
	CreateAccountCmd(accountId string) Command
	CreateResourceCmd(resourceId, parentId, resourceType string) Command
	CreateUserCmd(userId, userName, displayName string) Command
	CreateRoleCmd(roleId, roleName string) Command
	AssignRoleCmd(roleId, userId string) Command
	UnassignRoleCmd(roleId, userId string) Command
	CreatePermissionCmd(permitteeId, resourceId string, policies []string) Command
}

type Client struct {
	baseURL    string
	apiKey     string
	apiSecret  string
	HTTPClient *http.Client
}

// NewClient constructs a new client with apiKey and apiSecret
// communicating with the cerberus backend at baseUrl.
func NewClient(baseUrl, apiKey, apiSecret string) CerberusClient {
	return &Client{
		baseURL:   baseUrl,
		apiKey:    apiKey,
		apiSecret: apiSecret,
		HTTPClient: &http.Client{
			Timeout: time.Minute,
		},
	}
}

// GetToken swaps the apiKey and apiSecret for a short-lived JWT token
// meant to be used by machine-type clients (e.g. migration automation, etc.).
// The token returned is required for all other function calls.
// This is the first function that should be called.
func (c *Client) GetToken(ctx context.Context) (string, error) {

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

// GetUserToken swaps the apiKey and apiSecret for a short-lived JWT token
// meant to be used by user-type clients (e.g. browsers with a logged-in user).
// The token returned is required for all other function calls.
// This is the first function that should be called.
func (c *Client) GetUserToken(ctx context.Context, accountId, userId string) (string, error) {

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

// HasAccess determines if the userId in the token has sufficient access rights for resourceId
// in order to perform action on it.
// It is assumed that the JWT token acquired earlier is now in ctx, under the key 'cerberusToken'
// and that the JWT token is a user token.
func (c *Client) HasAccess(ctx context.Context, resourceId, action string) (bool, error) {

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

// UserHasAccess determines if the userId passed in has sufficient access rights for resourceId
// in order to perform action on it.
// It is assumed that the JWT token acquired earlier is now in ctx, under the key 'cerberusToken'.
func (c *Client) UserHasAccess(ctx context.Context, userId, resourceId, action string) (bool, error) {

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

// CreateAccount creates a new Account for an App with accountId as identifier.
// It is assumed there is a user token in ctx under the key 'cerberusToken',
// and the accountId should match the one previously specified to acquire the token
func (c *Client) CreateAccount(ctx context.Context, accountId string) (Account, error) {

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

// CreateResource creates a new Resource on an Account, which belongs to an App.
// The resource is identified by resourceId, has an optional parent parentId and is of resourceType.
// It is assumed that the JWT token acquired earlier is now in ctx, under the key 'cerberusToken'.
func (c *Client) CreateResource(ctx context.Context, resourceId, parentId, resourceType string) (Resource, error) {

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

// CreateUser creates a new User on an Account, which belongs to an App.
// The User is identified by userId, has a userName which is unique for the Account
// and a displayName for display.
// It is assumed that the JWT token acquired earlier is now in ctx, under the key 'cerberusToken'.
func (c *Client) CreateUser(ctx context.Context, userId, userName, displayName string) (User, error) {

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

// CreateRole creates a new Role on an Account, which belongs to an App.
// A Role is identified by a roleId, and has a roleName unique to the Account.
// It is assumed that the JWT token acquired earlier is now in ctx, under the key 'cerberusToken'.
func (c *Client) CreateRole(ctx context.Context, roleId, name string) (Role, error) {

	jwtToken := ctx.Value("cerberusToken")
	if jwtToken == nil {
		return Role{}, fmt.Errorf("no token")
	}

	body := &roleData{
		RoleId: roleId,
		Name:   name,
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

// AssignRole assigns the User identified by userId to the Role identified by roleId.
// It is assumed that the JWT token acquired earlier is now in ctx, under the key 'cerberusToken'.
func (c *Client) AssignRole(ctx context.Context, roleId, userId string) error {

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

// UnassignRole removes the User identified by userId from the Role identified by roleId.
// It is assumed that the JWT token acquired earlier is now in ctx, under the key 'cerberusToken'.
func (c *Client) UnassignRole(ctx context.Context, roleId, userId string) error {

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

// CreatePermission grants permission to some permittee (which could be a User, a Role or a machine Client)
// to the Resource identified by resourceId by granting a list of Policies which specifies which Actions are allowed.
// It is assumed that the JWT token acquired earlier is now in ctx, under the key 'cerberusToken'.
func (c *Client) CreatePermission(ctx context.Context, permitteeId, resourceId string, policies []string) error {

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

// GetUsers returns all the Users for an Account.
// It is assumed that the JWT token acquired earlier is now in ctx, under the key 'cerberusToken'.
func (c *Client) GetUsers(ctx context.Context) ([]User, error) {
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

// GetRoles returns all the Roles for an Account.
// It is assumed that the JWT token acquired earlier is now in ctx, under the key 'cerberusToken'.
func (c *Client) GetRoles(ctx context.Context) ([]Role, error) {
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

// GetUsersForRole returns all the Users in the Account
// who have been assigned to the Role identified by roleId.
// It is assumed that the JWT token acquired earlier is now in ctx, under the key 'cerberusToken'.
func (c *Client) GetUsersForRole(ctx context.Context, roleId string) ([]User, error) {
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

// GetRolesForUser returns all the Roles to which the User identified by userId
// has been assigned to.
// It is assumed that the JWT token acquired earlier is now in ctx, under the key 'cerberusToken'.
func (c *Client) GetRolesForUser(ctx context.Context, userId string) ([]Role, error) {
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

// RunScript runs a script on the App.
// It is assumed that the JWT token acquired earlier is now in ctx, under the key 'cerberusToken'.
func (c *Client) RunScript(ctx context.Context, script string) error {
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

// GetMigrationVersion returns the latest migration version and status for the App.
// It is assumed that the JWT token acquired earlier is now in ctx, under the key 'cerberusToken'.
func (c *Client) GetMigrationVersion(ctx context.Context) (MigrationVersion, error) {
	jwtToken := ctx.Value("cerberusToken")
	if jwtToken == nil {
		return MigrationVersion{}, fmt.Errorf("no token")
	}
	req, err := http.NewRequest(
		"GET",
		fmt.Sprintf("%s/api/migrationversion", c.baseURL),
		nil)
	if err != nil {
		return MigrationVersion{}, err
	}

	req = req.WithContext(ctx)

	req.Header.Set("Authorization", "Bearer "+jwtToken.(string))

	var mv MigrationVersion
	if err := c.sendRequest(req, &mv); err != nil {
		return MigrationVersion{}, err
	}

	return mv, nil
}

// SetMigrationVersion sets the latest migration version and status for an App.
// It is assumed that the JWT token acquired earlier is now in ctx, under the key 'cerberusToken'.
func (c *Client) SetMigrationVersion(ctx context.Context, version MigrationVersion) error {
	jwtToken := ctx.Value("cerberusToken")
	if jwtToken == nil {
		return fmt.Errorf("no token")
	}

	payloadBuf := new(bytes.Buffer)
	err := json.NewEncoder(payloadBuf).Encode(version)
	if err != nil {
		return err
	}

	req, err := http.NewRequest(
		"POST",
		fmt.Sprintf("%s/api/migrationversion", c.baseURL),
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

// Ping pings the cerberus backend.
// If successful, an HTTP 200 with json result "pong" is returned.
// No token is required.
func (c *Client) Ping(ctx context.Context) error {

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

// Execute runs a series of commands in the given order within one transaction.
// It is assumed that the JWT token acquired earlier is now in ctx, under the key 'cerberusToken'.
func (c *Client) Execute(ctx context.Context, commands ...Command) error {

	jwtToken := ctx.Value("cerberusToken")
	if jwtToken == nil {
		return fmt.Errorf("no token")
	}

	payloadBuf := new(bytes.Buffer)
	err := json.NewEncoder(payloadBuf).Encode(commands)
	if err != nil {
		return err
	}

	req, err := http.NewRequest(
		"POST",
		fmt.Sprintf("%s/api/commands", c.baseURL),
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

// CreateAccountCmd returns a Command for CreateAccount
func (c *Client) CreateAccountCmd(accountId string) Command {
	return Command{
		CreateAccount: &createAccountCmd{
			AccountId: accountId,
		},
	}
}

// CreateResourceCmd returns a Command for CreateResource
func (c *Client) CreateResourceCmd(resourceId, parentId, resourceType string) Command {
	return Command{
		CreateResource: &createResourceCmd{
			ResourceId:   resourceId,
			ParentId:     parentId,
			ResourceType: resourceType,
		},
	}
}

// CreateUserCmd returns a Command for CreateUser
func (c *Client) CreateUserCmd(userId, userName, displayName string) Command {
	return Command{
		CreateUser: &createUserCmd{
			UserId:      userId,
			UserName:    userName,
			DisplayName: displayName,
		},
	}
}

// CreateRoleCmd returns a Command for CreateRole
func (c *Client) CreateRoleCmd(roleId, name string) Command {
	return Command{
		CreateRole: &createRoleCmd{
			RoleId: roleId,
			Name:   name,
		},
	}
}

// AssignRoleCmd returns a Command for AssignRole
func (c *Client) AssignRoleCmd(roleId, userId string) Command {
	return Command{
		AssignRole: &assignRoleCmd{
			RoleId: roleId,
			UserId: userId,
		},
	}
}

// UnassignRoleCmd returns a Command for UnassignRole
func (c *Client) UnassignRoleCmd(roleId, userId string) Command {
	return Command{
		UnassignRole: &unassignRoleCmd{
			RoleId: roleId,
			UserId: userId,
		},
	}
}

// CreatePermissionCmd returns a Command for CreatePermission
func (c *Client) CreatePermissionCmd(permitteeId, resourceId string, policies []string) Command {
	return Command{
		CreatePermission: &createPermissionCmd{
			PermitteeId: permitteeId,
			ResourceId:  resourceId,
			Policies:    policies,
		},
	}
}

func (c *Client) sendRequest(req *http.Request, v interface{}) error {

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
