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

// A TokenPair contains a short-lived access token and a long-lived refresh token
type TokenPair struct {
	AccessToken  string `json:"accessToken"`
	RefreshToken string `json:"refreshToken"`
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
	RoleId       string `json:"roleId"`
	Name         string `json:"name"`
	IsSuperAdmin bool   `json:"isSuperAdmin"`
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

type refreshTokenData struct {
	RefreshToken string `json:"refreshToken"`
}

// Commands

type executeCommands struct {
	AccountId string    `json:"accountId,omitempty"`
	UserId    string    `json:"userId,omitempty"`
	Commands  []Command `json:"commands"`
}

type Command struct {
	CreateAccount        *createAccountCmd        `json:"createAccount,omitempty"`
	CreateResource       *createResourceCmd       `json:"createResource,omitempty"`
	CreateUser           *createUserCmd           `json:"createUser,omitempty"`
	CreateRole           *createRoleCmd           `json:"createRole,omitempty"`
	AssignRole           *assignRoleCmd           `json:"assignRole,omitempty"`
	UnassignRole         *unassignRoleCmd         `json:"unassignRole,omitempty"`
	CreateUserPermission *createUserPermissionCmd `json:"createUserPermission,omitempty"`
	CreateRolePermission *createRolePermissionCmd `json:"createRolePermission,omitempty"`
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
	RoleId       string `json:"roleId,omitempty"`
	Name         string `json:"roleName"`
	IsSuperAdmin bool   `json:"isSuperAdmin"`
}
type assignRoleCmd struct {
	RoleName string `json:"roleName"`
	UserId   string `json:"userId"`
}
type unassignRoleCmd struct {
	RoleName string `json:"roleName"`
	UserId   string `json:"userId"`
}
type createUserPermissionCmd struct {
	UserId     string   `json:"userId"`
	ResourceId string   `json:"resourceId"`
	Policies   []string `json:"policies"`
}
type createRolePermissionCmd struct {
	RoleName   string   `json:"roleName"`
	ResourceId string   `json:"resourceId"`
	Policies   []string `json:"policies"`
}

// A CerberusClient has the ability to communicate to the cerberus backend
// using an ApiKey and ApiSecret, which represents a specific App
type CerberusClient interface {
	GetToken() (TokenPair, error)
	GetUserToken(accountId, userId string) (TokenPair, error)
	HasAccess(ctx context.Context, resourceId, action string) (bool, error)
	UserHasAccess(ctx context.Context, userId, resourceId, action string) (bool, error)
	GetUsers(ctx context.Context) ([]User, error)
	GetRoles(ctx context.Context) ([]Role, error)
	GetUsersForRole(ctx context.Context, roleId string) ([]User, error)
	GetRolesForUser(ctx context.Context, userId string) ([]Role, error)
	RunScript(ctx context.Context, script string) error
	GetMigrationVersion(ctx context.Context) (MigrationVersion, error)
	SetMigrationVersion(ctx context.Context, version MigrationVersion) error
	Ping(ctx context.Context) error

	Execute(accountId, userId string, command ...Command) error
	ExecuteWithCtx(ctx context.Context, command ...Command) error
	CreateAccountCmd(accountId string) Command
	CreateResourceCmd(resourceId, parentId, resourceType string) Command
	CreateUserCmd(userId, userName, displayName string) Command
	CreateRoleCmd(roleName string) Command
	CreateRoleWithIdCmd(roleId, roleName string) Command
	CreateSuperRoleCmd(roleName string) Command
	CreateSuperRoleWithIdCmd(roleId, roleName string) Command
	AssignRoleCmd(roleName, userId string) Command
	UnassignRoleCmd(roleName, userId string) Command
	CreateUserPermissionCmd(userId, resourceId string, policies []string) Command
	CreateRolePermissionCmd(roleName, resourceId string, policies []string) Command
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

// GetToken swaps the apiKey and apiSecret for a TokenPair
// meant to be used by machine-type clients (e.g. migration automation, etc.).
// The token returned is required for all other function calls.
// This is the first function that should be called.
func (c *Client) GetToken() (TokenPair, error) {

	req, err := http.NewRequest("GET", fmt.Sprintf(
		"%s/auth/token", c.baseURL), nil)
	if err != nil {
		return TokenPair{}, err
	}

	req.SetBasicAuth(c.apiKey, c.apiSecret)

	var tokenPair TokenPair
	if err := c.sendRequest(req, &tokenPair); err != nil {
		return TokenPair{}, err
	}

	return tokenPair, nil
}

// GetUserToken swaps the apiKey and apiSecret for a TokenPair
// meant to be used by user-type clients (e.g. browsers with a logged-in user).
// The token returned is required for all other function calls.
// This is the first function that should be called.
func (c *Client) GetUserToken(accountId, userId string) (TokenPair, error) {

	req, err := http.NewRequest("GET", fmt.Sprintf(
		"%s/auth/token/accounts/%s/users/%s",
		c.baseURL, accountId, userId), nil)
	if err != nil {
		return TokenPair{}, err
	}

	req.SetBasicAuth(c.apiKey, c.apiSecret)

	var tokenPair TokenPair
	if err := c.sendRequest(req, &tokenPair); err != nil {
		return TokenPair{}, err
	}

	return tokenPair, nil
}

// RefreshToken swaps a refreshToken for a TokenPair with a new access token
func (c *Client) RefreshToken(ctx context.Context, refreshToken string) (TokenPair, error) {

	body := &refreshTokenData{
		RefreshToken: refreshToken,
	}

	payloadBuf := new(bytes.Buffer)
	err := json.NewEncoder(payloadBuf).Encode(body)
	if err != nil {
		return TokenPair{}, err
	}

	req, err := http.NewRequest("POST", fmt.Sprintf(
		"%s/auth/refreshtoken", c.baseURL), payloadBuf)
	if err != nil {
		return TokenPair{}, err
	}

	req = req.WithContext(ctx)

	var tokenPair TokenPair
	if err := c.sendRequest(req, &tokenPair); err != nil {
		return TokenPair{}, err
	}

	return tokenPair, nil
}

// HasAccess determines if the userId in the token has sufficient access rights for resourceId
// in order to perform action on it.
// It is assumed that the JWT token pair acquired earlier is now in ctx, under the key 'cerberusTokenPair'
// and that the JWT token is a user token.
func (c *Client) HasAccess(ctx context.Context, resourceId, action string) (bool, error) {

	jwtTokenPair := ctx.Value("cerberusTokenPair")
	if jwtTokenPair == nil {
		return false, fmt.Errorf("no token")
	}

	req, err := http.NewRequest(
		"GET",
		fmt.Sprintf("%s/access/resource/%s/action/%s", c.baseURL, resourceId, action), nil)
	if err != nil {
		return false, err
	}

	req = req.WithContext(ctx)

	req.Header.Set("Authorization", "Bearer "+jwtTokenPair.(TokenPair).AccessToken)

	if err := c.sendRequest(req, nil); err != nil {
		return false, err
	}

	return true, nil
}

// UserHasAccess determines if the userId passed in has sufficient access rights for resourceId
// in order to perform action on it.
// It is assumed that the JWT token pair acquired earlier is now in ctx, under the key 'cerberusTokenPair'.
func (c *Client) UserHasAccess(ctx context.Context, userId, resourceId, action string) (bool, error) {

	jwtTokenPair := ctx.Value("cerberusTokenPair")
	if jwtTokenPair == nil {
		return false, fmt.Errorf("no token")
	}

	req, err := http.NewRequest(
		"GET",
		fmt.Sprintf("%s/access/permittee/%s/resource/%s/action/%s", c.baseURL, userId, resourceId, action), nil)
	if err != nil {
		return false, err
	}

	req = req.WithContext(ctx)

	req.Header.Set("Authorization", "Bearer "+jwtTokenPair.(TokenPair).AccessToken)

	if err := c.sendRequest(req, nil); err != nil {
		return false, err
	}

	return true, nil
}

// GetUsers returns all the Users for an Account.
// It is assumed that the JWT token pair acquired earlier is now in ctx, under the key 'cerberusTokenPair'.
func (c *Client) GetUsers(ctx context.Context) ([]User, error) {
	jwtTokenPair := ctx.Value("cerberusTokenPair")
	if jwtTokenPair == nil {
		return []User{}, fmt.Errorf("no token")
	}
	req, err := http.NewRequest(
		"GET",
		fmt.Sprintf("%s/users", c.baseURL),
		nil)
	if err != nil {
		return []User{}, err
	}

	req = req.WithContext(ctx)

	req.Header.Set("Authorization", "Bearer "+jwtTokenPair.(TokenPair).AccessToken)

	var users []User
	if err := c.sendRequest(req, &users); err != nil {
		return []User{}, err
	}

	return users, nil
}

// GetRoles returns all the Roles for an Account.
// It is assumed that the JWT token pair acquired earlier is now in ctx, under the key 'cerberusTokenPair'.
func (c *Client) GetRoles(ctx context.Context) ([]Role, error) {
	jwtTokenPair := ctx.Value("cerberusTokenPair")
	if jwtTokenPair == nil {
		return []Role{}, fmt.Errorf("no token")
	}
	req, err := http.NewRequest(
		"GET",
		fmt.Sprintf("%s/roles", c.baseURL),
		nil)
	if err != nil {
		return []Role{}, err
	}

	req = req.WithContext(ctx)

	req.Header.Set("Authorization", "Bearer "+jwtTokenPair.(TokenPair).AccessToken)

	var roles []Role
	if err := c.sendRequest(req, &roles); err != nil {
		return []Role{}, err
	}

	return roles, nil
}

// GetUsersForRole returns all the Users in the Account
// who have been assigned to the Role identified by roleId.
// It is assumed that the JWT token pair acquired earlier is now in ctx, under the key 'cerberusTokenPair'.
func (c *Client) GetUsersForRole(ctx context.Context, roleId string) ([]User, error) {
	jwtTokenPair := ctx.Value("cerberusTokenPair")
	if jwtTokenPair == nil {
		return []User{}, fmt.Errorf("no token")
	}
	req, err := http.NewRequest(
		"GET",
		fmt.Sprintf("%s/users/roles/%s", c.baseURL, roleId),
		nil)
	if err != nil {
		return []User{}, err
	}

	req = req.WithContext(ctx)

	req.Header.Set("Authorization", "Bearer "+jwtTokenPair.(TokenPair).AccessToken)

	var users []User
	if err := c.sendRequest(req, &users); err != nil {
		return []User{}, err
	}

	return users, nil
}

// GetRolesForUser returns all the Roles to which the User identified by userId
// has been assigned to.
// It is assumed that the JWT token pair acquired earlier is now in ctx, under the key 'cerberusTokenPair'.
func (c *Client) GetRolesForUser(ctx context.Context, userId string) ([]Role, error) {
	jwtTokenPair := ctx.Value("cerberusTokenPair")
	if jwtTokenPair == nil {
		return []Role{}, fmt.Errorf("no token")
	}
	req, err := http.NewRequest(
		"GET",
		fmt.Sprintf("%s/roles/users/%s", c.baseURL, userId),
		nil)
	if err != nil {
		return []Role{}, err
	}

	req = req.WithContext(ctx)

	req.Header.Set("Authorization", "Bearer "+jwtTokenPair.(TokenPair).AccessToken)

	var roles []Role
	if err := c.sendRequest(req, &roles); err != nil {
		return []Role{}, err
	}

	return roles, nil
}

// RunScript runs a script on the App.
// It is assumed that the JWT token pair acquired earlier is now in ctx, under the key 'cerberusTokenPair'.
func (c *Client) RunScript(ctx context.Context, script string) error {
	jwtTokenPair := ctx.Value("cerberusTokenPair")
	if jwtTokenPair == nil {
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
		fmt.Sprintf("%s/script", c.baseURL),
		payloadBuf)
	if err != nil {
		return err
	}

	req = req.WithContext(ctx)

	req.Header.Set("Authorization", "Bearer "+jwtTokenPair.(TokenPair).AccessToken)

	if err := c.sendRequest(req, nil); err != nil {
		return err
	}

	return nil
}

// GetMigrationVersion returns the latest migration version and status for the App.
// It is assumed that the JWT token pair acquired earlier is now in ctx, under the key 'cerberusTokenPair'.
func (c *Client) GetMigrationVersion(ctx context.Context) (MigrationVersion, error) {
	jwtTokenPair := ctx.Value("cerberusTokenPair")
	if jwtTokenPair == nil {
		return MigrationVersion{}, fmt.Errorf("no token")
	}
	req, err := http.NewRequest(
		"GET",
		fmt.Sprintf("%s/migrationversion", c.baseURL),
		nil)
	if err != nil {
		return MigrationVersion{}, err
	}

	req = req.WithContext(ctx)

	req.Header.Set("Authorization", "Bearer "+jwtTokenPair.(TokenPair).AccessToken)

	var mv MigrationVersion
	if err := c.sendRequest(req, &mv); err != nil {
		return MigrationVersion{}, err
	}

	return mv, nil
}

// SetMigrationVersion sets the latest migration version and status for an App.
// It is assumed that the JWT token pair acquired earlier is now in ctx, under the key 'cerberusTokenPair'.
func (c *Client) SetMigrationVersion(ctx context.Context, version MigrationVersion) error {
	jwtTokenPair := ctx.Value("cerberusTokenPair")
	if jwtTokenPair == nil {
		return fmt.Errorf("no token")
	}

	payloadBuf := new(bytes.Buffer)
	err := json.NewEncoder(payloadBuf).Encode(version)
	if err != nil {
		return err
	}

	req, err := http.NewRequest(
		"POST",
		fmt.Sprintf("%s/migrationversion", c.baseURL),
		payloadBuf)
	if err != nil {
		return err
	}

	req = req.WithContext(ctx)

	req.Header.Set("Authorization", "Bearer "+jwtTokenPair.(TokenPair).AccessToken)

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

// Execute runs a series of commands in the given order within one transaction
// in the context of the account and user specified.
func (c *Client) Execute(accountId, userId string, commands ...Command) error {

	exec := executeCommands{
		AccountId: accountId,
		UserId:    userId,
		Commands:  commands,
	}

	payloadBuf := new(bytes.Buffer)
	err := json.NewEncoder(payloadBuf).Encode(exec)
	if err != nil {
		return err
	}

	req, err := http.NewRequest(
		"POST",
		fmt.Sprintf("%s/commands", c.baseURL),
		payloadBuf)
	if err != nil {
		return err
	}

	req.SetBasicAuth(c.apiKey, c.apiSecret)

	if err := c.sendRequest(req, nil); err != nil {
		return err
	}

	return nil
}

// ExecuteWithCtx runs a series of commands in the given order within one transaction
// in the context of the account and user specified.
// It assumes there's a User token in ctx under "cerberusTokenPair"
func (c *Client) ExecuteWithCtx(ctx context.Context, commands ...Command) error {
	jwtTokenPair := ctx.Value("cerberusTokenPair")
	if jwtTokenPair == nil {
		return fmt.Errorf("no token")
	}

	exec := executeCommands{
		Commands: commands,
	}

	payloadBuf := new(bytes.Buffer)
	err := json.NewEncoder(payloadBuf).Encode(exec)
	if err != nil {
		return err
	}

	req, err := http.NewRequest(
		"POST",
		fmt.Sprintf("%s/commands", c.baseURL),
		payloadBuf)
	if err != nil {
		return err
	}

	req = req.WithContext(ctx)

	req.Header.Set("Authorization", "Bearer "+jwtTokenPair.(TokenPair).AccessToken)

	if err := c.sendRequest(req, nil); err != nil {
		return err
	}

	return nil
}

// CreateAccountCmd returns a Command that creates a new Account for an App with accountId as identifier.
func (c *Client) CreateAccountCmd(accountId string) Command {
	return Command{
		CreateAccount: &createAccountCmd{
			AccountId: accountId,
		},
	}
}

// CreateResourceCmd returns a Command that creates a new Resource on an Account, which belongs to an App.
// The resource is identified by resourceId, has an optional parent parentId and is of resourceType.
func (c *Client) CreateResourceCmd(resourceId, parentId, resourceType string) Command {
	return Command{
		CreateResource: &createResourceCmd{
			ResourceId:   resourceId,
			ParentId:     parentId,
			ResourceType: resourceType,
		},
	}
}

// CreateUserCmd returns a Command that creates a new User on an Account, which belongs to an App.
// The User is identified by userId, has a userName which is unique for the Account
// and a displayName for display.
func (c *Client) CreateUserCmd(userId, userName, displayName string) Command {
	return Command{
		CreateUser: &createUserCmd{
			UserId:      userId,
			UserName:    userName,
			DisplayName: displayName,
		},
	}
}

// CreateRoleCmd returns a Command that creates a new Role on an Account, which belongs to an App.
// A Role is identified by a roleId (which will be auto-generated), and has a roleName unique to the Account.
func (c *Client) CreateRoleCmd(name string) Command {
	return Command{
		CreateRole: &createRoleCmd{
			Name:         name,
			IsSuperAdmin: false,
		},
	}
}

// CreateRoleWithIdCmd returns a Command that creates a new Role on an Account, which belongs to an App.
// A Role is identified by a roleId, and has a roleName unique to the Account.
func (c *Client) CreateRoleWithIdCmd(roleId, name string) Command {
	return Command{
		CreateRole: &createRoleCmd{
			RoleId:       roleId,
			Name:         name,
			IsSuperAdmin: false,
		},
	}
}

// CreateSuperRoleCmd returns a Command that creates a new 'super' Role on an Account, which belongs to an App.
// A Role is identified by a roleId, and has a roleName unique to the Account.
// A super Role has access to all resources regardless of permissions. There can only be one super role per Account.
func (c *Client) CreateSuperRoleCmd(name string) Command {
	return Command{
		CreateRole: &createRoleCmd{
			Name:         name,
			IsSuperAdmin: true,
		},
	}
}

// CreateSuperRoleWithIdCmd returns a Command that creates a new 'super' Role on an Account, which belongs to an App.
// A Role is identified by a roleId (which will be auto-generated), and has a roleName unique to the Account.
// A super Role has access to all resources regardless of permissions. There can only be one super role per Account.
func (c *Client) CreateSuperRoleWithIdCmd(roleId, name string) Command {
	return Command{
		CreateRole: &createRoleCmd{
			RoleId:       roleId,
			Name:         name,
			IsSuperAdmin: true,
		},
	}
}

// AssignRoleCmd returns a Command that assigns the User identified by userId to the Role identified by roleName.
func (c *Client) AssignRoleCmd(roleName, userId string) Command {
	return Command{
		AssignRole: &assignRoleCmd{
			RoleName: roleName,
			UserId:   userId,
		},
	}
}

// UnassignRoleCmd returns a Command that removes the User identified by userId from the Role identified by roleName.
func (c *Client) UnassignRoleCmd(roleName, userId string) Command {
	return Command{
		UnassignRole: &unassignRoleCmd{
			RoleName: roleName,
			UserId:   userId,
		},
	}
}

// CreateUserPermissionCmd returns a Command that grants permission to some user with userId
// to the Resource identified by resourceId by granting a list of Policies which specifies which Actions are allowed.
func (c *Client) CreateUserPermissionCmd(userId, resourceId string, policies []string) Command {
	return Command{
		CreateUserPermission: &createUserPermissionCmd{
			UserId:     userId,
			ResourceId: resourceId,
			Policies:   policies,
		},
	}
}

// CreateRolePermissionCmd returns a Command that grants permission to some role with roleName
// to the Resource identified by resourceId by granting a list of Policies which specifies which Actions are allowed.
func (c *Client) CreateRolePermissionCmd(roleName, resourceId string, policies []string) Command {
	return Command{
		CreateRolePermission: &createRolePermissionCmd{
			RoleName:   roleName,
			ResourceId: resourceId,
			Policies:   policies,
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

	defer func() {
		_ = res.Body.Close()
	}()

	if res.StatusCode < http.StatusOK || res.StatusCode >= http.StatusBadRequest {
		var errRes string
		if err = json.NewDecoder(res.Body).Decode(&errRes); err == nil {
			return errors.New(errRes)
		}

		return fmt.Errorf("unknown error, status code: %d", res.StatusCode)
	}

	if v != nil {
		if err = json.NewDecoder(res.Body).Decode(&v); err != nil {
			return err
		}
	}

	return nil
}
