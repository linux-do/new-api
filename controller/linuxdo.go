package controller

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"time"

	"one-api/common"
	"one-api/model"

	"github.com/gin-contrib/sessions"
	"github.com/gin-gonic/gin"
)

type LinuxDoOAuthResponse struct {
	AccessToken string `json:"access_token"`
	Scope       string `json:"scope"`
	TokenType   string `json:"token_type"`
}

type LinuxDoUser struct {
	ID         int               `json:"id"`
	Username   string            `json:"username"`
	Name       string            `json:"name"`
	Active     bool              `json:"active"`
	TrustLevel common.TrustLevel `json:"trust_level"`
	Silenced   bool              `json:"silenced"`
}

type UserHandler interface {
	Do() (*model.User, error)
}

type existingUserHandler struct {
	*LinuxDoUser
}

func (h existingUserHandler) Do() (*model.User, error) {
	user := &model.User{
		LinuxDoId: strconv.Itoa(h.ID),
	}

	err := user.FillUserByLinuxDoId()
	if err != nil {
		return nil, err
	}

	trustLevelStr := h.TrustLevel.String()
	if user.Group != trustLevelStr {
		user.Group = trustLevelStr
		err = user.Update(false)
		if err != nil {
			return nil, fmt.Errorf("更新用户组失败: %w", err)
		}
	}

	return user, err
}

type newUserHandler struct {
	ginCtx      *gin.Context
	linuxDoUser *LinuxDoUser
}

func (h newUserHandler) Do() (*model.User, error) {
	if !common.RegisterEnabled {
		return nil, errors.New("管理员关闭了新用户注册")
	}

	affCode := h.ginCtx.Query("aff")

	user := new(model.User)
	user.LinuxDoId = strconv.Itoa(h.linuxDoUser.ID)
	user.InviterId, _ = model.GetUserIdByAffCode(affCode)
	user.Username = "linuxdo_" + strconv.Itoa(model.GetMaxUserId()+1)
	if h.linuxDoUser.Name != "" {
		user.DisplayName = h.linuxDoUser.Name
	} else {
		user.DisplayName = h.linuxDoUser.Username
	}
	user.Role = common.RoleCommonUser
	user.Status = common.UserStatusEnabled
	user.Group = h.linuxDoUser.TrustLevel.String()
	if err := user.Insert(user.InviterId); err != nil {
		return nil, fmt.Errorf("创建用户失败: %w", err)
	}

	return user, nil
}

func getLinuxDoUserInfoByCode(code string) (*LinuxDoUser, error) {
	if code == "" {
		return nil, errors.New("无效的参数")
	}
	auth := base64.StdEncoding.EncodeToString([]byte(common.LinuxDoClientId + ":" + common.LinuxDoClientSecret))
	form := url.Values{
		"grant_type": {"authorization_code"},
		"code":       {code},
	}
	req, err := http.NewRequest("POST", "https://connect.linux.do/oauth2/token", bytes.NewBufferString(form.Encode()))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Authorization", "Basic "+auth)
	req.Header.Set("Accept", "application/json")
	client := http.Client{
		Timeout: 5 * time.Second,
	}
	res, err := client.Do(req)
	if err != nil {
		common.SysLog(err.Error())
		return nil, errors.New("无法连接至 LINUX DO 服务器，请稍后重试！")
	}
	defer res.Body.Close()
	var oAuthResponse LinuxDoOAuthResponse
	err = json.NewDecoder(res.Body).Decode(&oAuthResponse)
	if err != nil {
		return nil, err
	}
	req, err = http.NewRequest("GET", "https://connect.linux.do/api/user", nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", oAuthResponse.AccessToken))
	res2, err := client.Do(req)
	if err != nil {
		common.SysLog(err.Error())
		return nil, errors.New("无法连接至 LINUX DO 服务器，请稍后重试！")
	}
	defer res2.Body.Close()
	var linuxdoUser LinuxDoUser
	err = json.NewDecoder(res2.Body).Decode(&linuxdoUser)
	if err != nil {
		return nil, err
	}
	if linuxdoUser.ID == 0 {
		return nil, errors.New("返回值非法，用户字段为空，请稍后重试！")
	}
	return &linuxdoUser, nil
}

func LinuxDoOAuth(c *gin.Context) {
	session := sessions.Default(c)
	state := c.Query("state")
	if state == "" || session.Get("oauth_state") == nil || state != session.Get("oauth_state").(string) {
		c.JSON(http.StatusForbidden, gin.H{
			"success": false,
			"message": "state is empty or not same",
		})
		return
	}
	username := session.Get("username")
	if username != nil {
		LinuxDoBind(c)
		return
	}

	if !common.LinuxDoOAuthEnabled {
		c.JSON(http.StatusOK, gin.H{
			"success": false,
			"message": "管理员未开启通过 LINUX DO 登录以及注册",
		})
		return
	}
	code := c.Query("code")
	linuxDoUser, err := getLinuxDoUserInfoByCode(code)
	if err != nil {
		c.JSON(http.StatusOK, gin.H{
			"success": false,
			"message": err.Error(),
		})
		return
	}

	var userHandler UserHandler
	if model.IsLinuxDoIdAlreadyTaken(strconv.Itoa(linuxDoUser.ID)) {
		userHandler = existingUserHandler{linuxDoUser}
	} else {
		userHandler = newUserHandler{c, linuxDoUser}
	}

	user, err := userHandler.Do()
	if err != nil {
		c.JSON(http.StatusOK, gin.H{
			"success": false,
			"message": err.Error(),
		})
		return
	}

	if user.Status != common.UserStatusEnabled {
		c.JSON(http.StatusOK, gin.H{
			"message": "用户已被封禁",
			"success": false,
		})
		return
	}

	setupLogin(user, c)
}

func LinuxDoBind(c *gin.Context) {
	if !common.LinuxDoOAuthEnabled {
		c.JSON(http.StatusOK, gin.H{
			"success": false,
			"message": "管理员未开启通过 LINUX DO 登录以及注册",
		})
		return
	}
	code := c.Query("code")
	linuxdoUser, err := getLinuxDoUserInfoByCode(code)
	if err != nil {
		c.JSON(http.StatusOK, gin.H{
			"success": false,
			"message": err.Error(),
		})
		return
	}
	user := model.User{
		LinuxDoId: strconv.Itoa(linuxdoUser.ID),
	}
	if model.IsLinuxDoIdAlreadyTaken(user.LinuxDoId) {
		c.JSON(http.StatusOK, gin.H{
			"success": false,
			"message": "该 LINUX DO 账户已被绑定",
		})
		return
	}
	session := sessions.Default(c)
	id := session.Get("id")
	// id := c.GetInt("id")  // critical bug!
	user.Id = id.(int)
	err = user.FillUserById()
	if err != nil {
		c.JSON(http.StatusOK, gin.H{
			"success": false,
			"message": err.Error(),
		})
		return
	}
	user.LinuxDoId = strconv.Itoa(linuxdoUser.ID)
	user.Group = linuxdoUser.TrustLevel.String()
	err = user.Update(false)
	if err != nil {
		c.JSON(http.StatusOK, gin.H{
			"success": false,
			"message": err.Error(),
		})
		return
	}
	c.JSON(http.StatusOK, gin.H{
		"success": true,
		"message": "bind",
	})
	return
}
