package controller

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/gin-contrib/sessions"
	"github.com/gin-gonic/gin"
	"net/http"
	"net/url"
	"one-api/common"
	"one-api/model"
	"strconv"
	"time"
)

type LinuxDoOAuthResponse struct {
	AccessToken string `json:"access_token"`
	Scope       string `json:"scope"`
	TokenType   string `json:"token_type"`
}

type LinuxDoUser struct {
	ID         int    `json:"id"`
	Username   string `json:"username"`
	Name       string `json:"name"`
	Active     bool   `json:"active"`
	TrustLevel int    `json:"trust_level"`
	Silenced   bool   `json:"silenced"`
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
		err := user.FillUserByLinuxDoId()
		if err != nil {
			c.JSON(http.StatusOK, gin.H{
				"success": false,
				"message": err.Error(),
			})
			return
		}
	} else {
		if common.RegisterEnabled {
			affCode := c.Query("aff")
			user.InviterId, _ = model.GetUserIdByAffCode(affCode)

			user.Username = "linuxdo_" + strconv.Itoa(model.GetMaxUserId()+1)
			if linuxdoUser.Name != "" {
				user.DisplayName = linuxdoUser.Name
			} else {
				user.DisplayName = linuxdoUser.Username
			}
			user.Role = common.RoleCommonUser
			user.Status = common.UserStatusEnabled
			user.LinuxTrustLevel = 0

			if err := user.Insert(user.InviterId); err != nil {
				c.JSON(http.StatusOK, gin.H{
					"success": false,
					"message": err.Error(),
				})
				return
			}
		} else {
			c.JSON(http.StatusOK, gin.H{
				"success": false,
				"message": "管理员关闭了新用户注册",
			})
			return
		}
	}
	// 获取旧的信任额度和新的信任额度
	OldTrustLevel := user.LinuxTrustLevel
	NewTrustLevel := linuxdoUser.TrustLevel
	if OldTrustLevel < NewTrustLevel {
		switch OldTrustLevel {
			case 1:
				user.Quota -= common.QuotaForLinuxDoLevel1
			case 2:
				user.Quota -= common.QuotaForLinuxDoLevel2
			case 3:
				user.Quota -= common.QuotaForLinuxDoLevel3
		}
		switch NewTrustLevel {
			case 1:
				user.Quota += common.QuotaForLinuxDoLevel1
			case 2:
				user.Quota += common.QuotaForLinuxDoLevel2
			case 3:
				user.Quota += common.QuotaForLinuxDoLevel3
			case 4:
				user.Quota += common.QuotaForLinuxDoLevel4
		}
		user.LinuxTrustLevel = NewTrustLevel
		user.RefeashTimeStamp = 0
		err = user.Update(false)
		if err != nil {
			c.JSON(http.StatusOK, gin.H{
				"success": false,
				"message": err.Error(),
			})
			return
		}
	}
	// 刷新用户的配额
	if common.AutomaticRefreshLinuxDoUserQuotaEnabled {
		TimeStamp := time.Now().Unix()
		if TimeStamp - user.RefeashTimeStamp > int64(common.LinuxDoUserQuotaRefreshInterval * 3600) {
			model.RefreshUserQuotaAndSave(user.Id, TimeStamp)
		}
	}


	if user.Status != common.UserStatusEnabled {
		c.JSON(http.StatusOK, gin.H{
			"message": "用户已被封禁",
			"success": false,
		})
		return
	}
	setupLogin(&user, c)
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
	user.LinuxTrustLevel = linuxdoUser.TrustLevel
	switch user.LinuxTrustLevel {
	case 1:
		user.Quota += common.QuotaForLinuxDoLevel1
	case 2:
		user.Quota += common.QuotaForLinuxDoLevel2
	case 3:
		user.Quota += common.QuotaForLinuxDoLevel3
	case 4:
		user.Quota += common.QuotaForLinuxDoLevel4
	}

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
