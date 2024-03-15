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
		//如果已经登录了，就查找用户信息填充到user中
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

			if err := user.Insert(user.InviterId); err != nil {
				c.JSON(http.StatusOK, gin.H{
					"success": false,
					"message": err.Error(),
				})
				return
			} else {
				// 添加调试信息：记录用户等级和相应的配额
				common.SysLog(fmt.Sprintf("Setting quota for user with trust level %d: %s", linuxdoUser.TrustLevel, user.Username))

				switch linuxdoUser.TrustLevel {
				case 1:
					model.IncreaseUserQuota(user.Id, common.QuotaForLinuxDoLevel1*500000)
					common.SysLog(fmt.Sprintf("User '%s' assigned quota: %d (Level 1)", user.Username, common.QuotaForLinuxDoLevel1))
				case 2:
					model.IncreaseUserQuota(user.Id, common.QuotaForLinuxDoLevel2*500000)
					common.SysLog(fmt.Sprintf("User '%s' assigned quota: %d (Level 2)", user.Username, common.QuotaForLinuxDoLevel2))
				case 3:
					model.IncreaseUserQuota(user.Id, common.QuotaForLinuxDoLevel3*500000)
					common.SysLog(fmt.Sprintf("User '%s' assigned quota: %d (Level 3)", user.Username, common.QuotaForLinuxDoLevel3))
				default:
					common.SysLog(fmt.Sprintf("WARNING: User '%s' has an unknown trust level: %d", user.Username, linuxdoUser.TrustLevel))
				}
			}
		} else {
			c.JSON(http.StatusOK, gin.H{
				"success": false,
				"message": "管理员关闭了新用户注册",
			})
			return
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
