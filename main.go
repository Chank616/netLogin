package main

import (
	"fmt"
	"netLogin/utils"
	"os"
	"regexp"
	"strings"
	"time"
	"github.com/go-toast/toast"
)

func main() {
	content, _ := os.ReadFile("config.ncwu")
	config := string(content)
	info:= strings.Split(config, ",")
	username := info[0]
	password := info[1]

	// ip
	params := make(map[string]string)
	now := fmt.Sprintf("%d", time.Now().Unix()*100)
	params["callback"] = "jQuery112406336369815771166_" + now
	params["_"] = now
	resp := utils.Get("http://192.168.0.170/cgi-bin/rad_user_info", params)
	if resp == "超时无法访问" {
		notification := toast.Notification{
			AppID:   "NetLoginNCWU",
			Title:   "华北水利水电大学校园网认证状态😘",
			Message: "连接失败喵😭！可能是：\n1.校园网繁忙😃\n2.未设置自动连接😃\n3.看东西代理没关😃\n关注永雏塔菲喵，关注永雏塔菲谢谢喵！",
		}
		notification.Push()
		return
	}
	compileRegex := regexp.MustCompile(`online_ip":"(.*?)",`)
	matchArr := compileRegex.FindStringSubmatch(resp)
	ip := matchArr[len(matchArr)-1]

	// challenge
	params["ip"] = ip
	params["username"] = username
	resp = utils.Get("http://192.168.0.170/cgi-bin/get_challenge", params)
	compileRegex = regexp.MustCompile(`challenge":"(.*?)",`)
	matchArr = compileRegex.FindStringSubmatch(resp)
	challenge := matchArr[len(matchArr)-1]

	// password参数
	passwordEncrypt := utils.Hmac(challenge, password)

	// info参数
	i := fmt.Sprintf(`{"username":"%s","password":"%s","ip":"%s","acid":"2","enc_ver":"srun_bx1"}`, username, password, ip)
	infoEncrypt := "{SRBX1}" + utils.Base64Encode(utils.GetXencode(i, challenge))

	// chksum参数
	token := challenge
	chkstr := token + username
	chkstr += token + passwordEncrypt
	chkstr += token + "2"
	chkstr += token + ip
	chkstr += token + "200"
	chkstr += token + "1"
	chkstr += token + infoEncrypt
	chksumEncrypt := utils.Sha1(chkstr)

	// 发送登录包
	params["action"] = "login"
	params["password"] = "{MD5}" + passwordEncrypt
	params["ac_id"] = "2"
	params["chksum"] = chksumEncrypt
	params["info"] = infoEncrypt
	params["n"] = "200"
	params["type"] = "1"
	params["os"] = "Windows 10"
	params["name"] = "Windows"
	params["double_stack"] = "0"
	resp = utils.Get("http://192.168.0.170/cgi-bin/srun_portal", params)
	print(resp)
	// 显示通知
	compileRegex = regexp.MustCompile(`error_msg":"(.*?)",`)
	matchArr = compileRegex.FindStringSubmatch(resp)
	error_msg := matchArr[len(matchArr)-1]
	if error_msg != "" {
		notification := toast.Notification{
			AppID:   "NetLoginNCWU",
			Title:   "华北水利水电大学校园网认证状态😘",
			Message: "连接失败喵😭！\n" + "状态码: " + error_msg + "\n关注永雏塔菲喵，关注永雏塔菲谢谢喵！",
		}
		notification.Push()
		return
	}
	compileRegex = regexp.MustCompile(`suc_msg":"(.*?)",`)
	matchArr = compileRegex.FindStringSubmatch(resp)
	suc_msg := matchArr[len(matchArr)-1]
	notification := toast.Notification{
		AppID:   "NetLoginNCWU",
		Title:   "华北水利水电大学校园网认证状态😘",
		Message: "连接成功喵😎！\n" + "状态码: " + suc_msg + "\n关注永雏塔菲喵，关注永雏塔菲谢谢喵！",
	}
	notification.Push()

}
