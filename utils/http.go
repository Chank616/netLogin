package utils

import (
	"io"
	"net/http"
	"net/url"
)

func Get(addr string, param map[string]string) string {
	params := url.Values{}
	Url, _ := url.Parse(addr)
	for k, v := range param {
		params.Set(k, v)
	}
	//如果参数中有中文参数,这个方法会进行URLEncode
	Url.RawQuery = params.Encode()
	urlPath := Url.String()
	resp, err := http.Get(urlPath)
	if err != nil {
		return "超时无法访问"
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	return string(body)
}
