// Copyright 2012 Jiang Bian (borderj@gmail.com). All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Email: borderj@gmail.com
// Blog: http://wifihack.net/

// Sina WeiBo oauth2 Login, Base on goauth2 lib
package main

import (
	"code.google.com/p/goauth2/oauth"
	//"crypto/tls"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"strings"
	"text/template"
)

var notAuthenticatedTemplate = template.Must(template.New("").Parse(`
<html><body>
You have currently not given permissions to access your data.
<form action="/authorize" method="POST"><input type="submit" value="Ok, authorize this app with my id"/></form>
</form>
</body></html>
`))

var userInfoTemplate = template.Must(template.New("").Parse(`
<html><body>
Please Input Your Sina User Name:
<form action="/getuserinfo" method="POST">
<input type="input" name="userinfo" value="b0rder"/>
<input type="submit" value="Get User Info"/>
</form>
</body></html>
`))

// variables used during oauth protocol flow of authentication
var (
	code  = ""
	token = ""
)

var oauthCfg = &oauth.Config{
	ClientId:     "20479142",
	ClientSecret: "1fa5bdfd1a901a885c3ec9d1aceef701",
	AuthURL:      "https://api.weibo.com/oauth2/authorize",
	TokenURL:     "https://api.weibo.com/oauth2/access_token",
	RedirectURL:  "http://127.0.0.1:8080/oauth2callback",
	Scope:        "",
}

const profileInfoURL = "https://api.weibo.com/2/users/show.json"
const port = ":8080"

func main() {
	http.HandleFunc("/", handleRoot)
	http.HandleFunc("/authorize", handleAuthorize)

	http.HandleFunc("/oauth2callback", handleOAuth2Callback)
	http.HandleFunc("/getuserinfo", getUserInfo)

	log.Println("Listen On" + port)
	http.ListenAndServe(port, nil)
}

func handleRoot(w http.ResponseWriter, r *http.Request) {
	notAuthenticatedTemplate.Execute(w, nil)
}

// Start the authorization process
func handleAuthorize(w http.ResponseWriter, r *http.Request) {
	//Get the Google URL which shows the Authentication page to the user
	url := oauthCfg.AuthCodeURL("")

	log.Printf("URL: %v\n", url)
	//redirect user to that page
	http.Redirect(w, r, url, http.StatusFound)
}

// Function that handles the callback from the Google server
func handleOAuth2Callback(w http.ResponseWriter, r *http.Request) {
	//Get the code from the response
	code := r.FormValue("code")

	t := &oauth.Transport{oauth.Config: oauthCfg}

	// Exchange the received code for a token
	tok, _ := t.Exchange(code)

	{
		tokenCache := oauth.CacheFile("./request.token")

		err := tokenCache.PutToken(tok)
		if err != nil {
			log.Fatal("Cache write:", err)
		}
		log.Printf("Token is cached in %v\n", tokenCache)
		token = tok.AccessToken
	}

	/*
	   // Skip TLS Verify
	   t.Transport = &http.Transport{
	       TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	   }
	*/

	userInfoTemplate.Execute(w, nil)

}

// Get Sina User Info
func getUserInfo(w http.ResponseWriter, r *http.Request) {
	if token == "" {
		log.Println("Get Access Token Error")
		http.Redirect(w, r, "/", http.StatusFound)
		return
	}
	user := r.FormValue("userinfo")
	if strings.TrimSpace(user) == "" {
		w.Write([]byte("Please Input User Name"))
		return
	}

	url := fmt.Sprintf("%s?screen_name=%s&access_token=%s", profileInfoURL, user, token)
	log.Println("url: " + url)

	resp, err := http.Get(url)
	defer resp.Body.Close()

	if err != nil {
		log.Fatal("Request Error:", err)
	}

	body, _ := ioutil.ReadAll(resp.Body)
	w.Write(body)
}
