package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"github.com/londonhackspace/kube-auth-handler/common"
	"golang.org/x/term"
	"io/ioutil"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	clientauth "k8s.io/client-go/pkg/apis/clientauthentication/v1"
	"net/http"
	"os"
	"time"
)

func getCachedToken(clusername string) *cacheconfig {
	homedir, err := os.UserHomeDir()
	if err != nil {
		fmt.Fprintln(os.Stderr, "Error getting home directory:", err.Error())
		return nil
	}
	f, err := os.Open(homedir + string(os.PathSeparator) + ".kube" + string(os.PathSeparator) + clusername + "_cache")
	if err != nil {
		// probably just that the file doesn't exist, so don't bother logging
		return nil
	}
	defer f.Close()

	bytes, err := ioutil.ReadAll(f)
	if err != nil {
		fmt.Fprintln(os.Stderr, "Error getting cached config:", err.Error())
		return nil
	}

	var cfg cacheconfig

	err = json.Unmarshal(bytes, &cfg)
	if err != nil {
		fmt.Fprintln(os.Stderr, "Error getting cached config:", err.Error())
		return nil
	}

	return &cfg
}

func setCachedToken(clusername string, cfg *cacheconfig) {
	homedir, err := os.UserHomeDir()
	if err != nil {
		fmt.Fprintln(os.Stderr, "Error getting home directory:", err.Error())
		return
	}
	f, err := os.Create(homedir + string(os.PathSeparator) + ".kube" + string(os.PathSeparator) + clusername + "_cache")
	if err != nil {
		fmt.Fprintln(os.Stderr, "Error opening cache file:", err.Error())
		return
	}
	defer f.Close()

	data, err := json.Marshal(cfg)
	if err != nil {
		fmt.Fprintln(os.Stderr, "Error marshalling config to JSON:", err.Error())
		return
	}

	f.Write(data)
}

func tryAuth(authserver string, username string, password string) string {
	query := common.LoginRequest{
		Username: username,
		Password: password,
	}
	data, err := json.Marshal(&query)
	if err != nil {
		fmt.Println("Error forming query:", err.Error())
		os.Exit(1)
	}

	resp, err := http.DefaultClient.Post(authserver, "text/json", bytes.NewReader(data))
	if err != nil {
		fmt.Println("Error contacting server", err.Error())
		os.Exit(1)
	}

	respReader, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		fmt.Println("Error reading response:", err.Error())
		os.Exit(1)
	}

	loginResp := common.LoginResponse{}
	err = json.Unmarshal(respReader, &loginResp)
	if err != nil {
		fmt.Println("Error unmarshalling response:", err.Error())
		os.Exit(1)
	}

	if !loginResp.Success {
		fmt.Println("Error logging in")
		os.Exit(1)
	}

	return loginResp.Token
}

func main() {
	// first, get some environment variables
	cluster := os.Getenv("AUTH_CLUSTER")
	authServer := os.Getenv("AUTH_URL")
	user := os.Getenv("USER")

	if len(cluster) == 0 {
		fmt.Fprintln(os.Stderr, "AUTH_CLUSTER empty. Exiting.")
		os.Exit(1)
	}

	// this might get better results on Windows
	if len(user) == 0 {
		user = os.Getenv("USERNAME")
	}

	cached := getCachedToken(cluster)

	var token string
	var expiration metav1.Time

	if cached != nil {
		user = cached.Username
		if cached.TokenExpiry > time.Now().Unix() {
			token = cached.Token
			expiration = metav1.NewTime(time.Unix(cached.TokenExpiry, 0))
		}
	}

	if len(token) == 0 {
		if len(authServer) == 0 {
			fmt.Fprintln(os.Stderr, "AUTH_URL empty. Exiting.")
			os.Exit(1)
		}

		fmt.Fprintln(os.Stderr, "kubectl LDAP login helper")
		fmt.Fprintln(os.Stderr, "Logging into", cluster)
		fmt.Fprintln(os.Stderr, "Press enter for defaults")

		fmt.Fprintf(os.Stderr, "Username (%s): ", user)
		var givenUsername string
		// ignore any errors here - we will just check the string
		fmt.Scanln(&givenUsername)

		if len(givenUsername) == 0 {
			givenUsername = user
		} else {
			// set the user so the cache gets updated properly
			user = givenUsername
		}

		if len(givenUsername) == 0 {
			fmt.Fprintln(os.Stderr, "Error getting username")
			os.Exit(1)
		}

		fmt.Fprint(os.Stderr, "Password: ")
		data, err := term.ReadPassword(int(os.Stdin.Fd()))
		if err != nil {
			fmt.Fprintln(os.Stderr, "Error getting password")
			os.Exit(1)
		}

		token = tryAuth(authServer, givenUsername, string(data))
		expiration = metav1.NewTime(time.Now().Add(time.Hour * 6))
	}

	output := clientauth.ExecCredential{
		TypeMeta: metav1.TypeMeta{
			Kind:       "ExecCredential",
			APIVersion: "client.authentication.k8s.io/v1",
		},
		Status: &clientauth.ExecCredentialStatus{
			Token:               token,
			ExpirationTimestamp: &expiration,
		},
		Spec: clientauth.ExecCredentialSpec{},
	}

	data, err := json.Marshal(output)
	if err != nil {
		fmt.Fprintln(os.Stderr, "Error serialising result")
		os.Exit(1)
	}

	cached = &cacheconfig{
		Username:    user,
		Token:       token,
		TokenExpiry: expiration.Unix(),
	}
	setCachedToken(cluster, cached)

	// This is the important part: we output the JSON to stdout
	fmt.Println(string(data))
}
