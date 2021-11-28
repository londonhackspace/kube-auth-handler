package main

import (
	"encoding/json"
	"github.com/go-redis/redis/v8"
	"github.com/gorilla/mux"
	"github.com/londonhackspace/kube-auth-handler/common"
	"github.com/londonhackspace/kube-auth-handler/common/auth"
	"github.com/rs/zerolog/log"
	"io/ioutil"
	authentication "k8s.io/api/authentication/v1"
	"net/http"
	"os"
	"strconv"
)

var authenticator auth.Auth
var sessionstore auth.SessionStore

func handleGetToken(w http.ResponseWriter, r *http.Request) {
	body, err := ioutil.ReadAll(r.Body)
	if err != nil {
		log.Err(err).Msg("Error reading body")
		w.WriteHeader(500)
		return
	}

	var query common.LoginRequest
	err = json.Unmarshal(body, &query)
	if err != nil {
		log.Err(err).Msg("Error unmarshalling request")
		w.WriteHeader(500)
		return
	}

	resp := common.LoginResponse{
		Success: false,
		Token:   "",
	}

	user, err := authenticator.AuthenticateUser(query.Username, query.Password)
	if err == nil {
		resp.Success = true
		log.Info().Str("username", query.Username).
			Int("uid", user.Uid).
			Msg("User authenticated")
		resp.Token = sessionstore.AddUser(user)
	} else {
		log.Err(err).
			Str("username", query.Username).Msg("Error authenticating user")
	}

	data, err := json.Marshal(resp)
	if err != nil {
		log.Err(err).Msg("Error marshalling response")
		w.WriteHeader(500)
		return
	}

	w.Write(data)
}

func handleCheckToken(w http.ResponseWriter, r *http.Request) {
	body, err := ioutil.ReadAll(r.Body)
	if err != nil {
		log.Err(err).Msg("Error reading body")
		w.WriteHeader(500)
		return
	}

	var tokenReview authentication.TokenReview
	err = json.Unmarshal(body, &tokenReview)
	if err != nil {
		log.Err(err).Msg("Error unmarshalling body")
		w.WriteHeader(400)
		return
	}

	log.Info().Msg("got token review")

	response := authentication.TokenReview {
		TypeMeta: tokenReview.TypeMeta,
		Status: authentication.TokenReviewStatus{
			Authenticated: false,
			Error: "Not Authenticated",
		},
	}

	user := sessionstore.GetUser(tokenReview.Spec.Token)
	if user != nil {
		response.Status.Authenticated = true
		response.Status.User.UID = strconv.FormatInt(int64(user.Uid), 10)
		response.Status.User.Groups = user.Groups
		response.Status.User.Username = user.Username
		response.Status.Error = ""

		log.Info().Str("username", user.Username).
			Msg("User Token Validated")
	}

	resultData, err := json.Marshal(response)
	if err != nil {
		log.Err(err).Msg("error serialising response")
		w.WriteHeader(500)
		return
	}

	w.Write(resultData)
}

func main() {

	redisConn := redis.NewClient(&redis.Options{
		Addr: os.Getenv("REDIS_SERVER"),
		Password: "",
		DB: 0,
	})
	defer redisConn.Close()

	sessionstore = auth.CreateRedisSessionStore(redisConn)
	
	ldapConfig := auth.LDAPConfig{
		BindDN:  os.Getenv("LDAP_BINDDN"),
		BindPW:  os.Getenv("LDAP_BINDPW"),
		Server:  os.Getenv("LDAP_SERVER"),
		UserOU:  os.Getenv("LDAP_USEROU"),
		GroupOU: os.Getenv("LDAP_GROUPOU"),
		BaseDN:  os.Getenv("LDAP_BASEDN"),
		LdapSkipTLSVerify: os.Getenv("LDAP_SKIPTLSVERIFY") == "yes",
	}

	if len(ldapConfig.UserOU) == 0 {
		ldapConfig.UserOU = "ou=Users"
	}

	if len(ldapConfig.GroupOU) == 0 {
		ldapConfig.GroupOU = "ou=Groups"
	}

	if ldapConfig.LdapSkipTLSVerify {
		log.Warn().Msg("LDAP TLS Verification Skipped")
	}

	authenticator = auth.CreateLDAPAuth(ldapConfig)
	
	rtr := mux.NewRouter()

	rtr.Path("/getToken").Methods(http.MethodPost).HandlerFunc(handleGetToken)
	rtr.Path("/verify").Methods(http.MethodPost).HandlerFunc(handleCheckToken)


	listen, ok := os.LookupEnv("LISTEN_ADDR")

	if !ok {
		listen = "localhost:8080"
	}

	log.Info().Msg("Listening on " + listen)
	http.ListenAndServe(listen, rtr)
}
