package main

import (
	"context"
	b64 "encoding/base64"
	"flag"
	"fmt"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/go-ldap/ldap/v3"
	"github.com/gorilla/handlers"
	"github.com/gorilla/mux"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
)

type favContextKey string

type Config struct {
	LdapURL       string
	LdapHost      string
	LdapPort      int64
	LdapUser      string
	LdapPassword  string
	UserSearchDN  string
	GroupSearchDN string
}

type Context struct {
	Config *Config
	User   string
	Groups []string
}

func goMiddleware(nginxCtx Context, next http.Handler) http.Handler {
	gom := favContextKey("gonginx")
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {

		if r.Header.Get("Authorization") == "" || r.Header["Authorization"][0] == "" {
			w.Header().Set("WWW-Authenticate", `Basic realm="genouest"`)
			http.Error(w, "access not allowed", http.StatusUnauthorized)
			return
		}
		auth := strings.SplitN(r.Header.Get("Authorization"), " ", -1)
		if auth[0] != "Basic" {
			http.Error(w, "invalid authorization header", http.StatusUnauthorized)
			return
		}
		if len(auth) != 2 {
			http.Error(w, "invalid authorization header", http.StatusUnauthorized)
			return
		}
		payload, _ := b64.StdEncoding.DecodeString(auth[1])
		pair := strings.SplitN(string(payload), ":", 2)

		if len(pair) != 2 {
			http.Error(w, "wrong authorization header", http.StatusUnauthorized)
			return
		}

		if nginxCtx.Config == nil {
			http.Error(w, "ldap not configured", http.StatusUnauthorized)
			return
		}

		nginxCtx.User = pair[0]

		groups, err := ldapAuth(pair[0], pair[1], nginxCtx.Config)
		if err != nil {
			http.Error(w, "authorization failed", http.StatusForbidden)
			return
		}

		nginxCtx.Groups = groups
		ctx := context.WithValue(r.Context(), gom, nginxCtx)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

func ldapAuth(username, password string, config *Config) ([]string, error) {
	if config.LdapHost == "" && config.LdapURL == ""  {
		return nil, fmt.Errorf("ldap not configured")
	}

	var conn *ldap.Conn
	var err error
	if config.LdapURL != "" {
		conn, err = ldap.DialURL(config.LdapURL)
	} else {
		conn, err = ldap.Dial("tcp", fmt.Sprintf("%s:%d", config.LdapHost, config.LdapPort))
	}
	if err != nil {
		log.Error().Err(err).Msg("[ldap] failed to contact server")
		return nil, err
	}
	defer conn.Close()

	if config.LdapUser != "" {
		err = conn.Bind(config.LdapUser, config.LdapPassword)
	} else {
		err = conn.UnauthenticatedBind("")
	}

	if err != nil {
		log.Error().Err(err).Msg("[ldap] bind error")
		return nil, err
	}

	filter := fmt.Sprintf("(&(objectClass=organizationalPerson)(uid=%s))", username)

	searchRequest := ldap.NewSearchRequest(
		config.UserSearchDN,
		ldap.ScopeWholeSubtree,
		ldap.NeverDerefAliases,
		0,
		0,
		false,
		filter,
		[]string{"uid"},
		nil,
	)
	searchResult, err := conn.Search(searchRequest)
	if err != nil {
		log.Error().Err(err).Msg("[ldap] user search error")
		return nil, err
	}

	if len(searchResult.Entries) != 1 {
		return nil, fmt.Errorf("user does not exist or too many entries returned")
	}

	err = conn.Bind(searchResult.Entries[0].DN, password)
	if err != nil {
		log.Debug().Err(err).Msg("[ldap] user bind error")
		return nil, err
	}
	log.Debug().Msgf("[ldap][user=%s] auth ok", username)

	// Get user groups
	userGroupFilter := fmt.Sprintf("(|(&(objectClass=posixGroup)(memberUid=%s)))", username)
	searchUserGroupRequest := ldap.NewSearchRequest(
		config.GroupSearchDN,
		ldap.ScopeWholeSubtree,
		ldap.NeverDerefAliases,
		0,
		0,
		false,
		userGroupFilter,
		[]string{"cn"},
		nil,
	)

	groups := make([]string, 0)
	searchUserGroupResult, err := conn.Search(searchUserGroupRequest)

	if err == nil {
		for _, m := range searchUserGroupResult.Entries {

			log.Debug().Msgf("[ldap][user=%s][group] %+v", username, m)
			for _, a := range m.Attributes {
				log.Debug().Msgf("[ldap][user=%s][group][attr] %+v", username, a)
				if a.Name == "cn" {
					for _, u := range a.Values {
						if u != "" {
							groups = append(groups, u)
						}
					}
				}

			}
		}
		log.Debug().Msgf("[ldap][user=%s][groups] %+v", username, groups)
	} else {
		log.Error().Err(err).Msgf("[ldap][user=%s][groups] failed to retrieve groups", username)
	}

	return groups, nil
}

var authHandler = func(w http.ResponseWriter, r *http.Request) {
}

var authGroupsHandler = func(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)

	groups := strings.Split(vars["groups"], "/")

	gom := favContextKey("gonginx")
	goctx := r.Context().Value(gom).(Context)
	if len(goctx.Groups) == 0 {
		http.Error(w, "ldap no group", http.StatusForbidden)
	}
	ok := false
	for _, g := range groups {
		if g == "" {
			continue
		}
		for _, ug := range goctx.Groups {
			if g == ug {
				ok = true
				break
			}
		}
	}

	if !ok {
		log.Debug().Msgf("user %s not in groups %+v: %+v", goctx.User, groups, goctx.Groups)
		http.Error(w, "user not in groups", http.StatusForbidden)
	}

}

func main() {
	zerolog.TimeFieldFormat = zerolog.TimeFormatUnix

	var debug bool
	var port int64

	flag.BoolVar(&debug, "debug", false, "set log debug")
	flag.Int64Var(&port, "port", 9999, "server port")
	flag.Parse()

	zerolog.SetGlobalLevel(zerolog.InfoLevel)
	if debug {
		zerolog.SetGlobalLevel(zerolog.DebugLevel)
	}

	r := mux.NewRouter()
	r.HandleFunc("/", authHandler).Methods("GET")
	r.HandleFunc("/{groups:.*}", authGroupsHandler).Methods("GET")
	loggedRouter := handlers.LoggingHandler(os.Stdout, r)

	if os.Getenv("PORT") != "" {
		port, _ = strconv.ParseInt(os.Getenv("PORT"), 10, 64)
	}

	ldapHost := os.Getenv("LDAP_HOST")
	var ldapPort int64 = 389
	if os.Getenv("LDAP_PORT") != "" {
		ldapPort, _ = strconv.ParseInt(os.Getenv("LDAP_PORT"), 10, 64)
	}

	ldapUserDN := os.Getenv("LDAP_USER_DN")   // "ou=People,dc=genouest,dc=org"
	ldapGroupDN := os.Getenv("LDAP_GROUP_DN") // "ou=Groups,dc=genouest,dc=org"

	cfg := Config{
		LdapURL:       os.Getenv("LDAP_URL"),
		LdapHost:      ldapHost,
		LdapPort:      ldapPort,
		LdapUser:      os.Getenv("LDAP_USER"),
		LdapPassword:  os.Getenv("LDAP_PASSWORD"),
		UserSearchDN:  ldapUserDN,
		GroupSearchDN: ldapGroupDN,
	}

	ctx := Context{
		Config: &cfg,
		Groups: nil,
	}

	ctxHandler := goMiddleware(ctx, loggedRouter)

	srv := &http.Server{
		Handler:      ctxHandler,
		Addr:         fmt.Sprintf("%s:%d", "0.0.0.0", port),
		WriteTimeout: 5 * time.Minute,
		ReadTimeout:  5 * time.Minute,
	}

	srv.ListenAndServe()

}
