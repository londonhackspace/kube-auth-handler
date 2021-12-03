package auth

import (
	"crypto/tls"
	"fmt"
	ldapv3 "github.com/go-ldap/ldap/v3"
	"strconv"
)

type LDAPConfig struct {
	BindDN string
	BindPW string
	Server string

	UserOU  string
	GroupOU string
	BaseDN  string

	LdapSkipTLSVerify bool
}

type LDAPAuth struct {
	config LDAPConfig
}

func CreateLDAPAuth(config LDAPConfig) Auth {
	return &LDAPAuth{
		config: config,
	}
}

func (ldap *LDAPAuth) getConnection() (*ldapv3.Conn, error) {
	cfg := tls.Config{InsecureSkipVerify: ldap.config.LdapSkipTLSVerify}
	return ldapv3.DialURL(ldap.config.Server, ldapv3.DialWithTLSConfig(&cfg))
}

func (ldap *LDAPAuth) makeLDAPQuery(req *ldapv3.SearchRequest, c *ldapv3.Conn) (*ldapv3.SearchResult, error) {
	var ourCon *ldapv3.Conn
	if c == nil {
		var err error
		ourCon, err = ldap.getConnection()
		if err != nil {
			return nil, ServerError
		}
		defer ourCon.Close()
	} else {
		ourCon = c
	}

	err := ourCon.Bind(ldap.config.BindDN, ldap.config.BindPW)
	if err != nil {
		return nil, ServerError
	}

	return ourCon.Search(req)
}

func (ldap *LDAPAuth) getGroups(username string, c *ldapv3.Conn) []string {
	query := ldapv3.NewSearchRequest(ldap.config.GroupOU+","+ldap.config.BaseDN,
		ldapv3.ScopeWholeSubtree, ldapv3.NeverDerefAliases,
		0, 0, false,
		fmt.Sprintf("(&(objectClass=posixGroup)(memberUid=%s))", ldapv3.EscapeFilter(username)),
		[]string{"cn", "gidNumber"}, nil)
	res, err := ldap.makeLDAPQuery(query, c)
	if err != nil {
		//log.Err(err).Msg("Error getting groups for user")
		return []string{}
	}

	var groups []string
	for _, entry := range res.Entries {
		groups = append(groups, entry.GetAttributeValue("cn"))
	}
	return groups
}

func (ldap *LDAPAuth) AuthenticateUser(username string, password string) (*User, error) {
	c, err := ldap.getConnection()
	if err != nil {
		return nil, ServerError
	}
	// search for the user
	query := ldapv3.NewSearchRequest(ldap.config.UserOU+","+ldap.config.BaseDN,
		ldapv3.ScopeSingleLevel, ldapv3.NeverDerefAliases,
		0, 0, false,
		fmt.Sprintf("(&(objectClass=organizationalPerson)(uid=%s))", ldapv3.EscapeFilter(username)),
		[]string{"dn", "givenName", "uidNumber"}, nil)

	res, err := ldap.makeLDAPQuery(query, c)
	if err != nil {
		//log.Err(err).Msg("Error searching LDAP server")
		return nil, ServerError
	}

	if len(res.Entries) != 1 {
		return nil, AuthError
	}

	err = c.Bind(res.Entries[0].DN, password)
	if err != nil {
		/*log.Err(err).
		Str("username", username).
		Msg("Invalid Password")*/
		return nil, AuthError
	}

	uid, err := strconv.ParseInt(res.Entries[0].GetAttributeValue("uidNumber"), 10, 32)

	return &User{
		Uid:      int(uid),
		Name:     res.Entries[0].GetAttributeValue("givenName"),
		Username: username,
		Groups:   ldap.getGroups(username, c),
	}, nil
}
