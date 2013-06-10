# LDAP Roles Plugin for The Fascinator #

This plugin allows The Fascinator platform to query an LDAP server to determine user roles.

## Configuration ##

	"ldap": {  
		"baseURL": "ldap://localhost:389",  
		"baseDN": "ou=people,o=Sample org,c=AU",  
        "ldapSecurityPrincipal": "cn=JohnDoe,ou=Some Account,dc=sample,dc=edu,dc=au",
        "ldapSecurityCredentials": "<principal-password>",
		"idAttribute": "uid",  
		"filterPrefix": "uniquemember=",
		"filterSuffix": ",ou=people,dc=adelaide,dc=edu,dc=au",
		"ldapRoleAttribute": "cn",
		"ldapRoleMap": [
			{
				"ldapRoleAttrValue": "TFREG"
				"roles": ["registered"]
			},
			{
				"ldapRoleAttrValue": "TFADM"
				"roles": ["admin"]
			}
		]
	}

**baseURL**

The URL of the LDAP server.

**baseDN**

The base Distinguished Name to search under.

** ldapSecurityPrincipal **

The Security Principal to use for non-anonymous binding

** ldapSecurityCredentials **

Credentials for Security Principal

**idAttribute**

The name of the attribute for which the username will be searched under. This will be appended to the end of the baseDN when querying the LDAP server.
Using the example configuration above the query string will be:

	ou=people,o=Sample org,c=AU,uid=specifiedUsername

**filterPrefix**

The prefix for the LDAP search filter that is used to determine LDAP role membership. This field is optional.

**filterSuffix**

The suffix for the LDAP search filter that is used to determine LDAP role membership. This field is optional.

**ldapRoleAttribute**

The name of the LDAP attribute that contains the role values. If omitted, defaults to "objectClass".

**ldapRoleMap**

Maps role attribute values from LDAP to roles within The Fascinator. One `ldapRoleAttrValue` value may map to many The Fascinator `roles`.
