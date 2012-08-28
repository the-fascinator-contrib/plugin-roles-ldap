# LDAP Roles Plugin for The Fascinator #

This plugin allows The Fascinator platform to query an LDAP server to determine user roles.

## Configuration ##

`"ldap": {  
        "baseURL": "ldap://localhost:389",  
             "baseDN": "ou=people,o=Sample org,c=AU",  
             "idAttribute": "uid",  
             "objectClassRoleMap": [  
                {  
                    "objectClass": "adminOrgClass"  
                    "roles": ["admin","registered"]   
                },  
                {  
                    "objectClass": "registeredOrgClass"  
                    "roles": ["registered"]                    
                }  
            ]  
       }
` 
 
**baseURL**

The URL of the LDAP server.

**baseDN**

The base Distinguished Name to search under.

**idAttribute**

The name of the attribute for which the username will be searched under. This will be appended to the end of the baseDN when querying the LDAP server.
Using the example configuration above the query string will be:

ou=people,o=Sample org,c=AU,uid=specifiedUsername

**objectClassRoleMap**

Maps objectClass values from the LDAP server to roles within The Fascinator. One objectClass value may map to many The Fascinator roles.

