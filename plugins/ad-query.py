import ldap
import json
con=ldap.initialize('ldap://192.168.56.101')

def main(user):
    
    for x in user:
        user_dn = "<username>"
        password = "<password>"
        criteria = "(&(objectClass=user)(sAMAccountName="+x+"))"
        attributes = ["userPrincipalName","memberOf"]
        try:
            con.simple_bind_s(user_dn, password)
            res =con.search_s("DC=internal,DC=neteas", ldap.SCOPE_SUBTREE, criteria, attributes)
            for a in res:
                
                if 'memberOf' in a[1]:
                    b = a[1]['memberOf']
                    for p in b:
                        if 'BALABIT_MFA' in p:
                            print "Usuario faz parte do MFA"
                            if 'userPrincipalName' in a[1]:
                                b = a[1]
                                c = b['userPrincipalName'][0]
                                print c
                                attributes = ["memberOf"]
                            else:
                                pass
                    
        except Exception, error:
            print error

if __name__ == "__main__":
    user = ["t3435625"]
    main(user)