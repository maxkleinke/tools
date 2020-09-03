#!/bin/python3
# ldap3 client to query the windows ldap service
# Author: alwayslucky (@maxkleinke)

import ldap3
import traceback
import getopt
import sys
import json


def usage():
    print()
    print("ldap3 client")
    print("-------------------------------------------------------------")
    print("Usage:")
    print("info     - get server information")
    print("cs       - change the search base for queries")
    print("elevate  - elevate the connection to an authorized connection")
    print("modify   - modify user data (elevated connection necessary)")
    print("whoami   - get current user information")
    print("query    - query the ldap3 service")
    print("exit     - i wont say what it does")
    print("-------------------------------------------------------------")
    print()


def init(host, port, ssl):
    server = ldap3.Server(host, get_info = ldap3.ALL, port = port, use_ssl = ssl)
    connection = ldap3.Connection(server)
    connection.bind()
    
    return connection, server


def set_defaultNamingContext(serverinfo):
    serverinfo = json.loads(serverinfo)
    serverinfo = serverinfo["raw"]
    namingcontext = str(serverinfo["defaultNamingContext"]).strip("[']")
    return namingcontext


def print_serverinfo(server):
    print(server.info)


def whoami(connection):
    print(connection.extend.standard.who_am_i())


def elevate_connection(server, domainstring, password, autobind):
    try:
        connection = ldap3.Connection(server, domainstring, password, auto_bind = autobind)
        if(connection.bind()):
            print("Connection elevated!")
            print("current user: {}".format(connection.extend.standard.who_am_i()))
            user = str(connection.extend.standard.who_am_i()).split(":", 1)[1]
            return connection, user
        else:
            print("Elevating connection failed, check credentials")
    except:
        print("Elevating connection went wrong:")
        traceback.print_exc()
    finally:
        connection = ldap3.Connection(server)
        return connection, None


def query(connection, namingContext, objclass='*', scope='SUBTREE', attributes='*'):

    if objclass == '': objclass = '*'
    if scope == '': scope = 'SUBTREE'
    if attributes == '': attributes = '*'

    try:
        if connection.search(search_base = namingContext, search_filter='(&(objectClass={}))'.format(objclass), search_scope = scope, attributes = attributes):
            print(connection.entries)
        else:
            print("Search failed, do you have permissions?")
    except:
        print("Somenthing went wrong:")
        traceback.print_exc()


def modify(connection, namingContext, user, jsonKey, jsonValue):
    try:
        connection.modify('{},{}'.format(user, namingContext), {jsonKey: [(ldap3.MODIFY_REPLACE, [jsonValue])]})
        print("{}: {} successfully modified!".format(user, jsonKey))
    except:
        print("Modifying {} went wrong. Is your connection elevated?".format(jsonKey))
        traceback.print_exc()


def main(host, port, ssl):
    connection,server = init(host, port, ssl)
    defaultNamingContext = set_defaultNamingContext(server.info.to_json())
    searchBase = defaultNamingContext
    user = None
    usage()
    print("Connected to {} with naming context {} as user {}.".format(host, defaultNamingContext, user))

    while True:
        line = input("> ")
        
        if line == "q" or line == "exit" or line == "quit":
            break
        elif line == "usage":
            usage()
        elif line == "info":
            print_serverinfo(server)
        elif line == "cs":
            print("Changing the search base.")
            print("Current: {}".format(searchBase))
            searchBase = input("New naming context: ")
        elif line == "elevate":
            uid = input("uid: ")
            ou = input("ou: ")
            domainstring = "uid={},ou={},{}".format(uid, ou, namingContext)
            password = input("password: ")
            connection, user = elevate_connection(server, domainstring, password, True)
        elif line == "modify":
            jsonKey = input("Key: ")
            jsonValue = input("Value: ")
            modify(connection, namingContext, user, jsonKey, jsonValue)
        elif line == "whoami":
            whoami(connection)
        elif line == "query":
            objclass = input("ObjectClass (Default: *): ")
            scope = input("Scope (Default: SUBTREE): ")
            attributes = input("Attributes (Default: *): ")

            query(connection, searchBase, objclass, scope, attributes)
        else:
            print("unrecognized option: "+line)
            print("try: usage")


if __name__ == "__main__":
    optlist, args = getopt.getopt(sys.argv[1:], 'h:p:', ["ssl"])
    ssl = False

    for o, a in optlist:
        if o == "-h":
            host = str(a)
        elif o == "-p":
            if a == '':
                port = 389
                continue
            port = int(a)
        elif o == "--ssl":
            ssl = True
        else:
            assert False, "unhandled option"
    
    main(host, port, ssl)


