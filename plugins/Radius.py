#
#   Copyright (c) 2018 Balabit
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to
# deal in the Software without restriction, including without limitation the
# rights to use, copy, modify, merge, publish, distribute, sublicense, and/or
# sell copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in
# all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.  IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
# FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS
# IN THE SOFTWARE.
#
from psmlapi.plugin.mfa import MFACommunicationError, MFAAuthenticationFailure, MFAServiceUnreachable, MFAClient
from pyrad.client import Client, Timeout
from pyrad.dictionary import Dictionary
from pyrad.packet import AuthPacket, AccessReject, AccessAccept, md5_constructor
from socket import error as socket_error
import os
import logging
import ldap

RADIUS_DICTIONARY = os.path.join(os.path.dirname(__file__), "dictionary")


class RadiusClient(MFAClient):

    def __init__(self, server, port, secret, auth_type, conn_retries, conn_timeout):
        self._server = server
        self._port = port
        self._secret = secret
        self._auth_type = auth_type
        self._conn_retries = conn_retries
        self._conn_timeout = conn_timeout
        self._log = logging.getLogger(__name__)

    def do_authentication(self, user, passcode=""):

        radcli = Client(server=self._server,
                        authport=self._port,
                        secret=self._secret,
                        dict=Dictionary(RADIUS_DICTIONARY))
        radcli.retries = self._conn_retries
        radcli.timeout = self._conn_timeout

	l = ldap.initialize("ldap://192.168.56.101")
	try:
		l.simple_bind_s("svc_balabit@internal.neteas", "Welcome123")
		ldap_result = l.search("dc=internal,dc=neteas", ldap.SCOPE_SUBTREE, "(&(objectClass=group)(cn=BALABIT_MFA))", None)
		res_type, data = l.result(ldap_result, 0)
		user1 = user[1:]
		a = str(data[0][1]['member'])
		if user1 in a:
			ldap_result = l.search("dc=internal,dc=neteas", ldap.SCOPE_SUBTREE, "(&(objectClass=user)(cn=" + user + "))" , None)
			res_type, data = l.result(ldap_result, 0)
			user = data[0][1]['userPrincipalName'][0]
			radpkt = self._createAuthenticationPacket(client=radcli, radius_user=user, radius_pass=passcode)
    			print user
		else:
			return True
	except Exception, error:
		return True
        #radpkt = self._createAuthenticationPacket(client=radcli, radius_user=user, radius_pass=passcode)

        try:
            self._log.debug("Sending authentication packet to RADIUS server %s:%d", self._server, self._port)
            radrep = radcli.SendPacket(radpkt)
        except Timeout as ex:
            self._log.error("Network timeout while talking to RADIUS server %s:%d, %s",
                            self._server, self._port, str(ex))
            raise MFAServiceUnreachable("Network timeout while talking to RADIUS server")
        except socket_error as ex:
            self._log.error("Network error while talking to RADIUS server %s:%d, %s", self._server, self._port, str(ex))
            raise MFAServiceUnreachable("Network error while talking to RADIUS server")

        self._log.debug("RADIUS return code: '%s'", radrep.code)

        if radrep.code == AccessAccept:
            self._log.info("RADIUS authentication was successful")
            return True
        elif radrep.code == AccessReject:
            self._log.error("RADIUS authentication was rejected")
            raise MFAAuthenticationFailure("RADIUS authentication was rejected")
        else:
            self._log.error("Unknown RADIUS reply from %s:%d, reply=%d", self._server, self._port, radrep.code)
            raise MFACommunicationError("Unexpected RADIUS response code")

    def _createAuthenticationPacket(self, client, radius_user, radius_pass):
        req = _AuthPacketWithChapSupport(secret=self._secret, dict=client.dict)

        req["Service-Type"] = "Login-User"
        req["User-Name"] = radius_user
        if self._auth_type == 'pap':
            req["User-Password"] = req.PwCrypt(radius_pass)
        elif self._auth_type == 'chap':
            req["CHAP-Password"] = req.ChapDigest(radius_pass)
        else:
            raise MFACommunicationError("Unknown auth_type: %s", self._auth_type)
        return req

    def otp_authenticate(self, user, passcode):
        return self.do_authentication(user, passcode)

    def push_authenticate(self, user):
        return self.do_authentication(user)


class _AuthPacketWithChapSupport(AuthPacket):

    def ChapDigest(self, password):
        if self.authenticator is None:
            self.authenticator = self.CreateAuthenticator()

        id_str = chr(self.id)
        md5 = md5_constructor()
        md5.update(id_str)
        md5.update(password)
        md5.update(self.authenticator)
        digest = md5.digest()

        return id_str + digest
