package com.feihong.ldap;

import com.feihong.ldap.utils.Config;

import javax.naming.NamingException;
import java.io.IOException;
import java.rmi.AlreadyBoundException;

public class Starter {
    public static void main(String[] args) throws IOException, AlreadyBoundException, NamingException {
        Config.applyCmdArgs(args);
        LdapServer.start();
        HTTPServer.start();
        RMIServer.start();
    }
}
