package com.ibm.websphere.client.factory.jdbc;

import javax.naming.RefAddr;
import java.util.Properties;

//this is a stub class required by WebSphere2 ldap handler
public class PropertiesRefAddr extends RefAddr {
    private static final long serialVersionUID = 288055886942232156L;
    private Properties props;

    public PropertiesRefAddr(String addrType, Properties props) {
        super(addrType);
        this.props = props;
    }

    public Object getContent() {
        return this.props;
    }
}