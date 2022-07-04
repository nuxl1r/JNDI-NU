package com.feihong.ldap.template;

public interface Template {
    void generate();
    byte[] getBytes();
    void cache();
    String getClassName();
}
