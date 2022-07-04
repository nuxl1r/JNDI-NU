package com.feihong.ldap.controllers;

import com.feihong.ldap.exceptions.IncorrectParamsException;
import com.feihong.ldap.exceptions.UnSupportedActionTypeException;
import com.feihong.ldap.exceptions.UnSupportedGadgetTypeException;
import com.feihong.ldap.exceptions.UnSupportedPayloadTypeException;
import com.unboundid.ldap.listener.interceptor.InMemoryInterceptedSearchResult;

public interface LdapController {
    void sendResult(InMemoryInterceptedSearchResult result, String base) throws Exception;
    void process(String base) throws UnSupportedPayloadTypeException, IncorrectParamsException, UnSupportedGadgetTypeException, UnSupportedActionTypeException;
}
