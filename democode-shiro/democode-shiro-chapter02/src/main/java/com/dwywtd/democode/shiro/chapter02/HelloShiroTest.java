package com.dwywtd.democode.shiro.chapter02;

import org.apache.shiro.SecurityUtils;
import org.apache.shiro.authc.AuthenticationException;
import org.apache.shiro.authc.UsernamePasswordToken;
import org.apache.shiro.config.IniSecurityManagerFactory;
import org.apache.shiro.mgt.SecurityManager;
import org.apache.shiro.subject.SimplePrincipalCollection;
import org.apache.shiro.subject.Subject;
import org.junit.Assert;
import org.junit.Test;

public class HelloShiroTest {

    @Test
    public void testHello() {
        // 1、创建SecurityManager工厂，通过Ini配置文件初始化SecurityManager
        IniSecurityManagerFactory securityManagerFactory = new IniSecurityManagerFactory("classpath:shiro.ini");

        // 2、得到SecurityManager实例 并绑定给SecurityUtils
        SecurityManager securityManager = securityManagerFactory.getInstance();
        SecurityUtils.setSecurityManager(securityManager);

        // 3、得到Subject及创建用户名/密码身份验证Token（即用户身份/凭证
        Subject subject = SecurityUtils.getSubject();
        UsernamePasswordToken token = new UsernamePasswordToken("zhang", "123");

        try {
            // 4、登录，即身份验证
            subject.login(token);
        } catch (AuthenticationException e) {
            // 5、身份验证失败
            System.out.println("登陆失败！");
        }

        Assert.assertTrue(subject.isAuthenticated()); // 断言用户已经登录

        //6、退出
        subject.logout();
    }


    @Test
    public void testSingleRealm() {
        // 1、创建SecurityManager工厂，通过Ini配置文件初始化SecurityManager
        IniSecurityManagerFactory securityManagerFactory = new IniSecurityManagerFactory("classpath:shiro-realm.ini");

        // 2、得到SecurityManager实例 并绑定给SecurityUtils
        SecurityManager securityManager = securityManagerFactory.getInstance();
        SecurityUtils.setSecurityManager(securityManager);

        // 3、得到Subject及创建用户名/密码身份验证Token（即用户身份/凭证
        Subject subject = SecurityUtils.getSubject();
        UsernamePasswordToken token = new UsernamePasswordToken("zhang", "123");

        try {
            // 4、登录，即身份验证
            subject.login(token);
        } catch (AuthenticationException e) {
            System.out.println(e.getMessage());
            // 5、身份验证失败
            System.out.println("登陆失败！");
        }

        Assert.assertTrue(subject.isAuthenticated()); // 断言用户已经登录

        //6、退出
        subject.logout();
    }

    @Test
    public void testMultiRealm() {
        // 1、创建SecurityManager工厂，通过Ini配置文件初始化SecurityManager
        IniSecurityManagerFactory securityManagerFactory = new IniSecurityManagerFactory("classpath:shiro-multi-realm.ini");

        // 2、得到SecurityManager实例 并绑定给SecurityUtils
        SecurityManager securityManager = securityManagerFactory.getInstance();
        SecurityUtils.setSecurityManager(securityManager);

        // 3、得到Subject及创建用户名/密码身份验证Token（即用户身份/凭证
        Subject subject = SecurityUtils.getSubject();
        UsernamePasswordToken token = new UsernamePasswordToken("wang", "123");

        try {
            // 4、登录，即身份验证
            subject.login(token);
        } catch (AuthenticationException e) {
            System.out.println(e.getMessage());
            // 5、身份验证失败
            System.out.println("登陆失败！");
        }

        Assert.assertTrue(subject.isAuthenticated()); // 断言用户已经登录

        //6、退出
        subject.logout();
    }


    @Test
    public void testJdbcRealm() {
        // 1、创建SecurityManager工厂，通过Ini配置文件初始化SecurityManager
        IniSecurityManagerFactory securityManagerFactory = new IniSecurityManagerFactory("classpath:shiro-jdbc-realm.ini");

        // 2、得到SecurityManager实例 并绑定给SecurityUtils
        SecurityManager securityManager = securityManagerFactory.getInstance();
        SecurityUtils.setSecurityManager(securityManager);

        // 3、得到Subject及创建用户名/密码身份验证Token（即用户身份/凭证
        Subject subject = SecurityUtils.getSubject();
        UsernamePasswordToken token = new UsernamePasswordToken("zhang", "123");

        try {
            // 4、登录，即身份验证
            subject.login(token);
        } catch (AuthenticationException e) {
            System.out.println(e.getMessage());
            // 5、身份验证失败
            System.out.println("登陆失败！");
        }

        Assert.assertTrue(subject.isAuthenticated()); // 断言用户已经登录
        System.out.println("登陆成功！");

        //6、退出
        subject.logout();
    }

    @Test
    public void testAllSuccessfulStrategyWithSuccess() {
        // 1、创建SecurityManager工厂，通过Ini配置文件初始化SecurityManager
        IniSecurityManagerFactory securityManagerFactory = new IniSecurityManagerFactory("classpath:shiro-authenticator-all-success.ini");

        // 2、得到SecurityManager实例 并绑定给SecurityUtils
        SecurityManager securityManager = securityManagerFactory.getInstance();
        SecurityUtils.setSecurityManager(securityManager);

        // 3、得到Subject及创建用户名/密码身份验证Token（即用户身份/凭证
        Subject subject = SecurityUtils.getSubject();
        UsernamePasswordToken token = new UsernamePasswordToken("zhang", "123");

        try {
            // 4、登录，即身份验证
            subject.login(token);
        } catch (AuthenticationException e) {
            System.out.println(e.getMessage());
            // 5、身份验证失败
            System.out.println("登陆失败！");
        }

        Assert.assertTrue(subject.isAuthenticated()); // 断言用户已经登录
        System.out.println("登陆成功！");

        SimplePrincipalCollection principals = (SimplePrincipalCollection) subject.getPrincipals();
        for (String realmName : principals.getRealmNames()) {
            System.out.println("realmName:" + realmName);
            System.out.println("principals:" + principals.fromRealm(realmName));
        }

        //6、退出
        subject.logout();
    }


}
