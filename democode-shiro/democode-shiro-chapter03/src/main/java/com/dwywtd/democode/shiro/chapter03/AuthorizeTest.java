package com.dwywtd.democode.shiro.chapter03;

import org.apache.shiro.SecurityUtils;
import org.apache.shiro.authc.AuthenticationException;
import org.apache.shiro.authc.UsernamePasswordToken;
import org.apache.shiro.authz.UnauthorizedException;
import org.apache.shiro.config.IniSecurityManagerFactory;
import org.apache.shiro.mgt.SecurityManager;
import org.apache.shiro.subject.Subject;
import org.junit.Assert;
import org.junit.Test;

import java.util.Arrays;
import java.util.function.Consumer;

public class AuthorizeTest {


    private void login(String iniPath, String username, String password, Consumer<Subject> consumer) {
        // 1、创建SecurityManager工厂，通过Ini配置文件初始化SecurityManager
        IniSecurityManagerFactory securityManagerFactory = new IniSecurityManagerFactory(iniPath);

        // 2、得到SecurityManager实例 并绑定给SecurityUtils
        SecurityManager securityManager = securityManagerFactory.getInstance();
        SecurityUtils.setSecurityManager(securityManager);

        // 3、得到Subject及创建用户名/密码身份验证Token（即用户身份/凭证
        Subject subject = SecurityUtils.getSubject();
        UsernamePasswordToken token = new UsernamePasswordToken(username, password);

        try {
            // 4、登录，即身份验证
            subject.login(token);
        } catch (AuthenticationException e) {
            // 5、身份验证失败
            System.out.println("登陆失败！");
        }

        // 登陆后进一步验证
        consumer.accept(subject);

        //6、退出
        subject.logout();
    }


    @Test
    public void testRole() {
        login("classpath:shiro-role.ini", "zhang", "123", subject -> {
            //判断拥有角色：role1
            Assert.assertTrue(subject.hasRole("role1"));
            //判断拥有角色：role2
            Assert.assertTrue(subject.hasRole("role2"));
            //判断拥有角色：role1 and role2
            Assert.assertTrue(subject.hasAllRoles(Arrays.asList("role1", "role2")));

            //判断拥有角色：role1 and role2 and !role3
            boolean[] result = subject.hasRoles(Arrays.asList("role1", "role2", "role3"));
            Assert.assertTrue(Arrays.toString(result), result[0]);
            Assert.assertTrue(Arrays.toString(result), result[1]);
            Assert.assertFalse(result[2]);

        });
    }

    @Test(expected = UnauthorizedException.class)
    public void testRoleWithCheck() {
        login("classpath:shiro-role.ini", "zhang", "123", subject -> {
            //判断拥有角色：role1
            subject.checkRole("role1");
            //判断拥有角色：role2
            subject.checkRole("role2");
            //判断拥有角色：role1 and role2
            subject.checkRoles("role1", "role2");

            // 判断拥有角色：role1 and role2 and !role3
            subject.checkRoles("role1", "role2", "role3");
        });
    }

    @Test
    public void testPermission() {
        login("classpath:shiro-permission.ini", "zhang", "123", subject -> {
            //判断拥有权限：user:create
            Assert.assertTrue(subject.isPermitted("user:create"));
            //判断拥有权限：user:update
            Assert.assertTrue(subject.isPermitted("user:update"));
            //判断拥有权限：user:delete
            Assert.assertTrue(subject.isPermitted("user:delete"));
            //判断不拥有权限：user:view
            Assert.assertFalse(subject.isPermitted("user:view"));

            //判断拥有权限：user:create and user:delete
            Assert.assertTrue(subject.isPermittedAll("user:create", "user:update", "user:delete"));

            // 判断拥有权限：user:create and user:delete and !user:view
            Assert.assertFalse(subject.isPermittedAll("user:create", "user:update", "user:delete", "user:view"));

            boolean[] permitted = subject.isPermitted("user:create", "user:update", "user:delete", "user:view");
            System.out.println(Arrays.toString(permitted));
            Assert.assertTrue(permitted[0]);
            Assert.assertTrue(permitted[1]);
            Assert.assertTrue(permitted[2]);
            Assert.assertFalse(permitted[3]);
        });
    }

    @Test(expected = UnauthorizedException.class)
    public void testPermissionWithCheck() {
        login("classpath:shiro-permission.ini", "zhang", "123", subject -> {
            //判断拥有权限：user:create
            subject.checkPermission("user:create");
            //判断拥有权限：user:update
            subject.checkPermission("user:update");
            //判断拥有权限：user:delete
            subject.checkPermission("user:delete");
            //判断不拥有权限：user:view
//            subject.checkPermission("user:view");

            //判断拥有权限：user:create and user:delete
            subject.checkPermissions("user:create", "user:update", "user:delete");

            System.out.println("判断拥有权限：user:create and user:delete and !user:view");
            // 判断拥有权限：user:create and user:delete and !user:view
            subject.checkPermissions("user:create", "user:update", "user:delete", "user:view");
        });
    }
}
