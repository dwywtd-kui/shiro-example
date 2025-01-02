package com.dwywtd.democode.shiro.chapter02;

import org.apache.shiro.authc.*;
import org.apache.shiro.realm.Realm;

public class MyRealm3 implements Realm {
    @Override
    public String getName() {
        return "myRealm3";
    }

    @Override
    public boolean supports(AuthenticationToken authenticationToken) {
        return authenticationToken instanceof UsernamePasswordToken;
    }

    @Override
    public AuthenticationInfo getAuthenticationInfo(AuthenticationToken authenticationToken) throws AuthenticationException {
        System.out.println("myRealm3 验证用户名密码");
        String username = (String) authenticationToken.getPrincipal();
        String password = new String((char[]) authenticationToken.getCredentials());
        if (!"zhang".equals(username)) {
            throw new UnknownAccountException();
        } else if (!"123".equals(password)) {
            throw new IncorrectCredentialsException();
        }
        System.out.println("myRealm3 验证通过");
        return new SimpleAccount("zhang@163.com", "123", "myRealm3");
    }
}
