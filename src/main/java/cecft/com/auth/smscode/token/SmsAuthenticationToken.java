package cecft.com.auth.smscode.token;


import java.util.Collection;

import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;

public class SmsAuthenticationToken extends AbstractAuthenticationToken{
	
	//查看UsernamePasswordAuthenticationToken的源码，将其复制出来重命名为SmsAuthenticationToken，并稍作修改，修改后的代码如下
	
	//SmsAuthenticationToken包含一个principal属性，从它的两个构造函数可以看出，在认证之前principal存的是手机号，认证之后存的是
	//用户信息。UsernamePasswordAuthenticationToken原来还包含一个credentials属性用于存放密码，这里不需要就去掉了。

	private static final long serialVersionUID = -2055457189757789771L;
	
	private final Object principal;

	public SmsAuthenticationToken(String mobile) {
		super(null);
		this.principal = mobile;
        setAuthenticated(false);
	}
	
	public SmsAuthenticationToken(Object principal, Collection<? extends GrantedAuthority> authorities) {
        super(authorities);
        this.principal = principal;
        super.setAuthenticated(true); // must use super, as we override
    }

	@Override
	public Object getCredentials() {
		return null;
	}

	@Override
	public Object getPrincipal() {
		return this.principal;
	}
	
	public void setAuthenticated(boolean isAuthenticated) throws IllegalArgumentException {
        if (isAuthenticated) {
            throw new IllegalArgumentException(
                    "Cannot set this token to trusted - use constructor which takes a GrantedAuthority list instead");
        }
        super.setAuthenticated(false);
    }
	
	@Override
    public void eraseCredentials() {
        super.eraseCredentials();
    }

}
