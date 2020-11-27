package cecft.com.auth.smscode.provider;

import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.InternalAuthenticationServiceException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.UserDetails;

import cecft.com.auth.service.MyUserDetailService;
import cecft.com.auth.smscode.token.SmsAuthenticationToken;

public class SmsAuthenticationProvider implements AuthenticationProvider{
	
	//在创建完SmsAuthenticationFilter后，我们需要创建一个支持处理该类型Token的类，即SmsAuthenticationProvider，该类需要实现
	//AuthenticationProvider的两个抽象方法：
	
	private MyUserDetailService userDetailService;

	
	// authenticate方法用于编写具体的身份认证逻辑
	// 在authenticate方法中，我们从SmsAuthenticationToken中取出了手机号信息，并调用了UserDetailService的loadUserByUsername方法。\
	// 该方法在用户名密码类型的认证中，主要逻辑是通过用户名查询用户信息，如果存在该用户并且密码一致则认证成功；
	// 而在短信验证码认证的过程中，该方法需要通过手机号去查询用户，如果存在该用户则认证通过。
	// 认证通过后接着调用SmsAuthenticationToken的SmsAuthenticationToken(Object principal, Collection<? extends GrantedAuthority> authorities)构造函数构造一个认证通过的Token，包含了用户信息和用户权限。
	// 你可能会问，为什么这一步没有进行短信验证码的校验呢？实际上短信验证码的校验是在SmsAuthenticationFilter之前完成的，即只有当短信验证码正确以后才开始走认证的流程。所以接下来我们需要定一个过滤器来校验短信验证码的正确性。
	@Override
	public Authentication authenticate(Authentication authentication) throws AuthenticationException {
		
		SmsAuthenticationToken authenticationToken = (SmsAuthenticationToken) authentication;
        UserDetails userDetails = userDetailService.loadUserByUsername((String) authenticationToken.getPrincipal());

        if (userDetails == null)
            throw new InternalAuthenticationServiceException("未找到与该手机号对应的用户");

        SmsAuthenticationToken authenticationResult = new SmsAuthenticationToken(userDetails, userDetails.getAuthorities());

        authenticationResult.setDetails(authenticationToken.getDetails());

        return authenticationResult;
        
	}

	// supports方法指定了支持处理的Token类型为SmsAuthenticationToken
	@Override
	public boolean supports(Class<?> authentication) {
		// isAssignableFrom 判定此 Class 对象所表示的类或接口与指定的 Class 参数所表示的类或接口是否相同，或是否是其超类或超接口。
		// 如果是则返回 true；否则返回 false
		return SmsAuthenticationToken.class.isAssignableFrom(authentication);
	}
	
	public MyUserDetailService getUserDetailService() {
        return userDetailService;
    }

    public void setUserDetailService(MyUserDetailService userDetailService) {
        this.userDetailService = userDetailService;
    }

}
