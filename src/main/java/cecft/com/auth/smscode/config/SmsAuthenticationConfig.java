package cecft.com.auth.smscode.config;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.SecurityConfigurerAdapter;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.web.DefaultSecurityFilterChain;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import cecft.com.auth.service.MyUserDetailService;
import cecft.com.auth.smscode.filter.SmsAuthenticationFilter;
import cecft.com.auth.smscode.provider.SmsAuthenticationProvider;

@Configuration
public class SmsAuthenticationConfig extends SecurityConfigurerAdapter<DefaultSecurityFilterChain, HttpSecurity>{

	@Autowired
    private AuthenticationSuccessHandler authenticationSuccessHandler;

    @Autowired
    private AuthenticationFailureHandler authenticationFailureHandler;

    @Autowired
    private MyUserDetailService userDetailService;
    
    
    // 短信验证配置
    @Override
    public void configure(HttpSecurity http) throws Exception {
    	
    	// 在流程中第一步需要配置SmsAuthenticationFilter，分别设置了AuthenticationManager、AuthenticationSuccessHandler和
    	// AuthenticationFailureHandler属性。这些属性都是来自SmsAuthenticationFilter继承的AbstractAuthenticationProcessingFilter类中。
    	SmsAuthenticationFilter smsAuthenticationFilter = new SmsAuthenticationFilter();
        smsAuthenticationFilter.setAuthenticationManager(http.getSharedObject(AuthenticationManager.class));
        smsAuthenticationFilter.setAuthenticationSuccessHandler(authenticationSuccessHandler);
        smsAuthenticationFilter.setAuthenticationFailureHandler(authenticationFailureHandler);
    	
    	// 第二步配置SmsAuthenticationProvider，这一步只需要将我们自个的UserDetailService注入进来即可。
        SmsAuthenticationProvider smsAuthenticationProvider = new SmsAuthenticationProvider();
        smsAuthenticationProvider.setUserDetailService(userDetailService);
    	
    	// 最后调用HttpSecurity的authenticationProvider方法指定了AuthenticationProvider为SmsAuthenticationProvider，并将
        // SmsAuthenticationFilter过滤器添加到了UsernamePasswordAuthenticationFilter后面。
        http.authenticationProvider(smsAuthenticationProvider)
                .addFilterAfter(smsAuthenticationFilter, UsernamePasswordAuthenticationFilter.class);
        
        //到这里我们已经将短信验证码认证的各个组件组合起来了，最后一步需要做的是配置短信验证码校验过滤器，并且将短信验证码认证流程加入到Spring Security中。

    }
}
