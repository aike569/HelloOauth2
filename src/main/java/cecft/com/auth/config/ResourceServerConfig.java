package cecft.com.auth.config;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableResourceServer;
import org.springframework.security.oauth2.config.annotation.web.configuration.ResourceServerConfigurerAdapter;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import cecft.com.auth.handler.MyAuthenticationFailureHandler;
import cecft.com.auth.handler.MyAuthenticationSucessHandler;
import cecft.com.auth.smscode.config.SmsAuthenticationConfig;
import cecft.com.auth.smscode.filter.SmsCodeFilter;

//@Configuration
@Order(2)
@EnableResourceServer // 配置资源服务器
public class ResourceServerConfig extends ResourceServerConfigurerAdapter{

	@Autowired
    private MyAuthenticationSucessHandler authenticationSucessHandler;
	
    @Autowired
    private MyAuthenticationFailureHandler authenticationFailureHandler;
    
    @Autowired
    private SmsCodeFilter smsCodeFilter;
    
    @Autowired
    private SmsAuthenticationConfig smsAuthenticationConfig;
    
    @Override
    public void configure(HttpSecurity http) throws Exception {
    	http.addFilterBefore(smsCodeFilter, UsernamePasswordAuthenticationFilter.class) // 添加短信验证码校验过滤器
    		.formLogin() // 表单登录
		        .loginProcessingUrl("/login") // 处理表单登录 URL
		        .successHandler(authenticationSucessHandler) // 处理登录成功
		        .failureHandler(authenticationFailureHandler) // 处理登录失败
		    .and()
		        .authorizeRequests() // 授权配置
		        .antMatchers("/code/sms").permitAll() //允许通过
		        .anyRequest()  // 所有请求
		        .authenticated() // 都需要认证
		    .and()
		        .csrf().disable()
		    .apply(smsAuthenticationConfig) // 将短信验证码认证配置加到 Spring Security 中
		    ;
    }
    
    
    
}
