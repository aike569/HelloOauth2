package cecft.com.auth.config;

import java.util.ArrayList;
import java.util.List;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.BeanIds;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.config.annotation.configurers.ClientDetailsServiceConfigurer;
import org.springframework.security.oauth2.config.annotation.web.configuration.AuthorizationServerConfigurerAdapter;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableAuthorizationServer;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableResourceServer;
import org.springframework.security.oauth2.config.annotation.web.configuration.ResourceServerConfigurerAdapter;
import org.springframework.security.oauth2.config.annotation.web.configurers.AuthorizationServerEndpointsConfigurer;
import org.springframework.security.oauth2.provider.token.TokenEnhancer;
import org.springframework.security.oauth2.provider.token.TokenEnhancerChain;
import org.springframework.security.oauth2.provider.token.TokenStore;
import org.springframework.security.oauth2.provider.token.store.JwtAccessTokenConverter;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import cecft.com.auth.handler.MyAuthenticationFailureHandler;
import cecft.com.auth.handler.MyAuthenticationSucessHandler;
import cecft.com.auth.service.MyUserDetailService;
import cecft.com.auth.smscode.config.SmsAuthenticationConfig;
import cecft.com.auth.smscode.filter.SmsCodeFilter;

@Configuration
public class SecurityConfig extends WebSecurityConfigurerAdapter{

	@Bean(name = BeanIds.AUTHENTICATION_MANAGER)
    @Override
    public AuthenticationManager authenticationManagerBean() throws Exception {
        return super.authenticationManagerBean();
    }
	
	
	// 认证服务
	@Configuration
	@EnableAuthorizationServer
	protected static class AuthorizationServerConfiguration extends AuthorizationServerConfigurerAdapter {
		// 在同时定义了认证服务器和资源服务器后，再去使用授权码模式获取令牌可能会遇到 Full authentication is required to access this resource 的问题，
		// 这时候只要确保认证服务器先于资源服务器配置即可，比如在认证服务器的配置类上使用@Order(1)标注，在资源服务器的配置类上使用@Order(2)标注。

		// 定义MyUserDetailService需要用到的PasswordEncoder
		@Bean
	    public PasswordEncoder passwordEncoder() {
	        return new BCryptPasswordEncoder();
	    }
		
		@Autowired
	    private AuthenticationManager authenticationManager;
		
	    @Autowired
	    private MyUserDetailService userDetailService;
	    
//	    @Autowired
//	    private TokenStore redisTokenStore;
	    
	    @Autowired
	    private TokenStore jwtTokenStore;
	    
	    @Autowired
	    private JwtAccessTokenConverter jwtAccessTokenConverter;
	    
	    @Autowired
	    private TokenEnhancer tokenEnhancer;
	    
	    // 认证服务器在继承了AuthorizationServerConfigurerAdapter适配器后，需要重写configure(AuthorizationServerEndpointsConfigurer endpoints)方法，
	    // 指定 AuthenticationManager和UserDetailService。
	    
	    @Override
	    public void configure(AuthorizationServerEndpointsConfigurer endpoints) {
	    	
	    	
	    	// 在认证服务器里配置该 tokenEnhancer 增强器
	    	// 将TokenEnhancer和JwtAccessConverter加到一个enhancerChain中
	    	TokenEnhancerChain enhancerChain = new TokenEnhancerChain();
	        List<TokenEnhancer> enhancers = new ArrayList<>();
	        enhancers.add(tokenEnhancer);
	        enhancers.add(jwtAccessTokenConverter);
	        enhancerChain.setTokenEnhancers(enhancers); //将自定义Enhancer加入EnhancerChain的delegates数组中
	    	
	        endpoints
	                .authenticationManager(authenticationManager)
			        .tokenStore(jwtTokenStore)
			        .accessTokenConverter(jwtAccessTokenConverter)
	                .userDetailsService(userDetailService)
	                .tokenEnhancer(enhancerChain)
	                ;
	    }
	    
	    @Override
	    public void configure(ClientDetailsServiceConfigurer clients) throws Exception {
	    	clients.inMemory()
			        .withClient("test1") //（必须的）用来标识客户的Id
			        .secret(new BCryptPasswordEncoder().encode("test1111")) // （需要值得信任的客户端）客户端安全码，如果有的话。** (指定client_secret的时候需要进行加密处理)
			        .accessTokenValiditySeconds(60) // 有效时间 1小时
			        .refreshTokenValiditySeconds(864000) //10天
			        .scopes("all", "a", "b", "c")
			        .authorizedGrantTypes("password", "refresh_token")
			    .and()
			        .withClient("test2")
			        .secret(new BCryptPasswordEncoder().encode("test2222"))
			        .accessTokenValiditySeconds(7200);
	    }
	}
	
	// 资源服务
	@Configuration
	@EnableResourceServer
	@EnableGlobalMethodSecurity(securedEnabled = true, prePostEnabled = true, jsr250Enabled = true)
	protected static class ResourceServerConfiguration extends ResourceServerConfigurerAdapter {
		
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
	
}
