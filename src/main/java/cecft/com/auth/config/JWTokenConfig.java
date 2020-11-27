package cecft.com.auth.config;


import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.oauth2.provider.token.TokenEnhancer;
import org.springframework.security.oauth2.provider.token.TokenStore;
import org.springframework.security.oauth2.provider.token.store.JwtAccessTokenConverter;
import org.springframework.security.oauth2.provider.token.store.JwtTokenStore;

import cecft.com.auth.enhancer.JWTokenEnhancer;

@Configuration
public class JWTokenConfig{
	
	// 使用JWT替换默认的令牌（默认令牌使用UUID生成）只需要指定TokenStore为JwtTokenStore即可。
	
	// 如果想在JWT中添加一些额外的信息，我们需要实现TokenEnhancer（Token增强器）

	@Bean
    public TokenStore jwtTokenStore() {
        return new JwtTokenStore(jwtAccessTokenConverter());
    }

	
	/**
	 * JwtAccessTokenConverter：TokenEnhancer的子类，帮助程序在JWT编码的令牌值和OAuth身份验证信息之间进行转换（在两个方向上），
	 *    同时充当TokenEnhancer授予令牌的时间。
	 *    自定义的JwtAccessTokenConverter（把自己设置的jwt签名加入accessTokenConverter中）
	 * @return
	 */
    @Bean
    public JwtAccessTokenConverter jwtAccessTokenConverter() {
        JwtAccessTokenConverter accessTokenConverter = new JwtAccessTokenConverter();
        accessTokenConverter.setSigningKey("test_key"); // 签名密钥
        return accessTokenConverter;
    }
    
    /**
     * TokenEnhancer：在AuthorizationServerTokenServices 实现存储访问令牌之前增强访问令牌的策略。
     * @return
     */
    // 定义TokenEnhancer实现类
    @Bean
    public TokenEnhancer tokenEnhancer() {
        return new JWTokenEnhancer();
    }
    
}
