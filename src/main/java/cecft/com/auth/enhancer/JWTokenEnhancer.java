package cecft.com.auth.enhancer;

import java.util.HashMap;
import java.util.Map;

import org.springframework.security.oauth2.common.DefaultOAuth2AccessToken;
import org.springframework.security.oauth2.common.OAuth2AccessToken;
import org.springframework.security.oauth2.provider.OAuth2Authentication;
import org.springframework.security.oauth2.provider.token.TokenEnhancer;

/**
 * @author lmy
 * @Description 自定义 TokenEnhancer 实现类
 * @date 2020-10-22 10:10:28
 */
public class JWTokenEnhancer implements TokenEnhancer{
	
	// 如果想在JWT中添加一些额外的信息，我们需要实现TokenEnhancer（Token增强器）
	// 下面是自定义TokenEnhancer的代码（把附加信息加入oAuth2AccessToken中）：

	@Override
	public OAuth2AccessToken enhance(OAuth2AccessToken oAuth2AccessToken, OAuth2Authentication authentication) {
		Map<String, Object> info = new HashMap<>();
        info.put("message", "hello world");
        ((DefaultOAuth2AccessToken) oAuth2AccessToken).setAdditionalInformation(info);
        return oAuth2AccessToken;
	}
	
	
	/**
	 * 下面开始增强JWT令牌
	 *  Springsecurity默认生成Token的方法是DefaultTokenServices的createAccessToken方法:
	 */
//	该方法做了五件事：
//	1.使用UUID生成Token
//	2.判断Token是否过期，如果没过期，就把过期时间设为当前时间加1000s
//	3.设置刷新令牌
//	4.设置权限
//	5.判断是否有增强器，如果有就调用它的enhance方法
//	来源于 DefaultTokenServices类
//	private OAuth2AccessToken createAccessToken(OAuth2Authentication authentication, OAuth2RefreshToken refreshToken) {
//		DefaultOAuth2AccessToken token = new DefaultOAuth2AccessToken(UUID.randomUUID().toString());
//		int validitySeconds = getAccessTokenValiditySeconds(authentication.getOAuth2Request());
//		if (validitySeconds > 0) {
//			token.setExpiration(new Date(System.currentTimeMillis() + (validitySeconds * 1000L)));
//		}
//		token.setRefreshToken(refreshToken);
//		token.setScope(authentication.getOAuth2Request().getScope());
//
//		return accessTokenEnhancer != null ? accessTokenEnhancer.enhance(token, authentication) : token;
//	}
	


}
