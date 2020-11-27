package cecft.com.auth.smscode.filter;

import java.io.IOException;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.security.authentication.AuthenticationServiceException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.AbstractAuthenticationProcessingFilter;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.util.Assert;

import cecft.com.auth.smscode.token.SmsAuthenticationToken;

public class SmsAuthenticationFilter  extends AbstractAuthenticationProcessingFilter{
	
	//定义完SmsAuthenticationToken后，我们接着定义用于处理短信验证码登录请求的过滤器SmsAuthenticationFilter，同样的复制
	//UsernamePasswordAuthenticationFilter源码并稍作修改：
	
	public static final String MOBILE_KEY = "mobile";
	
	private String mobileParameter = MOBILE_KEY;
    private boolean postOnly = true;
    
    
    //构造函数中指定了当请求为/login/mobile，请求方法为POST的时候该过滤器生效。mobileParameter属性值为mobile，对应登录页面手机
    //号输入框的name属性
    public SmsAuthenticationFilter() {
        super(new AntPathRequestMatcher("/login/mobile", "POST"));
    }

    
    //attemptAuthentication方法从请求中获取到mobile参数值，并调用SmsAuthenticationToken的
    //SmsAuthenticationToken(String mobile)构造方法创建了一个SmsAuthenticationToken。
    //下一步就如流程图中所示的那样，SmsAuthenticationFilter将SmsAuthenticationToken交给AuthenticationManager处理。
    @Override
    public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response)
    		throws AuthenticationException, IOException, ServletException {
    	if (postOnly && !request.getMethod().equals("POST")) {
            throw new AuthenticationServiceException(
                    "Authentication method not supported: " + request.getMethod());
        }
        String mobile = obtainMobile(request);

        if (mobile == null) {
            mobile = "";
        }

        mobile = mobile.trim();

        SmsAuthenticationToken authRequest = new SmsAuthenticationToken(mobile);

        setDetails(request, authRequest);

        return this.getAuthenticationManager().authenticate(authRequest);
    }
    
    //获得手机号
    protected String obtainMobile(HttpServletRequest request) {
        return request.getParameter(mobileParameter);
    }

    protected void setDetails(HttpServletRequest request,
                              SmsAuthenticationToken authRequest) {
        authRequest.setDetails(authenticationDetailsSource.buildDetails(request));
    }

    public void setMobileParameter(String mobileParameter) {
        Assert.hasText(mobileParameter, "mobile parameter must not be empty or null");
        this.mobileParameter = mobileParameter;
    }

    public void setPostOnly(boolean postOnly) {
        this.postOnly = postOnly;
    }

    public final String getMobileParameter() {
        return mobileParameter;
    }

}
