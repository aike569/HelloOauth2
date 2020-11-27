package cecft.com.auth.controller;

import java.nio.charset.StandardCharsets;

import javax.servlet.http.HttpServletRequest;

import org.apache.commons.lang3.StringUtils;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.RestController;

import io.jsonwebtoken.Jwts;

@RestController
public class UserController {

	@GetMapping("index")
    public Object index(@AuthenticationPrincipal Authentication authentication, HttpServletRequest request){
		String header = request.getHeader("Authorization");
        String token = StringUtils.substringAfter(header, "bearer ");

        // signkey需要和JwtAccessTokenConverter中指定的签名密钥一致
        return Jwts.parser().setSigningKey("test_key".getBytes(StandardCharsets.UTF_8)).parseClaimsJws(token).getBody();
    }
	
	// (@PreAuthorize 注解会在方法执行前进行验证，而 @PostAuthorize 注解会在方法执行后进行验证)
    @RequestMapping("/su")
    @ResponseBody
    @PreAuthorize("hasAuthority('admin')") //只有拥有"admin"权限的人才能访问： 
    public String showLogin2() {
        return "hello spring security,login success";
    }
}
