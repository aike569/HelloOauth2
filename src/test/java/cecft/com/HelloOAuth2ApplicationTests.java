package cecft.com;

import org.junit.jupiter.api.Test;
import org.springframework.boot.test.context.SpringBootTest;

@SpringBootTest
class HelloOAuth2ApplicationTests {

	@Test
	void contextLoads() {
	}
	
	@Test
	public void test1() {
		String key = "role2ADMIN";
		String type = key.split("2")[0];
		String str = key.split("2")[1];
		System.out.println("type: "+type);
		System.out.println("str: "+str);
	}
	
	
	@Test
	public void test2() {
		String Str = new String("hello sunny，I am from itmind。");
        System.out.print("返回值 :" );
        System.out.println(Str.replaceFirst("sunny", "google" ));
        System.out.print("返回值 :" );
        System.out.println(Str.replaceFirst("(.*)sunny(.*)", "google" ));
	}

}
