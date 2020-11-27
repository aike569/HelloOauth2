package cecft.com.auth.smscode.entity;

import lombok.Data;

@Data
public class SmsCode {

	private String code;

    public SmsCode(String code) {
        this.code = code;
    }

}
