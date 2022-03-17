package com.learningstuff.springmultiplesecurity.payloads;

import lombok.*;

/**
 * Created by IntelliJ IDEA.
 * User: Md. Shamim
 * Email: mdshamim723@gmail.com
 * Date: ১৭/৩/২২
 * Time: ৬:১৪ PM
 * To change this template use File | Settings | File and Code Templates.
 */

@AllArgsConstructor
@NoArgsConstructor
@Getter
@Setter
@ToString
public class LoginRequest {

    public String username;
    public String password;

}
