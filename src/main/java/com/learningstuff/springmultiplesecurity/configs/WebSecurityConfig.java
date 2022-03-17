package com.learningstuff.springmultiplesecurity.configs;

import com.learningstuff.springmultiplesecurity.securities.APIKeyFilterRequest;
import com.learningstuff.springmultiplesecurity.securities.JwtFilterRequest;
import com.learningstuff.springmultiplesecurity.securities.MyAuthenticationEntryPoint;
import lombok.AllArgsConstructor;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

/**
 * Created by IntelliJ IDEA.
 * User: Md. Shamim
 * Email: mdshamim723@gmail.com
 * Date: ১৭/৩/২২
 * Time: ৩:৪৮ PM
 * To change this template use File | Settings | File and Code Templates.
 */

@Configuration
@EnableWebSecurity
@EnableGlobalMethodSecurity(prePostEnabled = true)
@AllArgsConstructor
public class WebSecurityConfig extends WebSecurityConfigurerAdapter {

    private final MyAuthenticationEntryPoint myAuthenticationEntryPoint;

    @Override
    protected void configure(HttpSecurity http) throws Exception {

        http.cors().and().csrf().disable();
        http.formLogin().and().httpBasic().disable();

        http.exceptionHandling()
                .authenticationEntryPoint(myAuthenticationEntryPoint)
                .and()
                .sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS)
                .and()
                .authorizeRequests()
                .anyRequest()
                .authenticated();

        http
                .addFilterBefore(new JwtFilterRequest(), UsernamePasswordAuthenticationFilter.class)
                .addFilterBefore(new APIKeyFilterRequest(), UsernamePasswordAuthenticationFilter.class);

    }

    @Override
    public void configure(WebSecurity web) throws Exception {

        web.ignoring()
                .antMatchers( "/login");

    }


}

