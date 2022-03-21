package com.learningstuff.springmultiplesecurity.configs;

import com.learningstuff.springmultiplesecurity.securities.APIKeyFilterRequest;
import com.learningstuff.springmultiplesecurity.securities.JwtFilterRequest;
import com.learningstuff.springmultiplesecurity.securities.MyAuthenticationEntryPoint;
import lombok.AllArgsConstructor;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
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
public class WebSecurityConfig {

    @Order(1)
    @Configuration
    @AllArgsConstructor
    public static class BearerTokenConfiguration extends WebSecurityConfigurerAdapter {

        private final MyAuthenticationEntryPoint myAuthenticationEntryPoint;

        @Override
        protected void configure(HttpSecurity http) throws Exception {

            http.cors().disable().csrf().disable();

            http.formLogin().disable().httpBasic().disable();

            http.antMatcher("/api/v1/**").exceptionHandling()
                    .authenticationEntryPoint(myAuthenticationEntryPoint)
                    .and()
                    .sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS)
                    .and()
                    .authorizeRequests()
                    .antMatchers("/login").permitAll()
                    .anyRequest()
                    .authenticated();

            http.addFilterBefore(new JwtFilterRequest(), UsernamePasswordAuthenticationFilter.class);

        }

    }

    @Order(2)
    @Configuration
    @AllArgsConstructor
    public static class APIKeyConfiguration extends WebSecurityConfigurerAdapter {

        private final MyAuthenticationEntryPoint myAuthenticationEntryPoint;

        @Override
        protected void configure(HttpSecurity http) throws Exception {

            http.cors().disable().csrf().disable();

            http.formLogin().disable().httpBasic().disable();

            http.antMatcher("/api/v2/**").exceptionHandling()
                    .authenticationEntryPoint(myAuthenticationEntryPoint)
                    .and()
                    .sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS)
                    .and()
                    .authorizeRequests()
                    .antMatchers("/login").permitAll()
                    .anyRequest()
                    .authenticated();

            http.addFilterBefore(new APIKeyFilterRequest(), UsernamePasswordAuthenticationFilter.class);

        }
    }

    @Order(3)
    @Configuration
    public static class WebConfiguration extends WebSecurityConfigurerAdapter {

        @Override
        protected void configure(HttpSecurity http) throws Exception {

            http
                    .antMatcher("/**")
                    .csrf()
                    .and()
                    .authorizeRequests()
                    .anyRequest().authenticated()
                    .and()
                    .formLogin().permitAll();
        }

    }

}

