package com.springbootauth;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.http.HttpStatus;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.security.web.authentication.HttpStatusEntryPoint;
import org.springframework.security.web.csrf.CookieCsrfTokenRepository;
import org.springframework.web.bind.annotation.*;

import java.util.Collection;
import java.util.Collections;
import java.util.Map;

@SpringBootApplication
@RestController
public class OauthRunner extends WebSecurityConfigurerAdapter {
    public static void main(String[] args) {
        SpringApplication.run(OauthRunner.class, args);
    }

    @GetMapping("/user")
    public Map<String, Object> users(@AuthenticationPrincipal OAuth2User principal) {
        Authentication authentication =
                SecurityContextHolder
                        .getContext()
                        .getAuthentication();

        OAuth2AuthenticationToken oauthToken =
                (OAuth2AuthenticationToken) authentication;

        System.out.println(oauthToken);


        Map<String, Object> list = principal.getAttributes();
        Collection<? extends GrantedAuthority> authorities = principal.getAuthorities();
        for (GrantedAuthority authority : authorities) {
            System.out.println(authorities);
        }
        for (Map.Entry<String, Object> entry : list.entrySet()) {
            System.out.print(entry.getKey()+"   ==   ");
            System.out.println(entry.getValue());
        }
        return list;
    }

    @RequestMapping("/done")
    public void getdone(){
        System.out.println("get called");
    }


    @GetMapping("/login/oauth2/code/github")
    public void codevalue(@PathVariable String code, @PathVariable String state){
        System.out.println("Code : "+code);
        System.out.println("State : "+state);
    }

    @PostMapping("/login/oauth2/code/github")
    public void codeVal(@PathVariable String code, @PathVariable String state){
        System.out.println("Code : "+code);
        System.out.println("State : "+state);
    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http.authorizeRequests(a -> a.antMatchers("/", "/error", "/webjars/**").permitAll().anyRequest().authenticated()
                ).exceptionHandling(e -> e.authenticationEntryPoint(new HttpStatusEntryPoint(HttpStatus.UNAUTHORIZED))
                ).csrf(c -> c.csrfTokenRepository(CookieCsrfTokenRepository.withHttpOnlyFalse()))
                .logout(l -> l.logoutSuccessUrl("/").permitAll())
                .oauth2Login();
    }
}
