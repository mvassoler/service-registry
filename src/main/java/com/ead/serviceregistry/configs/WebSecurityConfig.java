package com.ead.serviceregistry.configs;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

@Configuration
public class WebSecurityConfig extends WebSecurityConfigurerAdapter{

    @Value("${ead.client.registerWithEureka.username}")
    private String username;

    @Value("${ead.client.registerWithEureka.password}")
    private String password;

    @Override
    public void configure(HttpSecurity http) throws Exception {
        http.httpBasic()
                .and()
                .authorizeRequests()
                .anyRequest().authenticated() //listar os endpoints com autorizações especificas ou endpoints que podem ser acessados sem autenticação
                .and()
                .csrf().disable() //csrf: falsiciação de solicitação entre site é habilitado por default, mas clientes eureka não possuem token válidos
                .formLogin(); //obriga a exibição do formulário de autenticação no dashboard
    }

    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        auth.inMemoryAuthentication()  //do tipo em memória
                .withUser(username)  //usuario
                .password(passwordEncoder().encode(password))  //senha
                .roles("ADMIN"); //regra
    }

    //Procede o encode da senha
    @Bean
    public PasswordEncoder passwordEncoder(){
        return new BCryptPasswordEncoder();
    }
}
