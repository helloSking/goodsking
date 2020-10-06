package top.hiai.config;


import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;

/**
 * @Author hkq
 * @Email goodsking@163.com
 * Security配置类
 */

//AOP横切 ：拦截器
@EnableWebSecurity
public class SecurityConfig extends WebSecurityConfigurerAdapter {

    //链式编程   授权
    @Override
    protected void configure(HttpSecurity http) throws Exception {

        //首页所以人可以访问
        //里面的功能页面只有对应的有权限的人可以访问

        //请求授权的规则
        http.authorizeRequests()
                .antMatchers("/").permitAll()           //首页所有人可以访问
                .antMatchers("/level1/**").hasAnyRole("vip1")   //只有VIP1用户可以访问
                .antMatchers("/level2/**").hasAnyRole("vip2")   //只有VIP2用户可以访问
                .antMatchers("/level3/**").hasAnyRole("vip3");  //只有VIP3用户可以访问

        //没有权限会跳转到登陆页面

        //开启登录页面
//        http.formLogin();//默认的登录界面
        http.formLogin().loginPage("/my_login").usernameParameter("username").passwordParameter("password").loginProcessingUrl("/login");//自己的登录界面

        //防止网站攻击
        http.csrf().disable();//关闭

        //开启注销功能
//        http.logout().logoutUrl("/");

        //开启记住我功能
        http.rememberMe().rememberMeParameter("remember");

    }

    //认证
    //密码加密
    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {

        //从数据库中读取
        auth.inMemoryAuthentication()
                .passwordEncoder(new BCryptPasswordEncoder())
                .withUser("vip1").password(new BCryptPasswordEncoder().encode("123456")).roles("vip1")
                .and()
                .withUser("vip2").password(new BCryptPasswordEncoder().encode("123456")).roles("vip2")
                .and()
                .withUser("vip3").password(new BCryptPasswordEncoder().encode("123456")).roles("vip3")
                .and()
                .withUser("admin").password(new BCryptPasswordEncoder().encode("123456")).roles("vip1", "vip2", "vip3");

    }
}
