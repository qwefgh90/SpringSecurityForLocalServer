package hello;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.core.annotation.Order;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.WebAuthenticationDetails;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.GenericFilterBean;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import java.io.IOException;

@Component
public class CustomFilter extends GenericFilterBean {
    Logger logger = LoggerFactory.getLogger(CustomFilter.class);

    @Autowired
    AuthenticationManager authenticationManager;

    @Override
    public void doFilter(ServletRequest servletRequest, ServletResponse servletResponse, FilterChain filterChain) throws IOException, ServletException {
//        logger.info("doFilter()");
//        var preAuth = SecurityContextHolder.getContext().getAuthentication();
//        logger.info("auth11: " + preAuth.getPrincipal().toString());
//        logger.info("auth11: " + preAuth.isAuthenticated());
//
//        UsernamePasswordAuthenticationToken authToken = new UsernamePasswordAuthenticationToken("notimportant", "");
//        authToken.setDetails(new WebAuthenticationDetails((HttpServletRequest)servletRequest));
//
//        Authentication authentication = authenticationManager.authenticate(authToken);
//        logger.info("auth: " + authentication.isAuthenticated());
//        SecurityContextHolder.getContext().setAuthentication(authentication);
        filterChain.doFilter(servletRequest, servletResponse);
    }
}
