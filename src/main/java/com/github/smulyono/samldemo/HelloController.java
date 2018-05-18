package com.github.smulyono.samldemo;

import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.RequestMapping;

import java.security.Principal;

@Controller
public class HelloController {
    @RequestMapping("/")
    public String index() {
        return "public";
    }

    @RequestMapping("/private")
    public String index(Model model,Principal user) {
        model.addAttribute("username",user.getName());
        return "private";
    }
}
