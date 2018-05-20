package com.github.smulyono.samldemo;

import com.github.smulyono.samldemo.metadata.MetadataManagerProxy;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Lazy;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.ResponseBody;

import java.security.Principal;

@Controller
@Slf4j
@Lazy
public class HelloController {
    @Autowired
    MetadataManagerProxy metadataManagerProxy;

    @RequestMapping("/")
    public String index() {
        return "public";
    }

    @RequestMapping("/private")
    public String index(Model model,Principal user) {
        model.addAttribute("username",user.getName());
        return "private";
    }


    @RequestMapping("/reload")
    @ResponseBody
    public String reload(Principal user) {
        log.info("{} asking for metadata reload", user.getName());
        metadataManagerProxy.reload();
        return "OK";
    }
}
