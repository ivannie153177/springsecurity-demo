package com.springsecurity.demo.security.handler;

import com.google.gson.Gson;
import jakarta.servlet.ServletOutputStream;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.web.access.AccessDeniedHandler;
import org.springframework.stereotype.Component;

import java.io.IOException;
import java.util.HashMap;
import java.util.Map;
import java.util.Objects;

@Component
@Slf4j
public class CustomAccessDeniedHandler implements AccessDeniedHandler {
    @Override
    public void handle(HttpServletRequest request, HttpServletResponse response, AccessDeniedException accessDeniedException) {
        output(response, resultMap(false, 401, "can not access resources", null));
    }

    private void output(HttpServletResponse response, Map<String, Object> resultMap) {
        ServletOutputStream servletOutputStream = null;
        response.setCharacterEncoding("UTF-8");
        response.setContentType("application/json;charset=UTF-8");
        try {
            servletOutputStream = response.getOutputStream();
            servletOutputStream.write(new Gson().toJson(resultMap).getBytes());
        } catch (IOException e) {
            log.error("output try response output IO exception:", e);
        } finally {
            if (Objects.nonNull(servletOutputStream)) {
                try {
                    servletOutputStream.flush();
                    servletOutputStream.close();
                } catch (IOException e) {
                    log.error("output finally response output IO exception:", e);
                }
            }
        }
    }

    private Map<String, Object> resultMap(boolean flag, Integer code, String msg, Object data) {
        Map<String, Object> resultMap = new HashMap<>(16);
        resultMap.put("success", flag);
        resultMap.put("message", msg);
        resultMap.put("code", code);
        resultMap.put("timestamp", System.currentTimeMillis());
        if (Objects.nonNull(data)) {
            resultMap.put("result", data);
        }
        return resultMap;
    }

}
