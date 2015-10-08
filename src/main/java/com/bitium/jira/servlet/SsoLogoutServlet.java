package com.bitium.jira.servlet;
import java.io.IOException;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.security.saml.SAMLCredential;
import org.springframework.security.saml.context.SAMLMessageContext;
import org.springframework.security.saml.websso.SingleLogoutProfileImpl;

import com.bitium.jira.config.SAMLJiraConfig;
import com.bitium.saml.SAMLContext;


public class SsoLogoutServlet extends HttpServlet {
	private static final long serialVersionUID = 1L;

	private Log log = LogFactory.getLog(SsoLogoutServlet.class);

	private SAMLJiraConfig saml2Config;

	@Override
	public void init() throws ServletException {
		super.init();
	}

	@Override
	protected void doGet(HttpServletRequest request, HttpServletResponse response)
			throws ServletException, IOException {

		try {
			SAMLContext context = new SAMLContext(request, saml2Config);
			SAMLMessageContext messageContext = context.createSamlMessageContext(request, response);

			SAMLCredential credential = (SAMLCredential)request.getSession().getAttribute("SAMLCredential");

			// Send request
	        SingleLogoutProfileImpl profile = new SingleLogoutProfileImpl();
	        profile.setMetadata(context.getMetadataManager());
	        profile.setProcessor(context.getSamlProcessor());
	        profile.sendLogoutRequest(messageContext, credential);
		} catch (Exception e) {
		    log.error("saml plugin error + " + e.getMessage());
		    response.sendRedirect(saml2Config.getBaseUrl() + "/login.action?samlerror=general");
		}
	}

	@Override
	protected void doPost(HttpServletRequest request, HttpServletResponse response) throws ServletException {

	}

	public void setSaml2Config(SAMLJiraConfig saml2Config) {
		this.saml2Config = saml2Config;
	}
}
