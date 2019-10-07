#!/usr/bin/env ruby

require 'json'
require 'net/http'
require 'openssl'
require 'uri'
require 'nokogiri'

module EcpDemo

  NS_ECP                  = "urn:oasis:names:tc:SAML:2.0:profiles:SSO:ecp".freeze
  NS_PAOS                 = "urn:liberty:paos:2003-08".freeze
  NS_SOAP                 = "http://schemas.xmlsoap.org/soap/envelope/".freeze
  NS_SAMLP                = "urn:oasis:names:tc:SAML:2.0:protocol".freeze
  NS_SAML                 = "urn:oasis:names:tc:SAML:2.0:assertion".freeze

  SOAP_ACTOR              = "http://schemas.xmlsoap.org/soap/actor/next".freeze
  SOAP_MUST_UNDERSTAND    = "1".freeze

  NAMESPACES              = { "ecp": NS_ECP, "paos": NS_PAOS, "soap": NS_SOAP, "samlp": NS_SAMLP, "saml": NS_SAML }.freeze

  VALID_LOG_CATEGORIES    = %w[sp-resource message-info saml-message http-request-response http-content http-lowlevel].freeze
  DEFAULT_LOG_CATEGORIES  = %w[sp-resource message-info saml-message http-request-response].freeze

  class EcpFLowError < StandardError; end

  class EcpFlow
    attr_reader :uri, :sp_resource, :idp_endpoint, :user, :password, :idp_auth_method, :log_categories

    attr_accessor :http, :paos_request_text, :paos_request_dom, :provider_name,
      :sp_response_consumer_url, :sp_message_id, :sp_is_passive, :sp_issuer, :sp_relay_state, :sp_authn_request_xml,
      :idp_response_text, :idp_response_xml, :idp_assertion_consumer_url, :idp_request_authenticated,
      :idp_saml_response_xml, :idp_saml_response_status_xml, :idp_saml_response_status_code,
      :idp_saml_response_status_code2, :idp_saml_response_status_msg, :idp_saml_response_status_detail,
      :sp_response_xml

    def initialize(sp_resource, idp_endpoint, user, password, idp_auth_method, log_categories)
      puts "JJV 0.0 #{File.basename(__FILE__)} / #{__method__}"

      # HTTP session used to perform HTTP request/response
      @uri = URI.parse(sp_resource)
      puts "JJV 0.0 #{File.basename(__FILE__)} / #{__method__} uri.host        ->#{uri.host}<-"
      puts "JJV 0.0 #{File.basename(__FILE__)} / #{__method__} uri.port        ->#{uri.port}<-"
      puts "JJV 0.0 #{File.basename(__FILE__)} / #{__method__} uri.request_uri ->#{uri.request_uri}<-"
 
      @http = Net::HTTP.new(uri.host, uri.port)
      http.use_ssl = true
      http.verify_mode = OpenSSL::SSL::VERIFY_NONE
  
      @sp_resource = sp_resource
      @idp_endpoint = idp_endpoint
      @user = user
      @password = password
      @idp_auth_method = idp_auth_method
      @log_categories = log_categories
  
      #### Collected Data ####
  
      # SP Request
      @paos_request_text = nil
      @paos_request_dom = nil
      @sp_response_consumer_url = nil
      @sp_message_id = nil
      @sp_is_passive = nil
      @sp_issuer = nil
      @sp_relay_state = nil
      @sp_authn_request_xml = nil
  
      # IdP Response
      @idp_response_text = nil
      @idp_response_xml = nil
      @idp_assertion_consumer_url = nil
      @idp_request_authenticated = nil
      @idp_saml_response_xml = nil
      @idp_saml_response_status_xml = nil
      @idp_saml_response_status_code = nil
      @idp_saml_response_status_code2 = nil
      @idp_saml_response_status_msg = nil
      @idp_saml_response_status_detail = nil
  
      # SP Response
      @sp_response_xml = nil
    end

    def run
        puts "JJV 0.0 #{File.basename(__FILE__)} / #{__method__}"

        ecp_issues_request_to_sp
        process_paos_request
        determine_idp_endpoint

        return 1 # JJV

        build_authn_request_for_idp
        send_authn_request_to_idp
        process_idp_response
        validate_idp_response
        build_sp_response
        send_sp_response
    end

    def ecp_issues_request_to_sp
      puts "JJV 0.0 #{File.basename(__FILE__)} / #{__method__}"

      puts "*** ECP Issues HTTP Request to Service Provider ***"

      http = Net::HTTP.new(uri.host, uri.port)
      http.use_ssl = true
      http.verify_mode = OpenSSL::SSL::VERIFY_NONE
  
      request = Net::HTTP::Get.new(uri.request_uri)
      request["Accept"] = "text/html, application/vnd.paos+xml"
      request["PAOS"]   = 'ver="urn:liberty:paos:2003-08";"urn:oasis:names:tc:SAML:2.0:profiles:SSO:ecp"'

      response = http.request(request)

      # puts "Reply:\n " + JSON.pretty_generate(JSON.parse(response.body.strip))
      puts "Response.body \n " + response.body

      @paos_request_text = response.body
    end

    def process_paos_request
      puts "JJV 0.0 #{File.basename(__FILE__)} / #{__method__}"
      puts "*** Process PAOS request from SP ***"

      @paos_request_dom = Nokogiri.XML(paos_request_text)

      @sp_response_consumer_url = get_xml_element_text(paos_request_dom, true,  '/soap:Envelope/soap:Header/paos:Request/@responseConsumerURL')
      @sp_message_id            = get_xml_element_text(paos_request_dom, false, '/soap:Envelope/soap:Header/paos:Request/@messageID')
      @provider_name            = get_xml_element_text(paos_request_dom, false, '/soap:Envelope/soap:Header/ecp:Request/@ProviderName')
      @sp_is_passive            = get_xml_element_text(paos_request_dom, false, '/soap:Envelope/soap:Header/ecp:Request/@IsPassive')
      @sp_issuer                = get_xml_element_text(paos_request_dom, true,  '/soap:Envelope/soap:Header/ecp:Request/saml:Issuer')
      @sp_relay_state           = get_xml_element_text(paos_request_dom, false, '/soap:Envelope/soap:Header/ecp:RelayState')
      @sp_authn_request_xml     = get_xml_element(paos_request_dom,      true,  '/soap:Envelope/soap:Body/samlp:AuthnRequest')
    end

    def determine_idp_endpoint
        puts "JJV 0.0 #{File.basename(__FILE__)} / #{__method__}"
    end

    def build_authn_request_for_idp
        puts "JJV 0.0 #{File.basename(__FILE__)} / #{__method__}"
    end

    def send_authn_request_to_idp
        puts "JJV 0.0 #{File.basename(__FILE__)} / #{__method__}"
    end

    def process_idp_response
        puts "JJV 0.0 #{File.basename(__FILE__)} / #{__method__}"
    end

    def validate_idp_response
        puts "JJV 0.0 #{File.basename(__FILE__)} / #{__method__}"
    end

    def build_sp_response
        puts "JJV 0.0 #{File.basename(__FILE__)} / #{__method__}"
    end

    def send_sp_response
        puts "JJV 0.0 #{File.basename(__FILE__)} / #{__method__}"
    end

    private

    def get_xml_element(context_node, required, xpath_expr)
      matches = context_node.xpath(xpath_expr, NAMESPACES)

      if matches.count == 0
        raise EcpFlowError, "#{xpath_expr} not found " if required
        return nil
      end

      raise EcpFlowError, "found #{matches.count} multiple matches for #{xpath_expr}" if matches.count > 1

      return matches.first
    end

    def get_xml_element_text(context_node, required, xpath_expr)
      data = get_xml_element(context_node, required, xpath_expr)

      return data.children.first.text if data.respond_to?("children")

      return data.nil? ? nil : data.value
    end
  end
end

if $PROGRAM_NAME == __FILE__

   # require 'pry'; binding.pry # JJV

  sp_resource     = 'https://joev-saml/saml_login'
  idp_endpoint    = 'http://joev-keycloak:8080/auth/realms/miq/protocol/saml'
  user            = 'jvlcek'
  password        = 'smartvm'
  idp_auth_method = 'basic'
  log_categories  = %w[http-lowlevel http-content sp-resource http-request-response message-info saml-message]

  EcpDemo::EcpFlow.new(sp_resource, idp_endpoint, user, password, idp_auth_method, log_categories).run
end

